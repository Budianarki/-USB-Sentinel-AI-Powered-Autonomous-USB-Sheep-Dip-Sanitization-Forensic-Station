"""Scanning engine coordinator for Layer 2 Deterministic Inspection.

Coordinates:
- Anti-TOCTOU streaming & single-pass reading with hash integrity verification
- ClamAV INSTREAM and YARA signature scanning
- Filename sanitization and Unicode RTL / path traversal defense
- Archive metadata inspection and Zip Bomb / Quota protection
- Subprocess-isolated static tools with execution timeout and resource limits
- Filesystem whitelist validation
"""

import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.agents.schemas import FileFeatures
from sentinel.guard.filesystem import is_filesystem_supported, validate_path_safety
from sentinel.scan.archive import inspect_archive
from sentinel.scan.clamav import (
    ClamAvScanner,
    MockClamAvScanner,
    create_clamav_scanner,
)
from sentinel.scan.sanitize import sanitize_filename
from sentinel.scan.static_runner import IsolatedStaticRunner
from sentinel.scan.stream_reader import process_untrusted_file_stream
from sentinel.scan.yara_scanner import (
    MockYaraScanner,
    YaraScanner,
    create_yara_scanner,
)
from sentinel.util.config import PolicyConfig, SentinelConfig

logger = logging.getLogger(__name__)


@dataclass
class ScanSessionResult:
    """Summary of deterministic scanning for a full USB session."""

    file_features: list[FileFeatures] = field(default_factory=list)
    scan_complete: bool = True
    scanners_ok: bool = True
    filesystem_supported: bool = True
    av_or_yara_hit: bool = False
    has_risky_type: bool = False
    deterministic_risk: float = 0.0
    deterministic_reasons: list[str] = field(default_factory=list)
    is_mock: bool = False
    total_files_scanned: int = 0


class ScanEngine:
    """Layer 2 scanning engine orchestrating all deterministic checks."""

    def __init__(
        self,
        config: SentinelConfig,
        policy_config: PolicyConfig,
        clamav_scanner: ClamAvScanner | MockClamAvScanner | None = None,
        yara_scanner: YaraScanner | MockYaraScanner | None = None,
        static_runner: IsolatedStaticRunner | None = None,
    ) -> None:
        self.config = config
        self.policy_config = policy_config
        self.is_mock = config.mode == "laptop_mock"

        # Initialize scanners according to mode
        self.clamav = clamav_scanner or create_clamav_scanner(mode=config.mode)
        self.yara = yara_scanner or create_yara_scanner(mode=config.mode)
        self.static_runner = static_runner or IsolatedStaticRunner(timeout_s=5.0)

    def scan_mount(
        self,
        mount_point: Path,
        filesystem_type: str = "vfat",
        _simulate_stream_tamper: bool = False,
    ) -> ScanSessionResult:
        """Execute complete Layer 2 scan on a mounted partition."""
        reasons: list[str] = []
        file_features_list: list[FileFeatures] = []
        max_file_risk = 0.0
        av_or_yara_hit = False
        has_risky_type = False
        scan_complete = True
        scanners_ok = True

        if self.is_mock:
            logger.info("[MOCK] Starting deterministic scan session in laptop_mock mode.")

        # 1. Check scanner health
        if self.config.mode == "iot":
            if not self.clamav.is_available():
                logger.error("ClamAV daemon offline in IoT mode")
                scanners_ok = False
                reasons.append("ClamAV scanner offline or unreachable in IoT mode")

            if isinstance(self.yara, YaraScanner) and self.yara.init_error:
                logger.error("YARA engine error in IoT mode: %s", self.yara.init_error)
                scanners_ok = False
                reasons.append(f"YARA scanner offline or error: {self.yara.init_error}")

        # 2. Filesystem whitelist check
        allowed_fs = getattr(self.config.scan, "allowed_filesystems", None)
        fs_ok = is_filesystem_supported(filesystem_type, allowed_filesystems=allowed_fs)
        if not fs_ok:
            reasons.append(
                f"Filesystem type '{filesystem_type}' not supported on security whitelist"
            )

        # 3. Enumerate files with quota limit
        if not mount_point.exists():
            return ScanSessionResult(
                file_features=[],
                scan_complete=True,
                scanners_ok=scanners_ok,
                filesystem_supported=fs_ok,
                deterministic_risk=0.0,
                deterministic_reasons=["Empty mount directory"],
                is_mock=self.is_mock,
            )

        entries = list(mount_point.rglob("*"))
        regular_files = [
            f
            for f in entries
            if (f.is_file() or f.is_symlink())
            and not any(part.startswith((".sentinel_quarantine", ".Trash")) for part in f.parts)
        ]

        if len(regular_files) > self.config.scan.max_files:
            scan_complete = False
            reasons.append(
                f"File count ({len(regular_files)}) exceeded quota limit ({self.config.scan.max_files}); scan aborted"
            )
            # Truncate scan to quota limit
            regular_files = regular_files[: self.config.scan.max_files]

        for file_path in regular_files:
            file_id = f"f_{uuid.uuid4().hex[:12]}"
            file_flags: list[str] = []
            file_av_hits: list[str] = []
            file_yara_hits: list[str] = []
            file_risk = 0.0

            # 3a. Path safety & Symlink validation
            is_safe_path, path_flags = validate_path_safety(file_path, mount_point)
            file_flags.extend(path_flags)
            if not is_safe_path:
                scan_complete = False
                reasons.append(f"Dangerous path or symlink traversal detected: {file_path.name}")
                file_risk = max(file_risk, 0.90)
                # Skip reading dangerous escaping file
                features = FileFeatures(
                    file_id=file_id,
                    sha256="0" * 64,
                    size=0,
                    detected_type="symlink_escape",
                    ext_mismatch=True,
                    entropy=0.0,
                    flags=file_flags,
                    av_hits=[],
                    yara_hits=[],
                    static_summary={"error": "symlink_escapes_mount"},
                    sanitized_name=file_path.name,
                )
                file_features_list.append(features)
                continue

            # 3b. Filename sanitization (including Unicode RTL check)
            name_res = sanitize_filename(file_path.name)
            file_flags.extend(name_res.flags)
            if name_res.bidi_detected:
                reasons.append(
                    f"Unicode BiDi override extension spoofing detected in '{name_res.sanitized_name}'"
                )
                file_risk = max(file_risk, 0.85)

            # 3c. Archive metadata & Zip bomb protection (before extraction)
            archive_res = inspect_archive(
                file_path,
                max_decompress_ratio=self.config.scan.max_decompress_ratio,
                max_uncompressed_mb=self.config.scan.max_file_mb,
                max_files_in_archive=self.config.scan.max_files,
                max_depth=self.config.scan.max_archive_depth,
            )
            if archive_res.is_archive:
                file_flags.extend(archive_res.flags)
                if archive_res.is_bomb or archive_res.quota_exceeded:
                    scan_complete = False
                    file_risk = max(file_risk, 0.90)
                    reasons.append(
                        f"Zip bomb or archive quota exceeded in '{name_res.sanitized_name}' "
                        f"(ratio: {archive_res.decompress_ratio:.1f}x); scan aborted"
                    )

            # 3d. Anti-TOCTOU streaming & single-pass read with hash verification
            try:
                with process_untrusted_file_stream(
                    file_path,
                    clamav_scanner=self.clamav,
                    max_file_mb=self.config.scan.max_file_mb,
                    _simulate_tamper_on_temp=_simulate_stream_tamper,
                ) as stream_res:
                    file_flags.extend(stream_res.flags)

                    if stream_res.quota_exceeded:
                        scan_complete = False
                        reasons.append(f"File size quota exceeded for '{name_res.sanitized_name}'")
                        file_risk = max(file_risk, 0.70)

                    # Integrity verification: TOCTOU check
                    if not stream_res.integrity_verified:
                        # Critical hardware tampering indicator!
                        scan_complete = False
                        file_risk = 1.0
                        reasons.append(
                            f"TOCTOU Integrity Violation: File '{name_res.sanitized_name}' returned different bytes "
                            f"between stream and buffer!"
                        )

                    # AV results from INSTREAM
                    if not stream_res.av_result.clean and stream_res.av_result.virus_name:
                        file_av_hits.append(stream_res.av_result.virus_name)
                        av_or_yara_hit = True
                        file_risk = 1.0
                        reasons.append(f"Antivirus hit: {stream_res.av_result.virus_name}")

                    if not stream_res.av_result.scanners_ok:
                        scanners_ok = False
                        if stream_res.av_result.error_message:
                            reasons.append(stream_res.av_result.error_message)

                    # Static tools via isolated subprocess
                    static_summary: dict[str, Any] = {}
                    detected_type = "unknown"
                    ext_mismatch = False
                    entropy = 0.0

                    max_static_mb = getattr(self.config.scan, "max_static_analysis_mb", 50)
                    max_static_bytes = max_static_mb * 1024 * 1024

                    if stream_res.size > max_static_bytes:
                        file_flags.append("static_analysis_size_exceeded")
                        scan_complete = False
                        file_risk = max(file_risk, 0.75)
                        reasons.append(
                            f"File '{name_res.sanitized_name}' ({stream_res.size / (1024*1024):.1f}MB) "
                            f"exceeds maximum static analysis limit ({max_static_mb}MB); "
                            "static analysis skipped (fail-closed to quarantine)"
                        )
                    elif stream_res.temp_path and stream_res.temp_path.exists():
                        # Read sample for YARA scan
                        sample_data = stream_res.temp_path.read_bytes()
                        yara_res = self.yara.scan_data(sample_data)
                        if yara_res.hits:
                            file_yara_hits.extend(yara_res.hits)
                            av_or_yara_hit = True
                            file_risk = 1.0
                            reasons.append(f"YARA signature match: {', '.join(yara_res.hits)}")
                        if not yara_res.scanners_ok:
                            scanners_ok = False
                            if yara_res.error_message:
                                reasons.append(yara_res.error_message)

                        # Isolated static parsing in subprocess
                        sub_res = self.static_runner.run_analysis(
                            file_path=stream_res.temp_path,
                            original_filename=name_res.sanitized_name,
                            tool="all",
                        )
                        detected_type = sub_res.detected_type
                        ext_mismatch = sub_res.ext_mismatch
                        entropy = sub_res.entropy
                        file_flags.extend(sub_res.flags)
                        static_summary = sub_res.static_summary

                        if sub_res.status != "success":
                            reasons.append(
                                f"Static analysis {sub_res.status}: {sub_res.error_message}"
                            )
                            file_risk = max(file_risk, 0.75)

                    # Risky type & whitelist evaluation
                    allowed_types = self.config.scan.allowed_types
                    if detected_type not in allowed_types and detected_type not in (
                        "unknown",
                        "txt",
                    ):
                        has_risky_type = True
                        file_flags.append("untrusted_type")
                        file_risk = max(
                            file_risk,
                            self.policy_config.deterministic_risks.get("untrusted_type", 0.50),
                        )

                    if ext_mismatch:
                        file_risk = max(
                            file_risk,
                            self.policy_config.deterministic_risks.get("type_mismatch", 0.85),
                        )
                        reasons.append(
                            f"Extension mismatch in '{name_res.sanitized_name}' (detected: {detected_type})"
                        )

                    if "office_macro_autoexec" in file_flags:
                        file_risk = max(
                            file_risk,
                            self.policy_config.deterministic_risks.get(
                                "office_macro_autoexec", 0.90
                            ),
                        )
                        reasons.append(
                            f"Auto-executing macro detected in '{name_res.sanitized_name}'"
                        )

                    if "pe_packed" in file_flags:
                        file_risk = max(
                            file_risk, self.policy_config.deterministic_risks.get("pe_packed", 0.70)
                        )

                    if "archive_encrypted" in file_flags:
                        file_risk = max(
                            file_risk,
                            self.policy_config.deterministic_risks.get("archive_encrypted", 0.60),
                        )

                    if "autorun_autoexec_trigger" in file_flags or "autorun_inf_present" in file_flags:
                        file_risk = max(file_risk, 0.95)
                        reasons.append(f"AutoRun infection script detected in '{name_res.sanitized_name}'")

                    if "double_extension_deception" in file_flags:
                        file_risk = max(file_risk, 0.90)
                        reasons.append(f"Deceptive double-extension detected in '{name_res.sanitized_name}'")

                    if any(f.startswith("lnk_invokes_") for f in file_flags):
                        file_risk = max(file_risk, 0.95)
                        reasons.append(f"Malicious shortcut payload execution detected in '{name_res.sanitized_name}'")

                    if "ransomware_note_detected" in file_flags:
                        file_risk = max(file_risk, 0.95)
                        reasons.append(f"Ransomware extortion note detected in '{name_res.sanitized_name}'")

                    if (
                        "wscript_shell_invocation" in file_flags
                        or "remote_downloader" in file_flags
                        or "amsi_bypass" in file_flags
                        or "powershell_encoded" in file_flags
                    ):
                        file_risk = max(file_risk, 0.90)
                        reasons.append(f"Malicious script payload execution detected in '{name_res.sanitized_name}'")

                    features = FileFeatures(
                        file_id=file_id,
                        sha256=stream_res.sha256,
                        size=stream_res.size,
                        detected_type=detected_type,
                        ext_mismatch=ext_mismatch,
                        entropy=entropy,
                        flags=list(dict.fromkeys(file_flags)),
                        av_hits=file_av_hits,
                        yara_hits=file_yara_hits,
                        static_summary=static_summary,
                        sanitized_name=name_res.sanitized_name,
                    )
                    file_features_list.append(features)
                    max_file_risk = max(max_file_risk, file_risk)

            except Exception as exc:  # noqa: BLE001
                scan_complete = False
                logger.error("Error reading file %s: %s", file_path, exc)
                reasons.append(f"Error scanning file '{name_res.sanitized_name}': {exc}")
                max_file_risk = max(max_file_risk, 0.90)
                file_features_list.append(
                    FileFeatures(
                        file_id=file_id,
                        sha256="0" * 64,
                        size=0,
                        detected_type="unreadable",
                        ext_mismatch=False,
                        entropy=0.0,
                        flags=["unreadable_file_error"],
                        av_hits=[],
                        yara_hits=[],
                        static_summary={"error": str(exc)},
                        sanitized_name=name_res.sanitized_name,
                    )
                )

        # De-duplicate reasons
        dedup_reasons = list(dict.fromkeys(reasons))

        return ScanSessionResult(
            file_features=file_features_list,
            scan_complete=scan_complete,
            scanners_ok=scanners_ok,
            filesystem_supported=fs_ok,
            av_or_yara_hit=av_or_yara_hit,
            has_risky_type=has_risky_type,
            deterministic_risk=max_file_risk,
            deterministic_reasons=dedup_reasons,
            is_mock=self.is_mock,
            total_files_scanned=len(file_features_list),
        )
