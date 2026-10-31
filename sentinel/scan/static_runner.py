"""Subprocess supervisor for isolated static file parsing (Layer 2).

Enforces:
- Strict per-file execution timeout (default 5.0 seconds)
- Process memory and CPU limits via setrlimit on Linux (RLIMIT_AS, RLIMIT_CPU)
- Graceful crash and timeout handling without destabilizing the Sentinel daemon
"""

import json
import logging
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _linux_limits() -> None:
    """Apply resource constraints on Linux to prevent DoS via decompression bombs or regex hangs."""
    try:
        import resource  # type: ignore[import-not-found]

        # RLIMIT_CPU: limit CPU time to 5 seconds
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))  # type: ignore[attr-defined]
        # RLIMIT_AS: limit address space to 512 MB
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001
        logger.debug("Failed setting resource limits: %s", exc)


@dataclass
class IsolatedStaticResult:
    status: str  # "success", "timeout", "error"
    detected_type: str = "unknown"
    ext_mismatch: bool = False
    entropy: float = 0.0
    flags: list[str] = field(default_factory=list)
    static_summary: dict[str, Any] = field(default_factory=dict)
    error_message: str | None = None


class IsolatedStaticRunner:
    """Supervises isolated worker subprocesses for static analysis."""

    def __init__(self, timeout_s: float = 5.0) -> None:
        self.timeout_s = timeout_s

    def run_analysis(
        self,
        file_path: Path,
        original_filename: str,
        tool: str = "all",
    ) -> IsolatedStaticResult:
        """Run static parser in isolated subprocess with timeout and setrlimit."""
        cmd = [
            sys.executable,
            "-m",
            "sentinel.scan.static_worker",
            "--file",
            str(file_path),
            "--tool",
            tool,
            "--filename",
            original_filename,
        ]

        preexec = _linux_limits if sys.platform.startswith("linux") else None

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
                preexec_fn=preexec,
                check=False,
            )

            if proc.returncode != 0:
                logger.warning(
                    "Static parser worker exited with error code %d: %s",
                    proc.returncode,
                    proc.stderr.strip(),
                )
                return IsolatedStaticResult(
                    status="error",
                    flags=["static_analysis_crash"],
                    error_message=f"Parser worker crashed: {proc.stderr.strip()}",
                )

            data = json.loads(proc.stdout)
            return IsolatedStaticResult(
                status="success",
                detected_type=data.get("detected_type", "unknown"),
                ext_mismatch=data.get("ext_mismatch", False),
                entropy=data.get("entropy", 0.0),
                flags=data.get("flags", []),
                static_summary=data.get("static_summary", {}),
            )

        except subprocess.TimeoutExpired:
            logger.warning("Static parser worker timed out after %.1f seconds", self.timeout_s)
            return IsolatedStaticResult(
                status="timeout",
                flags=["static_analysis_timeout"],
                error_message=f"Parser timed out after {self.timeout_s}s",
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to execute static parser worker: %s", exc)
            return IsolatedStaticResult(
                status="error",
                flags=["static_analysis_error"],
                error_message=str(exc),
            )
