"""YARA scanner and mock scanner for Layer 2.

In IoT mode:
- Requires real YARA engine and rule files.
- If YARA library is not available or rules fail to compile -> scanners_ok=False.

In laptop_mock mode:
- MockYaraScanner provides simulated signature detection with prominent [MOCK] labeling.
- If real YARA is installed and rules are present, real scanning can also be evaluated.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Check for yara library
try:
    import yara  # type: ignore[import-untyped,import-not-found]
except ImportError:
    yara = None

DEFAULT_YARA_RULES_PATH = Path(__file__).parent / "yara_rules" / "index.yar"


@dataclass
class YaraScanResult:
    """Outcome of YARA signature scanning."""

    hits: list[str] = field(default_factory=list)
    scanners_ok: bool = True
    error_message: str | None = None
    is_mock: bool = False


class YaraScanner:
    """Production YARA scanner compiling and evaluating YARA rules."""

    def __init__(self, rules_path: str | Path | None = None) -> None:
        self.rules_path: Path | None = None
        if rules_path is not None:
            self.rules_path = Path(rules_path)
        elif DEFAULT_YARA_RULES_PATH.exists():
            self.rules_path = DEFAULT_YARA_RULES_PATH

        self.compiled_rules: Any = None
        self.init_error: str | None = None

        if yara is None:
            self.init_error = "YARA library (yara-python) not installed on IoT system"
            return

        if self.rules_path and self.rules_path.exists():
            try:
                self.compiled_rules = yara.compile(filepath=str(self.rules_path))
            except Exception as exc:  # noqa: BLE001
                self.init_error = f"Failed to compile YARA rules at {self.rules_path}: {exc}"
        else:
            self.init_error = f"YARA rules file not found: {self.rules_path}"

    def scan_data(self, data: bytes) -> YaraScanResult:
        """Scan byte buffer against compiled YARA rules."""
        if self.init_error or self.compiled_rules is None:
            return YaraScanResult(
                hits=[],
                scanners_ok=False,
                error_message=self.init_error or "YARA engine not ready",
            )

        try:
            matches = self.compiled_rules.match(data=data)
            hit_names = [m.rule for m in matches]
            return YaraScanResult(hits=hit_names, scanners_ok=True)
        except Exception as exc:  # noqa: BLE001
            return YaraScanResult(
                hits=[],
                scanners_ok=False,
                error_message=f"YARA scan execution error: {exc}",
            )


class MockYaraScanner:
    """Mock YARA scanner for laptop_mock mode.

    Labels all outputs explicitly with [MOCK].
    """

    def __init__(self, simulate_rules_broken: bool = False) -> None:
        self.simulate_rules_broken = simulate_rules_broken
        self.is_mock = True

    def scan_data(self, data: bytes) -> YaraScanResult:
        logger.info("[MOCK YARA] Scanning data buffer in laptop_mock mode.")
        if self.simulate_rules_broken:
            return YaraScanResult(
                hits=[],
                scanners_ok=False,
                error_message="[MOCK] Simulated YARA engine failure",
                is_mock=True,
            )

        hits: list[str] = []
        lower_data = data.lower()

        # Simulated signatures based on MalwareBazaar & vx-underground profiles
        if b"raspberryrobin" in lower_data or (b"msiexec" in lower_data and b"/q /n -i" in lower_data):
            hits.append("[MOCK] RaspberryRobin_USB_Worm")
        if b"lockbit" in lower_data or b"vssadmin delete shadows" in lower_data:
            hits.append("[MOCK] LockBit_Ransomware_Indicators")
        if b"redlinestealer" in lower_data or b"encryptedusername" in lower_data:
            hits.append("[MOCK] RedLine_Stealer_Signatures")
        if b"ramnit" in lower_data:
            hits.append("[MOCK] Ramnit_USB_Spreader")
        if b"mimikatz" in lower_data:
            hits.append("[MOCK] Hacktool.Mimikatz.Gen")
        if b"powershell" in lower_data and (
            b"-enc" in lower_data or b"-encodedcommand" in lower_data
        ):
            hits.append("[MOCK] Suspicious_Encoded_PowerShell")
        if b"eval(base64_decode" in lower_data:
            hits.append("[MOCK] WebShell.PhpEvalBase64")

        return YaraScanResult(hits=hits, scanners_ok=True, is_mock=True)


def create_yara_scanner(
    mode: str,
    rules_path: str | Path | None = None,
) -> YaraScanner | MockYaraScanner:
    """Factory creating appropriate YARA scanner based on system mode."""
    if mode == "laptop_mock":
        return MockYaraScanner()
    return YaraScanner(rules_path=rules_path)
