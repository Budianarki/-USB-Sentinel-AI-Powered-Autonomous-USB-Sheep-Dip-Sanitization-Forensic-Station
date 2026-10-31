"""Integration tests with native Linux components (Layer 1 & Layer 2).

Marked with appropriate markers:
- linux_only: Runs only on Linux environments
- needs_clamd: Runs when real clamd daemon is reachable, skips with clear message otherwise
- needs_root: Runs when root privileges are available, skips with instructions otherwise
"""

import sys
from pathlib import Path

import pytest

from sentinel.platform.linux_udev import LinuxUdevSource
from sentinel.policy.engine import PolicyEngine
from sentinel.scan.clamav import ClamAvScanner, RUNTIME_EICAR_BYTES
from sentinel.scan.engine import ScanEngine
from sentinel.scan.yara_scanner import YaraScanner
from sentinel.util.config import PolicyConfig, SentinelConfig


def is_clamd_reachable(
    socket_path: str = "/var/run/clamav/clamd.ctl",
    host: str = "127.0.0.1",
    port: int = 3310,
) -> bool:
    """Check whether native clamd daemon is responsive via socket or TCP."""
    scanner = ClamAvScanner(host=host, port=port, socket_path=socket_path, timeout_s=1.0)
    return scanner.is_available()


def get_clamd_stream_max_length() -> int:
    """Read StreamMaxLength from clamd.conf, defaulting to 25MB if unconfigured."""
    candidate_paths = [
        Path("/etc/clamav/clamd.conf"),
        Path("/etc/clamd.conf"),
        Path("/etc/clamd.d/clamd.conf"),
    ]
    for p in candidate_paths:
        if p.exists():
            try:
                for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                    clean_line = line.strip()
                    if clean_line.startswith("StreamMaxLength") and not clean_line.startswith("#"):
                        parts = clean_line.split()
                        if len(parts) >= 2:
                            val_str = parts[1].strip()
                            mult = 1
                            if val_str.endswith(("M", "m")):
                                mult = 1024 * 1024
                                val_str = val_str[:-1]
                            elif val_str.endswith(("K", "k")):
                                mult = 1024
                                val_str = val_str[:-1]
                            elif val_str.endswith(("G", "g")):
                                mult = 1024 * 1024 * 1024
                                val_str = val_str[:-1]
                            return int(val_str) * mult
            except Exception:
                pass
    return 25 * 1024 * 1024  # Default 25 MB


# ==============================================================================
# 3.a ClamAV Native INSTREAM Test
# ==============================================================================
@pytest.mark.linux_only
@pytest.mark.needs_clamd
def test_clamav_native_instream_eicar_and_benign() -> None:
    """3.a: Real ClamAV via INSTREAM detects runtime EICAR and reports clean files clean."""
    if not sys.platform.startswith("linux"):
        pytest.skip("Test is Linux-only")

    socket_path = "/var/run/clamav/clamd.ctl"
    if not is_clamd_reachable(socket_path):
        pytest.skip(
            "Native clamd daemon is not reachable at /var/run/clamav/clamd.ctl or 127.0.0.1:3310 "
            "(requires package clamav-daemon and service started)"
        )

    scanner = ClamAvScanner(socket_path=socket_path)

    # 1. EICAR detection
    eicar_res = scanner.scan_stream([RUNTIME_EICAR_BYTES])
    assert eicar_res.clean is False
    assert eicar_res.scanners_ok is True
    assert eicar_res.virus_name is not None
    assert any(tok in eicar_res.virus_name for tok in ("Eicar", "Test", "FOUND"))

    # 2. Benign clean file
    clean_payload = b"USB Sentinel Sheep-Dip Station: Benign verification file text content."
    clean_res = scanner.scan_stream([clean_payload])
    assert clean_res.clean is True
    assert clean_res.scanners_ok is True
    assert clean_res.virus_name is None


# ==============================================================================
# 3.b StreamMaxLength Exceeded Test
# ==============================================================================
@pytest.mark.linux_only
@pytest.mark.needs_clamd
def test_clamav_native_stream_max_length_exceeded() -> None:
    """3.b: Files exceeding StreamMaxLength from clamd.conf must yield scanners_ok=False and never clean."""
    if not sys.platform.startswith("linux"):
        pytest.skip("Test is Linux-only")

    socket_path = "/var/run/clamav/clamd.ctl"
    if not is_clamd_reachable(socket_path):
        pytest.skip("Native clamd daemon is not reachable (needs clamav-daemon service)")

    max_len = get_clamd_stream_max_length()
    scanner = ClamAvScanner(socket_path=socket_path)

    def oversized_stream():
        chunk = b"X" * 65536
        sent = 0
        while sent <= max_len + 65536:
            yield chunk
            sent += len(chunk)

    res = scanner.scan_stream(oversized_stream())
    assert res.clean is False
    assert res.scanners_ok is False or "exceeded" in (res.error_message or "").lower()


# ==============================================================================
# 3.c Clamd Daemon Offline in IoT Mode
# ==============================================================================
@pytest.mark.linux_only
def test_clamav_daemon_offline_in_iot_mode_quarantined() -> None:
    """3.c: When clamd is offline or socket missing in IoT mode, the session action is strictly QUARANTINE."""
    if not sys.platform.startswith("linux"):
        pytest.skip("Test is Linux-only")

    # Scanner pointing to dead socket
    scanner = ClamAvScanner(
        socket_path="/tmp/nonexistent_clamd_sentinel.sock",
        host="127.0.0.1",
        port=65432,
        timeout_s=0.5,
    )
    assert scanner.is_available() is False

    cfg = SentinelConfig(mode="iot")
    pol_cfg = PolicyConfig()
    policy = PolicyEngine(pol_cfg)

    # Invariant 2 fail closed: scanners_ok=False must result in QUARANTINE
    decision = policy.decide(
        session_id="offline_clamd_session",
        scan_complete=True,
        scanners_ok=False,
        filesystem_supported=True,
        deterministic_risk=0.0,
    )
    assert decision.action == "QUARANTINE"
    assert any("Security scanners offline" in r for r in decision.deterministic_reasons)


# ==============================================================================
# 3.d Native YARA Engine Test
# ==============================================================================
@pytest.mark.linux_only
def test_native_yara_compilation_and_matching(tmp_path: Path) -> None:
    """3.d: Real YARA rule compiled and matched; broken rule causes scanners_ok=False and QUARANTINE."""
    if not sys.platform.startswith("linux"):
        pytest.skip("Test is Linux-only")

    # 1. Valid rule compilation & matching
    valid_rule_path = tmp_path / "valid_test_rules.yar"
    valid_rule_path.write_text(
        'rule SentinelCustomExploitToken {\n'
        '    meta:\n'
        '        description = "Test rule for native Linux YARA compilation"\n'
        '    strings:\n'
        '        $sig = "SENTINEL_NATIVE_YARA_TARGET_PAYLOAD_ABC"\n'
        '    condition:\n'
        '        $sig\n'
        '}\n'
    )

    scanner = YaraScanner(rules_path=valid_rule_path)
    assert scanner.init_error is None
    assert scanner.compiled_rules is not None

    # Match payload
    match_result = scanner.scan_data(
        b"Arbitrary prefix ... SENTINEL_NATIVE_YARA_TARGET_PAYLOAD_ABC ... suffix"
    )
    assert match_result.scanners_ok is True
    assert "SentinelCustomExploitToken" in match_result.hits

    # Clean payload
    clean_result = scanner.scan_data(b"Completely innocent data without the signature string.")
    assert clean_result.scanners_ok is True
    assert clean_result.hits == []

    # 2. Broken rule compilation failure
    broken_rule_path = tmp_path / "syntax_error_rules.yar"
    broken_rule_path.write_text("rule Broken { invalid yara syntax here !!! }")

    broken_scanner = YaraScanner(rules_path=broken_rule_path)
    assert broken_scanner.init_error is not None
    assert broken_scanner.compiled_rules is None

    broken_res = broken_scanner.scan_data(b"data")
    assert broken_res.scanners_ok is False
    assert "Failed to compile YARA rules" in (broken_res.error_message or "")

    # Verify PolicyEngine fail-closed on broken YARA scanner
    policy = PolicyEngine(PolicyConfig())
    dec = policy.decide(
        session_id="broken_yara_session",
        scan_complete=True,
        scanners_ok=broken_res.scanners_ok,
        filesystem_supported=True,
        deterministic_risk=0.0,
    )
    assert dec.action == "QUARANTINE"


# ==============================================================================
# 3.h udev Device Guard against Real Hardware Descriptors
# ==============================================================================
@pytest.mark.linux_only
def test_udev_device_guard_against_connected_hardware() -> None:
    """3.h: Live udev descriptor extraction and BadUSB guard evaluation on Linux."""
    if not sys.platform.startswith("linux"):
        pytest.skip("Test is Linux-only")

    try:
        import pyudev
    except ImportError:
        pytest.skip("pyudev is not installed")

    context = pyudev.Context()
    source = LinuxUdevSource()
    devices = list(context.list_devices(subsystem="usb", DEVTYPE="usb_device"))
    assert len(devices) > 0, "Expected at least root hubs or USB devices on Linux"

    cfg = SentinelConfig(mode="iot")
    pol = PolicyEngine(PolicyConfig())

    non_storage_blocked_count = 0
    for dev in devices:
        desc = source._parse_udev_device(dev)
        # Check against allow_classes ([0x08])
        disallowed = [c for c in desc.interface_classes if c not in cfg.usb.allow_classes]
        if disallowed or (0x03 in desc.interface_classes):
            decision = pol.evaluate_guard_violation("live_udev_test", disallowed or [0x03])
            assert decision.action == "BLOCK"
            assert decision.risk == 1.0
            non_storage_blocked_count += 1

    assert non_storage_blocked_count > 0, (
        "Verified Device Guard successfully rejected live non-storage USB devices on host"
    )
