"""Unit tests for scanner engines, fault injection, and mock discipline."""

from pathlib import Path

from sentinel.scan.clamav import (
    RUNTIME_EICAR_BYTES,
    ClamAvScanner,
    MockClamAvScanner,
    create_clamav_scanner,
)
from sentinel.scan.yara_scanner import (
    MockYaraScanner,
    YaraScanner,
    create_yara_scanner,
)


def test_runtime_eicar_construction_and_detection() -> None:
    """Invariant: EICAR is constructed at runtime and detected without hardcoded malware in repo."""
    # Ensure raw test bytes match standard length (68 bytes)
    assert len(RUNTIME_EICAR_BYTES) == 68
    assert RUNTIME_EICAR_BYTES.startswith(b"X5O!P%@AP[4\\")
    assert RUNTIME_EICAR_BYTES.endswith(b"FILE!$H+H*")

    scanner = MockClamAvScanner()
    # Stream chunks containing runtime EICAR
    chunks = [b"Prefix data ", RUNTIME_EICAR_BYTES, b" Postfix data"]
    result = scanner.scan_stream(chunks)

    assert result.clean is False
    assert result.virus_name is not None
    assert "EICAR" in result.virus_name
    assert result.is_mock is True
    assert result.scanners_ok is True


def test_clamav_offline_fault_injection_in_iot_mode() -> None:
    """Fault Injection: When ClamAV daemon is unreachable in IoT mode, scanners_ok must be False."""
    scanner = ClamAvScanner(host="127.0.0.1", port=9999, timeout_s=0.5)

    assert scanner.is_available() is False

    res = scanner.scan_stream([b"test data"])
    assert res.clean is False
    assert res.scanners_ok is False
    assert "offline or error" in (res.error_message or "")


def test_yara_uninitialized_fault_injection_in_iot_mode() -> None:
    """Fault Injection: When YARA library or rules are unavailable in IoT mode, scanners_ok must be False."""
    scanner = YaraScanner(rules_path=Path("/non_existent_rules.yar"))

    res = scanner.scan_data(b"some data")
    assert res.scanners_ok is False
    assert res.hits == []
    assert res.error_message is not None


def test_mock_scanners_only_active_in_laptop_mock_mode() -> None:
    """Mock scanners must only be created in laptop_mock mode and be flagged as is_mock=True."""
    clam_mock = create_clamav_scanner(mode="laptop_mock")
    assert isinstance(clam_mock, MockClamAvScanner)
    assert clam_mock.is_mock is True

    yara_mock = create_yara_scanner(mode="laptop_mock")
    assert isinstance(yara_mock, MockYaraScanner)
    assert yara_mock.is_mock is True

    clam_iot = create_clamav_scanner(mode="iot")
    assert isinstance(clam_iot, ClamAvScanner)

    yara_iot = create_yara_scanner(mode="iot")
    assert isinstance(yara_iot, YaraScanner)
