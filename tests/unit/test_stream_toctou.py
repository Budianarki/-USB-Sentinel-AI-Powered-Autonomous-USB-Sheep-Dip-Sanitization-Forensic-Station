"""Unit tests for Anti-TOCTOU streaming reader and hash integrity verification."""

from pathlib import Path

from sentinel.scan.clamav import MockClamAvScanner
from sentinel.scan.stream_reader import process_untrusted_file_stream


def test_clean_streaming_read_and_cleanup(tmp_path: Path) -> None:
    """Stream file once, compute SHA256, verify integrity, and ensure temp file is cleaned up."""
    usb_file = tmp_path / "normal_data.bin"
    content = b"Safe deterministic flashdisk payload" * 100
    usb_file.write_bytes(content)

    mock_clamav = MockClamAvScanner()
    recorded_temp_path = None

    with process_untrusted_file_stream(usb_file, clamav_scanner=mock_clamav) as res:
        recorded_temp_path = res.temp_path
        assert res.integrity_verified is True
        assert res.flags == []
        assert res.size == len(content)
        assert res.temp_path is not None
        assert res.temp_path.exists()
        assert res.temp_path.read_bytes() == content

    # Post-context: verify working copy was automatically deleted
    assert recorded_temp_path is not None
    assert not recorded_temp_path.exists()


def test_toctou_fault_simulation_triggers_quarantine_flag(tmp_path: Path) -> None:
    """Fault Injection: If file bytes differ between stream and buffer, integrity mismatch must be flagged."""
    usb_file = tmp_path / "toctou_device_file.bin"
    usb_file.write_bytes(b"initial_read_benign_bytes")

    mock_clamav = MockClamAvScanner()

    # Simulate hardware changing content behind our back
    with process_untrusted_file_stream(
        usb_file,
        clamav_scanner=mock_clamav,
        _simulate_tamper_on_temp=True,
    ) as res:
        assert res.integrity_verified is False
        assert "integrity_hash_mismatch" in res.flags


def test_file_size_quota_exceeded_aborts_reading(tmp_path: Path) -> None:
    """Quota limit exceeded during stream read must abort reading and flag quota exceed."""
    usb_file = tmp_path / "huge_file.bin"
    # 2 MB content
    usb_file.write_bytes(b"A" * (2 * 1024 * 1024))

    mock_clamav = MockClamAvScanner()

    # Set quota threshold to max 1 MB
    with process_untrusted_file_stream(
        usb_file,
        clamav_scanner=mock_clamav,
        max_file_mb=1,
    ) as res:
        assert res.quota_exceeded is True
        assert "file_size_quota_exceeded" in res.flags

