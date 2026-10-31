"""Integration tests for Checkpoint 1B: Deterministic scanning lifecycle, TOCTOU, and fault injection."""

import zipfile
from pathlib import Path
from typing import Literal

import pytest

from sentinel.main import SentinelStation
from sentinel.platform.base import UsbDeviceDescriptor, UsbEvent
from sentinel.platform.display_console import ConsoleDisplay
from sentinel.platform.gpio import MockDoorLock, MockIndicator, MockTamper
from sentinel.platform.mock_usb import MockUsbSource
from sentinel.scan.clamav import MOCK_MALWARE_SIG, MockClamAvScanner
from sentinel.scan.engine import ScanEngine
from sentinel.scan.yara_scanner import MockYaraScanner
from sentinel.util.config import PolicyConfig, PolicyThresholds, SentinelConfig


@pytest.fixture
def test_device() -> UsbDeviceDescriptor:
    return UsbDeviceDescriptor(
        device_id="usb_test_device_01",
        vendor_id="0781",
        product_id="5583",
        serial_number="SECURE_TEST_01",
        interface_classes=[0x08],  # Mass storage
    )


@pytest.fixture
def station_factory(tmp_path: Path):
    def _create(
        mode: Literal["iot", "laptop_mock"] = "laptop_mock",
        simulate_clamav_down: bool = False,
        simulate_yara_down: bool = False,
    ):
        config = SentinelConfig(mode=mode)
        policy_config = PolicyConfig(
            version="1.0.0",
            thresholds=PolicyThresholds(allow=0.15, review=0.40, block=0.75),
        )

        usb_source = MockUsbSource(default_mount_dir=tmp_path)
        display = ConsoleDisplay(silent=True)
        indicator = MockIndicator()
        tamper = MockTamper()
        door_lock = MockDoorLock()

        clamav_mock = MockClamAvScanner(simulate_daemon_down=simulate_clamav_down)
        yara_mock = MockYaraScanner(simulate_rules_broken=simulate_yara_down)
        scan_engine = ScanEngine(
            config=config,
            policy_config=policy_config,
            clamav_scanner=clamav_mock,
            yara_scanner=yara_mock,
        )

        stn = SentinelStation(
            config=config,
            usb_source=usb_source,
            display=display,
            indicator=indicator,
            tamper=tamper,
            door_lock=door_lock,
            scan_engine=scan_engine,
        )
        return stn, display, indicator

    return _create


@pytest.mark.asyncio
async def test_benign_files_session_yields_allow(
    station_factory,
    tmp_path: Path,
    test_device: UsbDeviceDescriptor,
) -> None:
    """Flashdisk with allowed benign files (text, png header) must result in ALLOW."""
    # Populate tmp_path with benign files
    doc = tmp_path / "meeting_notes.txt"
    doc.write_text("All actions clean and documented.")
    img = tmp_path / "diagram.png"
    img.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)

    stn, display, indicator = station_factory(mode="laptop_mock")

    event = UsbEvent(event_type="CONNECT", device=test_device, timestamp=1.0)
    decision = await stn.handle_usb_event(event)

    assert decision is not None
    assert decision.action == "ALLOW"
    assert decision.risk <= 0.15
    assert display.current_status == "[MOCK] ALLOWED"
    assert indicator.current_state == "green"


@pytest.mark.asyncio
async def test_runtime_eicar_yields_block(
    station_factory,
    tmp_path: Path,
    test_device: UsbDeviceDescriptor,
) -> None:
    """Flashdisk containing mock malware test signature must result in BLOCK."""
    eicar_file = tmp_path / "test_signature.bin"
    eicar_file.write_bytes(MOCK_MALWARE_SIG)

    stn, display, indicator = station_factory(mode="laptop_mock")

    event = UsbEvent(event_type="CONNECT", device=test_device, timestamp=2.0)
    decision = await stn.handle_usb_event(event)

    assert decision is not None
    assert decision.action == "BLOCK"
    assert decision.risk == 1.0
    assert any(
        "Antivirus or YARA" in r or "Antivirus hit" in r for r in decision.deterministic_reasons
    )
    assert display.current_status == "[MOCK] BLOCKED"
    assert indicator.current_state == "red"


@pytest.mark.asyncio
async def test_toctou_tamper_fault_yields_quarantine(
    station_factory,
    tmp_path: Path,
    test_device: UsbDeviceDescriptor,
) -> None:
    """Fault: Hardware returning different bytes between stream and buffer must trigger QUARANTINE."""
    suspicious_file = tmp_path / "tamper_target.dat"
    suspicious_file.write_bytes(b"initial_innocent_bytes")

    stn, display, _indicator = station_factory(mode="laptop_mock")

    # Hook scan_engine to simulate TOCTOU stream tamper
    orig_scan = stn.scan_engine.scan_mount
    stn.scan_engine.scan_mount = lambda *args, **kwargs: orig_scan(
        *args, **(kwargs | {"_simulate_stream_tamper": True})
    )

    event = UsbEvent(event_type="CONNECT", device=test_device, timestamp=3.0)
    decision = await stn.handle_usb_event(event)

    assert decision is not None
    assert decision.action == "QUARANTINE"
    assert any(
        "TOCTOU" in r or "scan incomplete" in r.lower() for r in decision.deterministic_reasons
    )
    assert display.current_status == "[MOCK] QUARANTINE"


@pytest.mark.asyncio
async def test_zip_bomb_metadata_check_yields_quarantine(
    station_factory,
    tmp_path: Path,
    test_device: UsbDeviceDescriptor,
) -> None:
    """Zip bomb with excessive decompression ratio (> 100x) must fail closed to QUARANTINE."""
    zip_file = tmp_path / "suspicious_bomb.zip"
    payload = b"0" * 400_000
    with zipfile.ZipFile(zip_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("huge_file.dat", payload)

    stn, display, _indicator = station_factory(mode="laptop_mock")

    event = UsbEvent(event_type="CONNECT", device=test_device, timestamp=4.0)
    decision = await stn.handle_usb_event(event)

    assert decision is not None
    assert decision.action in ("QUARANTINE", "BLOCK")
    assert any(
        "Zip bomb" in r or "scan incomplete" in r.lower() for r in decision.deterministic_reasons
    )
    assert display.current_status in ("[MOCK] QUARANTINE", "[MOCK] BLOCKED")


@pytest.mark.asyncio
async def test_unicode_rtl_spoofing_yields_quarantine_or_block(
    station_factory,
    tmp_path: Path,
    test_device: UsbDeviceDescriptor,
) -> None:
    """Filename containing Unicode RLO override (e.g. evil\u202edpx.exe) must be quarantined/blocked."""
    spoofed = tmp_path / "invoice_\u202edpx.exe"
    spoofed.write_bytes(b"some fake invoice text")

    stn, _display, _indicator = station_factory(mode="laptop_mock")

    event = UsbEvent(event_type="CONNECT", device=test_device, timestamp=5.0)
    decision = await stn.handle_usb_event(event)

    assert decision is not None
    assert decision.action in ("QUARANTINE", "BLOCK")
    assert any("Unicode BiDi" in r for r in decision.deterministic_reasons)


@pytest.mark.asyncio
async def test_scanners_offline_fault_in_iot_mode_yields_quarantine(
    station_factory,
    tmp_path: Path,
    test_device: UsbDeviceDescriptor,
) -> None:
    """Fault Injection: When scanners are offline, decision must fail closed to QUARANTINE."""
    safe_file = tmp_path / "safe.txt"
    safe_file.write_text("Hello")

    # Simulate ClamAV daemon down in IoT mode
    stn, display, _indicator = station_factory(mode="iot", simulate_clamav_down=True)

    event = UsbEvent(event_type="CONNECT", device=test_device, timestamp=6.0)
    decision = await stn.handle_usb_event(event)

    assert decision is not None
    assert decision.action == "QUARANTINE"
    assert any(
        "Security scanners offline" in r or "ClamAV" in r for r in decision.deterministic_reasons
    )
    assert display.current_status == "QUARANTINE"  # In IoT mode, no [MOCK] prefix
