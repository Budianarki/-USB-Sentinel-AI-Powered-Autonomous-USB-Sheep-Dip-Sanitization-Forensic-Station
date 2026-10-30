"""Integration tests for Phase 0: Mock USB session lifecycle and state machine."""

from pathlib import Path

import pytest

from sentinel.main import SentinelStation
from sentinel.platform.base import UsbDeviceDescriptor, UsbEvent
from sentinel.platform.display_console import ConsoleDisplay
from sentinel.platform.gpio import MockDoorLock, MockIndicator, MockTamper
from sentinel.platform.mock_usb import MockUsbSource
from sentinel.util.config import SentinelConfig


@pytest.fixture
def station(tmp_path: Path) -> tuple[SentinelStation, MockUsbSource, ConsoleDisplay, MockIndicator, MockTamper]:
    config = SentinelConfig(mode="laptop_mock")
    usb_source = MockUsbSource(default_mount_dir=tmp_path)
    display = ConsoleDisplay(silent=True)
    indicator = MockIndicator()
    tamper = MockTamper()
    door_lock = MockDoorLock()

    stn = SentinelStation(
        config=config,
        usb_source=usb_source,
        display=display,
        indicator=indicator,
        tamper=tamper,
        door_lock=door_lock,
    )
    return stn, usb_source, display, indicator, tamper


@pytest.mark.asyncio
async def test_empty_usb_session_allow(
    station: tuple[SentinelStation, MockUsbSource, ConsoleDisplay, MockIndicator, MockTamper],
    tmp_path: Path,
) -> None:
    """Empty USB flashdisk must flow through entire lifecycle and be ALLOWED."""
    stn, _usb, display, indicator, _ = station

    device = UsbDeviceDescriptor(
        device_id="usb_mock_001",
        vendor_id="0781",
        product_id="5567",
        serial_number="SAN_DISK_001",
        interface_classes=[0x08],  # Mass storage
        product_name="Ultra USB 3.0",
    )

    event = UsbEvent(event_type="CONNECT", device=device, timestamp=100.0)
    decision = await stn.handle_usb_event(event)

    assert decision is not None
    assert decision.action == "ALLOW"
    assert decision.risk == 0.0
    assert "Empty flashdisk" in decision.deterministic_reasons[0]

    # Verify state machine returned to IDLE
    assert stn.state == "IDLE"
    assert stn.active_session_id is None
    assert stn.active_device is None

    # Verify indicator and display
    assert indicator.current_state == "green"
    assert "success" in indicator.beep_history
    assert display.current_status == "ALLOWED"


@pytest.mark.asyncio
async def test_badusb_hid_blocked_in_guard(
    station: tuple[SentinelStation, MockUsbSource, ConsoleDisplay, MockIndicator, MockTamper],
) -> None:
    """Device presenting HID interface (0x03) must be immediately BLOCKED by Layer 1 Guard."""
    stn, _, display, indicator, _ = station

    # Emulate a Rubber Ducky presenting Mass Storage + HID keyboard composite
    bad_device = UsbDeviceDescriptor(
        device_id="usb_ducky_001",
        vendor_id="1234",
        product_id="bad1",
        serial_number="DUCKY_KEYBOARD",
        interface_classes=[0x08, 0x03],  # Mass storage + HID!
        product_name="Innocent Flashdisk",
    )

    event = UsbEvent(event_type="CONNECT", device=bad_device, timestamp=101.0)
    decision = await stn.handle_usb_event(event)

    assert decision is not None
    assert decision.action == "BLOCK"
    assert decision.risk == 1.0
    assert "BadUSB" in decision.deterministic_reasons[0]

    assert stn.state == "IDLE"
    assert indicator.current_state == "red"
    assert "alarm" in indicator.beep_history
    assert display.current_status == "BLOCKED"


@pytest.mark.asyncio
async def test_second_insertion_rejected_with_alarm(
    station: tuple[SentinelStation, MockUsbSource, ConsoleDisplay, MockIndicator, MockTamper],
) -> None:
    """When a session is active, plugging a second device must be rejected with alarm."""
    stn, _, display, indicator, _ = station

    # Set state as active in middle of session
    stn.state = "SCANNING"
    stn.active_session_id = "session-123"

    second_dev = UsbDeviceDescriptor(
        device_id="usb_second_002",
        serial_number="SECOND_DEVICE",
        interface_classes=[0x08],
    )
    event = UsbEvent(event_type="CONNECT", device=second_dev, timestamp=102.0)
    decision = await stn.handle_usb_event(event)

    assert decision is None
    assert "alarm" in indicator.beep_history
    assert display.current_status == "REJECTED"


@pytest.mark.asyncio
async def test_forced_unplug_aborts_session(
    station: tuple[SentinelStation, MockUsbSource, ConsoleDisplay, MockIndicator, MockTamper],
) -> None:
    """Unplugging USB while scanning must abort the session without ALLOW."""
    stn, _usb, display, indicator, _ = station

    device = UsbDeviceDescriptor(
        device_id="usb_pull_test",
        serial_number="PULL_EARLY",
        interface_classes=[0x08],
    )

    stn.active_device = device
    stn.active_session_id = "session-pull"
    stn.state = "SCANNING"

    disconnect_event = UsbEvent(event_type="DISCONNECT", device=device, timestamp=103.0)
    await stn.handle_usb_event(disconnect_event)

    assert stn.state == "IDLE"
    assert stn.active_device is None
    assert "alarm" in indicator.beep_history
    assert display.current_status == "ABORTED"


def test_tamper_switch_triggers_alarm(
    station: tuple[SentinelStation, MockUsbSource, ConsoleDisplay, MockIndicator, MockTamper],
) -> None:
    """Triggering chassis tamper switch must activate visual/audible alarms immediately."""
    _, _, display, indicator, tamper = station

    tamper.trigger()
    assert indicator.current_state == "red"
    assert "alarm" in indicator.beep_history
    assert display.current_status == "SECURITY ALERT"
