"""Unit tests for platform mock implementations."""

from pathlib import Path

import pytest

from sentinel.platform.base import UsbDeviceDescriptor
from sentinel.platform.display_console import ConsoleDisplay
from sentinel.platform.gpio import MockDoorLock, MockIndicator, MockTamper
from sentinel.platform.mock_usb import MockUsbSource


@pytest.mark.asyncio
async def test_mock_usb_source_events_and_mount(tmp_path: Path) -> None:
    """Test MockUsbSource event queuing, mounting, and unmounting."""
    usb = MockUsbSource(default_mount_dir=tmp_path)
    device = UsbDeviceDescriptor(
        device_id="mock_usb_1",
        vendor_id="1234",
        product_id="5678",
        serial_number="TEST_SERIAL_123",
        interface_classes=[0x08],
    )

    usb.inject_connect(device, filesystem_path=tmp_path)

    # Read event from generator
    event_iter = usb.events()
    event = await anext(event_iter)
    assert event.event_type == "CONNECT"
    assert event.device.serial_number == "TEST_SERIAL_123"

    # Test mount
    mount_res = await usb.mount(device)
    assert mount_res.success is True
    assert mount_res.read_only is True
    assert mount_res.mount_point == tmp_path
    assert "mock_usb_1" in usb.mounted_devices

    # Test unmount
    await usb.unmount(device)
    assert "mock_usb_1" not in usb.mounted_devices


@pytest.mark.asyncio
async def test_mock_usb_mount_failure() -> None:
    """Test MockUsbSource failure simulation."""
    usb = MockUsbSource()
    usb.simulate_mount_failure = True
    device = UsbDeviceDescriptor(device_id="mock_dev_fail")
    res = await usb.mount(device)
    assert res.success is False
    assert "Simulated mount failure" in (res.error_message or "")


def test_console_display() -> None:
    """Test ConsoleDisplay history tracking."""
    display = ConsoleDisplay(silent=True)
    assert display.current_status == "IDLE"

    display.show("SCANNING", ["Scanning file 1", "Scanning file 2"])
    assert display.current_status == "SCANNING"
    assert len(display.history) == 1
    assert display.history[0][0] == "SCANNING"

    display.clear()
    assert display.current_status == "IDLE"


def test_mock_indicator() -> None:
    """Test MockIndicator LED color and beep tracking."""
    ind = MockIndicator()
    assert ind.current_state == "off"

    ind.set_state("green")
    assert ind.current_state == "green"
    ind.beep("success")
    assert ind.beep_history == ["success"]


def test_mock_tamper() -> None:
    """Test MockTamper trigger callback."""
    tamper = MockTamper()
    called = []

    def _cb() -> None:
        called.append(True)

    tamper.on_tamper(_cb)
    assert not tamper.is_triggered()

    tamper.trigger()
    assert tamper.is_triggered()
    assert len(called) == 1

    tamper.reset()
    assert not tamper.is_triggered()


def test_mock_door_lock_fail_closed() -> None:
    """Door lock must default to locked (fail closed)."""
    door = MockDoorLock()
    assert door.is_locked() is True

    door.unlock()
    assert door.is_locked() is False
    assert door.unlock_count == 1

    door.lock()
    assert door.is_locked() is True
