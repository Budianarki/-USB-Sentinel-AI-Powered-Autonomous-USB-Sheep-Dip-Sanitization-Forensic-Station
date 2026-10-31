"""Tests for USB device class evaluation and BadUSB guard (Layer 1).

Tests:
- Mass storage only [0x08] passes.
- Composite [0x08, 0x03] (Mass Storage + HID) is BLOCKED.
- HID [0x03], CDC/Serial [0x02, 0x0A] are BLOCKED.
- Serial reputation: trusted (ALLOW), previously blocked (BLOCK), unknown (ALLOW if class ok).
- Production integration test via SentinelStation.
- Fake pyudev device parsing for LinuxUdevSource._parse_udev_device.
"""

from pathlib import Path
from typing import Any

import pytest
import yaml

from sentinel.guard.usb_class import (
    CLASS_CDC_DATA,
    CLASS_COMM_CDC,
    CLASS_HID,
    CLASS_MASS_STORAGE,
    evaluate_device_class,
)
from sentinel.main import SentinelStation
from sentinel.platform.base import UsbDeviceDescriptor, UsbEvent
from sentinel.platform.display_console import ConsoleDisplay
from sentinel.platform.gpio import MockDoorLock, MockIndicator
from sentinel.platform.mock_usb import MockUsbSource
from sentinel.policy.engine import PolicyEngine
from sentinel.scan.engine import ScanEngine
from sentinel.util.config import PolicyConfig, SentinelConfig


def test_mass_storage_only_allowed() -> None:
    """A pure Mass Storage device [0x08] must be allowed."""
    dev = UsbDeviceDescriptor(
        device_id="/dev/bus/usb/001/002",
        vendor_id="0781",
        product_id="5567",
        serial_number="SAN123456",
        device_class=0x00,
        interface_classes=[CLASS_MASS_STORAGE],
    )
    res = evaluate_device_class(dev)
    assert res.allowed is True
    assert res.action == "ALLOW"
    assert res.risk == 0.0
    assert not res.disallowed_classes
    assert not res.is_composite
    assert res.serial_reputation == "unknown"


def test_composite_storage_and_hid_blocked() -> None:
    """Composite device [0x08, 0x03] represents BadUSB and must be BLOCKED."""
    dev = UsbDeviceDescriptor(
        device_id="/dev/bus/usb/001/003",
        vendor_id="0781",
        product_id="BAD0",
        serial_number="RUBBERDUCKY1",
        device_class=0x00,
        interface_classes=[CLASS_MASS_STORAGE, CLASS_HID],
    )
    res = evaluate_device_class(dev)
    assert res.allowed is False
    assert res.action == "BLOCK"
    assert res.risk == 1.0
    assert CLASS_HID in res.disallowed_classes
    assert res.is_composite is True
    assert any("BadUSB alert" in reason for reason in res.reasons)


def test_hid_only_blocked() -> None:
    """Pure HID device [0x03] (keyboard/mouse) must be BLOCKED."""
    dev = UsbDeviceDescriptor(
        device_id="/dev/bus/usb/001/004",
        vendor_id="046d",
        product_id="c31c",
        serial_number="KEYBOARD01",
        device_class=0x00,
        interface_classes=[CLASS_HID],
    )
    res = evaluate_device_class(dev)
    assert res.allowed is False
    assert res.action == "BLOCK"
    assert res.risk == 1.0
    assert CLASS_HID in res.disallowed_classes
    assert any("Human Interface Device" in reason for reason in res.reasons)


def test_cdc_serial_blocked() -> None:
    """CDC/Serial [0x02, 0x0A] modem/virtual serial must be BLOCKED."""
    dev = UsbDeviceDescriptor(
        device_id="/dev/bus/usb/001/005",
        vendor_id="2341",
        product_id="0043",
        serial_number="ARDUINO_SERIAL",
        device_class=0x00,
        interface_classes=[CLASS_COMM_CDC, CLASS_CDC_DATA],
    )
    res = evaluate_device_class(dev)
    assert res.allowed is False
    assert res.action == "BLOCK"
    assert CLASS_COMM_CDC in res.disallowed_classes


def test_serial_reputation_whitelist_and_blacklist(tmp_path: Path) -> None:
    """Test serial reputation evaluation against YAML configuration."""
    trusted_file = tmp_path / "trusted_devices.yaml"
    trusted_file.write_text(
        yaml.dump({
            "trusted_serials": ["TRUSTED_SN_123"],
            "blocked_serials": ["MALICIOUS_SN_999"],
        }),
        encoding="utf-8",
    )

    # 1. Trusted serial with mass storage
    dev_trusted = UsbDeviceDescriptor(
        device_id="/dev/sdb",
        vendor_id="0781",
        product_id="0001",
        serial_number="TRUSTED_SN_123",
        device_class=0x00,
        interface_classes=[CLASS_MASS_STORAGE],
    )
    res_trusted = evaluate_device_class(dev_trusted, serial_whitelist_file=trusted_file)
    assert res_trusted.allowed is True
    assert res_trusted.serial_reputation == "known_good"

    # 2. Previously blocked serial
    dev_blocked = UsbDeviceDescriptor(
        device_id="/dev/sdc",
        vendor_id="0781",
        product_id="0001",
        serial_number="MALICIOUS_SN_999",
        device_class=0x00,
        interface_classes=[CLASS_MASS_STORAGE],
    )
    res_blocked = evaluate_device_class(dev_blocked, serial_whitelist_file=trusted_file)
    assert res_blocked.allowed is False
    assert res_blocked.action == "BLOCK"
    assert res_blocked.serial_reputation == "previously_blocked"
    assert any("blacklisted" in r for r in res_blocked.reasons)

    # 3. Unknown serial
    dev_unknown = UsbDeviceDescriptor(
        device_id="/dev/sdd",
        vendor_id="0781",
        product_id="0001",
        serial_number="UNKNOWN_SN_456",
        device_class=0x00,
        interface_classes=[CLASS_MASS_STORAGE],
    )
    res_unknown = evaluate_device_class(dev_unknown, serial_whitelist_file=trusted_file)
    assert res_unknown.allowed is True
    assert res_unknown.serial_reputation == "unknown"


@pytest.mark.asyncio
async def test_production_guard_pipeline_blocking(tmp_path: Path) -> None:
    """Test SentinelStation full pipeline rejecting composite BadUSB."""
    cfg = SentinelConfig(mode="laptop_mock")
    policy_cfg = PolicyConfig()
    policy_eng = PolicyEngine(policy_cfg)
    scan_eng = ScanEngine(cfg, policy_cfg)

    usb_source = MockUsbSource()
    display = ConsoleDisplay()
    indicator = MockIndicator()
    door_lock = MockDoorLock()
    db_path = tmp_path / "sentinel.db"

    station = SentinelStation(
        config=cfg,
        usb_source=usb_source,
        display=display,
        indicator=indicator,
        door_lock=door_lock,
        policy_engine=policy_eng,
        scan_engine=scan_eng,
        db_path=db_path,
    )

    composite_dev = UsbDeviceDescriptor(
        device_id="/dev/bus/usb/001/099",
        vendor_id="0781",
        product_id="9999",
        serial_number="BAD_COMPOSITE_001",
        device_class=0x00,
        interface_classes=[CLASS_MASS_STORAGE, CLASS_HID],
    )

    event = UsbEvent(event_type="CONNECT", device=composite_dev, timestamp=100.0)
    decision = await station.handle_usb_event(event)

    assert decision is not None
    assert decision.action == "BLOCK"
    assert decision.risk == 1.0
    assert any("BadUSB" in r for r in decision.deterministic_reasons)
    assert indicator.current_state == "red"
    assert door_lock.is_locked() is True


class FakeUdevAttributes:
    """Mock pyudev Device attributes dict-like interface."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)


class FakeUdevChild:
    """Mock pyudev child interface device."""

    def __init__(self, subsystem: str, iface_class_hex: bytes | str) -> None:
        self.subsystem = subsystem
        self.attributes = FakeUdevAttributes({"bInterfaceClass": iface_class_hex})


class FakeUdevDevice:
    """Mock pyudev parent USB device."""

    def __init__(
        self,
        dev_class_hex: bytes | str | None,
        properties: dict[str, str],
        children: list[FakeUdevChild],
        device_node: str | None = None,
    ) -> None:
        self.attributes = FakeUdevAttributes(
            {"bDeviceClass": dev_class_hex} if dev_class_hex is not None else {}
        )
        self.properties = properties
        self.children = children
        self.device_node = device_node


def test_linux_udev_parser_with_fake_devices() -> None:
    """Test LinuxUdevSource._parse_udev_device against synthetic pyudev objects."""
    from sentinel.platform.linux_udev import LinuxUdevSource

    # We instantiate LinuxUdevSource without starting monitor loop
    source = object.__new__(LinuxUdevSource)

    # Fake 1: Pure Mass Storage with bytes attribute
    child1 = FakeUdevChild(subsystem="usb", iface_class_hex=b"08")
    fake1 = FakeUdevDevice(
        dev_class_hex=b"00",
        properties={
            "ID_VENDOR_ID": "0781",
            "ID_MODEL_ID": "5581",
            "ID_SERIAL_SHORT": "1234567890ABC",
            "ID_VENDOR": "SanDisk",
            "ID_MODEL": "Ultra",
        },
        children=[child1],
        device_node="/dev/sdb",
    )

    desc1 = source._parse_udev_device(fake1)
    assert desc1.vendor_id == "0781"
    assert desc1.product_id == "5581"
    assert desc1.serial_number == "1234567890ABC"
    assert desc1.device_class == 0x00
    assert desc1.interface_classes == [0x08]
    assert desc1.manufacturer == "SanDisk"
    assert desc1.product_name == "Ultra"

    # Fake 2: Composite Mass Storage + HID
    c_storage = FakeUdevChild(subsystem="usb", iface_class_hex="08")
    c_hid = FakeUdevChild(subsystem="usb", iface_class_hex="03")
    c_other = FakeUdevChild(subsystem="pci", iface_class_hex="00")  # Should be ignored (subsystem!=usb)

    fake2 = FakeUdevDevice(
        dev_class_hex=None,
        properties={
            "ID_VENDOR_ID": "1111",
            "ID_MODEL_ID": "2222",
            "ID_SERIAL": "COMPOSITE_SN",
        },
        children=[c_storage, c_hid, c_other],
        device_node=None,
    )

    desc2 = source._parse_udev_device(fake2)
    assert desc2.interface_classes == [0x08, 0x03]
    assert desc2.serial_number == "COMPOSITE_SN"
