"""USB class evaluation and BadUSB device guard (Layer 1).

Enforces:
- Whitelist of permitted USB classes (default: 0x08 Mass Storage only).
- Instant rejection (BLOCK) of HID (0x03), CDC/Serial (0x02, 0x0A), Wireless (0xE0), etc.
- BadUSB composite detection: devices presenting Mass Storage alongside HID or other classes.
- Device serial reputation: check against trusted whitelist / blocked blacklist.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml

from sentinel.platform.base import UsbDeviceDescriptor

logger = logging.getLogger(__name__)

# Standard USB Device & Interface Classes
CLASS_PER_INTERFACE = 0x00
CLASS_AUDIO = 0x01
CLASS_COMM_CDC = 0x02
CLASS_HID = 0x03
CLASS_PHYSICAL = 0x05
CLASS_IMAGE = 0x06
CLASS_PRINTER = 0x07
CLASS_MASS_STORAGE = 0x08
CLASS_HUB = 0x09
CLASS_CDC_DATA = 0x0A
CLASS_SMART_CARD = 0x0B
CLASS_VIDEO = 0x0E
CLASS_WIRELESS = 0xE0
CLASS_MISCELLANEOUS = 0xEF
CLASS_VENDOR_SPECIFIC = 0xFF

DANGEROUS_BADUSB_CLASSES = {
    CLASS_HID,  # 0x03 Human Interface Device (keyboard emulation)
    CLASS_COMM_CDC,  # 0x02 CDC Communication (virtual serial / modem)
    CLASS_CDC_DATA,  # 0x0A CDC Data
    CLASS_WIRELESS,  # 0xE0 Wireless Controller (Bluetooth / Wi-Fi dongle)
}


@dataclass
class DeviceGuardResult:
    """Outcome of Layer 1 USB device class and serial validation."""

    allowed: bool
    action: Literal["ALLOW", "BLOCK"]
    risk: float = 0.0
    reasons: list[str] = field(default_factory=list)
    disallowed_classes: list[int] = field(default_factory=list)
    is_composite: bool = False
    serial_reputation: Literal["known_good", "unknown", "previously_blocked"] = "unknown"


def load_serial_reputation(
    serial: str,
    whitelist_file: str | Path | None = None,
) -> Literal["known_good", "unknown", "previously_blocked"]:
    """Query serial reputation from trusted_devices.yaml or whitelist config."""
    if not whitelist_file or not serial:
        return "unknown"

    p = Path(whitelist_file)
    if not p.exists():
        return "unknown"

    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        trusted = data.get("trusted_serials", [])
        blocked = data.get("blocked_serials", [])

        if serial in blocked:
            return "previously_blocked"
        if serial in trusted:
            return "known_good"
    except Exception as e:  # noqa: BLE001
        logger.warning("Failed to load serial reputation from %s: %s", whitelist_file, e)

    return "unknown"


def evaluate_device_class(
    device: UsbDeviceDescriptor,
    allow_classes: list[int] | None = None,
    serial_whitelist_file: str | Path | None = None,
) -> DeviceGuardResult:
    """Evaluate USB device descriptor against Layer 1 security rules."""
    allowed_list = allow_classes if allow_classes is not None else [CLASS_MASS_STORAGE]
    reasons: list[str] = []
    disallowed: list[int] = []

    # 1. Collect all declared classes (device class and interface classes)
    classes = set(device.interface_classes)
    if device.device_class and device.device_class != CLASS_PER_INTERFACE:
        classes.add(device.device_class)

    # 2. Check serial reputation
    serial_rep = load_serial_reputation(device.serial_number, serial_whitelist_file)
    if serial_rep == "previously_blocked":
        reasons.append(
            f"Device serial '{device.serial_number}' is blacklisted (previously blocked)"
        )
        return DeviceGuardResult(
            allowed=False,
            action="BLOCK",
            risk=1.0,
            reasons=reasons,
            disallowed_classes=[],
            serial_reputation="previously_blocked",
        )

    # 3. Check for disallowed classes
    for cls_id in classes:
        if cls_id not in allowed_list:
            disallowed.append(cls_id)

    # 4. Check for BadUSB composite device (Storage + HID or other interface)
    is_composite = (CLASS_MASS_STORAGE in classes) and any(
        c != CLASS_MASS_STORAGE for c in classes
    )

    if CLASS_HID in classes:
        reasons.append("BadUSB alert: Human Interface Device (HID) class 0x03 detected")
    elif any(c in DANGEROUS_BADUSB_CLASSES for c in classes):
        reasons.append(f"BadUSB alert: dangerous peripheral class detected ({disallowed})")

    if is_composite and disallowed:
        reasons.append(
            "BadUSB alert: suspicious composite storage device presenting unauthorized interfaces"
        )

    if disallowed:
        if not reasons:
            reasons.append(f"BadUSB protection: disallowed interface class detected ({disallowed})")
        return DeviceGuardResult(
            allowed=False,
            action="BLOCK",
            risk=1.0,
            reasons=reasons,
            disallowed_classes=disallowed,
            is_composite=is_composite,
            serial_reputation=serial_rep,
        )

    return DeviceGuardResult(
        allowed=True,
        action="ALLOW",
        risk=0.0,
        reasons=[],
        disallowed_classes=[],
        is_composite=False,
        serial_reputation=serial_rep,
    )
