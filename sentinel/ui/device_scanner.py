"""Hardware USB storage device detector for Sentinel Station UI/UX."""

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def list_connected_usb_devices() -> list[dict[str, Any]]:
    """Enumerate all connected USB block storage devices and partitions.

    Returns empty list if 0 devices are plugged in.
    """
    devices: list[dict[str, Any]] = []

    # Read current system mount points
    mount_points: dict[str, str] = {}
    try:
        proc_mounts = Path("/proc/mounts")
        if proc_mounts.exists():
            for line in proc_mounts.read_text().splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0].startswith("/dev/"):
                    mount_points[parts[0]] = parts[1]
    except Exception as exc:  # noqa: BLE001
        logger.debug("Failed reading /proc/mounts: %s", exc)

    try:
        import pyudev  # type: ignore[import-untyped]

        context = pyudev.Context()
        for dev in context.list_devices(subsystem="block"):
            props = dev.properties
            dev_type = props.get("DEVTYPE")
            if dev_type != "partition":
                continue

            # Check if device sits on the USB bus
            parent_usb = dev.find_parent("usb")
            if not parent_usb:
                continue

            node = dev.device_node or ""
            uuid_val = props.get("ID_FS_UUID", "UNKNOWN")
            vendor = props.get("ID_VENDOR", props.get("ID_USB_VENDOR", "Generic USB"))
            model = props.get("ID_MODEL", props.get("ID_USB_MODEL", "Flash Drive"))
            serial = props.get("ID_SERIAL_SHORT", props.get("ID_SERIAL", "UNKNOWN"))
            fs_type = props.get("ID_FS_TYPE", "vfat")
            fs_size_bytes = int(props.get("ID_FS_SIZE", 0) or 0)

            # Get human-readable size
            size_gb = round(fs_size_bytes / (1024**3), 2) if fs_size_bytes else 0.0

            # Find active mount point
            active_mount = mount_points.get(node)
            if not active_mount and uuid_val:
                # Check standard linux automount locations
                media_path = Path("/media")
                for candidate in media_path.glob(f"*/{uuid_val}"):
                    if candidate.exists():
                        active_mount = str(candidate)
                        break

            devices.append({
                "node": node,
                "vendor": vendor,
                "model": model,
                "label": f"{vendor} {model}".strip(),
                "serial": serial,
                "uuid": uuid_val,
                "fs_type": fs_type,
                "size_gb": size_gb,
                "mount_point": active_mount or "",
                "is_mounted": bool(active_mount),
            })

    except Exception as exc:  # noqa: BLE001
        logger.error("Error detecting USB block devices via pyudev: %s", exc)

    return devices
