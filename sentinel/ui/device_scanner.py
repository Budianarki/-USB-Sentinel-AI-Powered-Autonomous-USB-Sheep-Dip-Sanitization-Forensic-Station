"""Hardware USB storage device detector for Sentinel Station UI/UX.

Multi-source hardware detection:
1. Primary: pyudev kernel block subsystem with USB bus parent discovery
2. Secondary fallback: lsblk -J -O hardware hierarchy analysis
3. Dynamic auto-mount via udisks2 for plug-and-play sheep-dip station
"""

from __future__ import annotations

import json
import logging
import subprocess
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

    # 1. Primary: pyudev detection
    try:
        import pyudev  # type: ignore[import-untyped]

        context = pyudev.Context()
        for dev in context.list_devices(subsystem="block"):
            props = dev.properties
            dev_type = props.get("DEVTYPE")

            # Check if device sits on the USB bus
            parent_usb = dev.find_parent("usb") or (props.get("ID_BUS") == "usb")
            if not parent_usb:
                continue

            # Accept partitions or unpartitioned formatted raw disks
            has_fs = bool(props.get("ID_FS_TYPE") or props.get("ID_FS_USAGE") == "filesystem")
            if dev_type != "partition" and not (dev_type == "disk" and has_fs):
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
                media_path = Path("/media")
                for candidate in media_path.glob(f"*/{uuid_val}"):
                    if candidate.exists():
                        active_mount = str(candidate)
                        break

            # Fallback auto-mount if device is plugged but unmounted
            if not active_mount and node:
                try:
                    res = subprocess.run(
                        ["udisksctl", "mount", "-b", node, "--no-user-interaction"],
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=3,
                    )
                    if res.returncode == 0:
                        for word in res.stdout.strip().split():
                            if word.startswith(("/media", "/run/media", "/mnt")):
                                active_mount = word.rstrip(".")
                                break
                except Exception as mount_exc:  # noqa: BLE001
                    logger.debug("Auto-mount fallback failed: %s", mount_exc)

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
        logger.debug("Error detecting USB block devices via pyudev: %s", exc)

    # 2. Secondary fallback: lsblk -J -O if pyudev returned 0 devices
    if not devices:
        try:
            lsblk_res = subprocess.run(
                ["lsblk", "-J", "-O"],
                check=False,
                capture_output=True,
                text=True,
                timeout=4,
            )
            if lsblk_res.returncode == 0:
                blk_data = json.loads(lsblk_res.stdout)
                for blk in blk_data.get("blockdevices", []):
                    is_usb = (
                        blk.get("tran") == "usb"
                        or blk.get("hotplug") is True
                        or "usb" in (blk.get("subsystems") or "")
                        or (blk.get("rm") is True and blk.get("kname", "").startswith("sd"))
                    )
                    if not is_usb:
                        continue

                    vendor = (blk.get("vendor") or "USB").strip()
                    model = (blk.get("model") or "Storage").strip()
                    serial = blk.get("serial") or "UNKNOWN"

                    # Check partitions under this disk
                    children = blk.get("children", [])
                    targets = children if children else [blk]

                    for target in targets:
                        node = target.get("path") or f"/dev/{target.get('kname', '')}"
                        uuid_val = target.get("uuid") or "UNKNOWN"
                        fs_type = target.get("fstype") or "vfat"
                        size_str = target.get("size") or "0G"

                        size_gb = 0.0
                        if size_str.endswith("G"):
                            try:
                                size_gb = float(size_str.rstrip("G"))
                            except ValueError:
                                pass
                        elif size_str.endswith("M"):
                            try:
                                size_gb = round(float(size_str.rstrip("M")) / 1024, 2)
                            except ValueError:
                                pass

                        mountpoint = target.get("mountpoint")
                        if not mountpoint and target.get("mountpoints"):
                            for mp in target["mountpoints"]:
                                if mp:
                                    mountpoint = mp
                                    break

                        # Auto-mount if unmounted
                        if not mountpoint and node:
                            try:
                                mount_sub = subprocess.run(
                                    ["udisksctl", "mount", "-b", node, "--no-user-interaction"],
                                    check=False,
                                    capture_output=True,
                                    text=True,
                                    timeout=3,
                                )
                                if mount_sub.returncode == 0:
                                    for word in mount_sub.stdout.strip().split():
                                        if word.startswith(("/media", "/run/media", "/mnt")):
                                            mountpoint = word.rstrip(".")
                                            break
                            except Exception as m_err:  # noqa: BLE001
                                logger.debug("lsblk fallback auto-mount failed: %s", m_err)

                        devices.append({
                            "node": node,
                            "vendor": vendor,
                            "model": model,
                            "label": f"{vendor} {model}".strip(),
                            "serial": serial,
                            "uuid": uuid_val,
                            "fs_type": fs_type,
                            "size_gb": size_gb,
                            "mount_point": mountpoint or "",
                            "is_mounted": bool(mountpoint),
                        })
        except Exception as lsblk_exc:  # noqa: BLE001
            logger.debug("Failed running lsblk fallback: %s", lsblk_exc)

    return devices
