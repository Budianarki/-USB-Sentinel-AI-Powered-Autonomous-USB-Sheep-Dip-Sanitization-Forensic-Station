"""Linux udev implementation of UsbSource.

NOTE: This module is Linux-only. All pyudev and Linux mount operations are isolated here.
On non-Linux platforms (e.g. Windows/macOS), attempting to instantiate LinuxUdevSource
will raise a PlatformNotSupportedError.
"""

import asyncio
import sys
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Literal

from sentinel.platform.base import (
    MountResult,
    UsbDeviceDescriptor,
    UsbEvent,
    UsbSource,
)


class PlatformNotSupportedError(RuntimeError):
    """Raised when Linux-specific hardware interfaces are invoked on non-Linux OS."""


# Isolated Linux-only imports
try:
    if sys.platform.startswith("linux"):
        import pyudev  # type: ignore[import-untyped]
    else:
        pyudev = None  # type: ignore[assignment]
except ImportError:
    pyudev = None  # type: ignore[assignment]


class LinuxUdevSource(UsbSource):
    """Linux implementation of UsbSource using pyudev and kernel mount."""

    _mount_base_dir: Path
    _mounted_devices: dict[str, Path]

    def __init__(self, mount_base_dir: Path | None = None) -> None:
        if not sys.platform.startswith("linux"):
            raise PlatformNotSupportedError(
                f"LinuxUdevSource requires Linux, but current platform is '{sys.platform}'"
            )
        if pyudev is None:
            raise PlatformNotSupportedError(
                "pyudev library is required on Linux. Install via pip install pyudev"
            )

        self._mount_base_dir = mount_base_dir or Path("/mnt/sentinel")
        self._udev_context = pyudev.Context()
        self._mounted_devices: dict[str, Path] = {}

    async def events(self) -> AsyncIterator[UsbEvent]:
        """Monitor udev subsystem for USB device plug/unplug events."""
        if not sys.platform.startswith("linux") or pyudev is None:
            raise PlatformNotSupportedError("pyudev is only supported on Linux")

        loop = asyncio.get_running_loop()
        monitor = pyudev.Monitor.from_netlink(self._udev_context)
        monitor.filter_by(subsystem="usb")

        # Create an async queue for udev events
        queue: asyncio.Queue[UsbEvent] = asyncio.Queue()

        def _udev_callback(device: Any) -> None:
            action = device.action
            if action not in ("add", "remove"):
                return

            event_type: Literal["CONNECT", "DISCONNECT"] = (
                "CONNECT" if action == "add" else "DISCONNECT"
            )
            dev_desc = self._parse_udev_device(device)
            event = UsbEvent(
                event_type=event_type,
                device=dev_desc,
                timestamp=time.time(),
            )
            loop.call_soon_threadsafe(queue.put_nowait, event)

        observer = pyudev.MonitorObserver(monitor, callback=_udev_callback)
        observer.start()

        try:
            while True:
                event = await queue.get()
                yield event
                queue.task_done()
        finally:
            observer.stop()

    def _parse_udev_device(self, device: Any) -> UsbDeviceDescriptor:
        """Extract descriptors from pyudev device."""
        props = getattr(device, "properties", device)
        vid = props.get("ID_VENDOR_ID", "0000")
        pid = props.get("ID_MODEL_ID", "0000")
        serial = props.get("ID_SERIAL_SHORT", props.get("ID_SERIAL", "UNKNOWN"))
        dev_class_raw = device.attributes.get("bDeviceClass")
        if dev_class_raw is not None:
            if isinstance(dev_class_raw, bytes):
                dev_class_raw = dev_class_raw.decode("ascii", errors="ignore")
            try:
                dev_class = int(dev_class_raw, 16)
            except (ValueError, TypeError):
                dev_class = 0x00
        else:
            dev_class = 0x00

        # Scan interface classes safely
        interface_classes: list[int] = []
        for child in device.children:
            if child.subsystem == "usb":
                iface_raw = child.attributes.get("bInterfaceClass")
                if iface_raw is not None:
                    if isinstance(iface_raw, bytes):
                        iface_raw = iface_raw.decode("ascii", errors="ignore")
                    try:
                        iface_cls = int(iface_raw, 16)
                        interface_classes.append(iface_cls)
                    except (ValueError, TypeError):
                        pass

        if not interface_classes and dev_class:
            interface_classes.append(dev_class)

        return UsbDeviceDescriptor(
            device_id=device.device_node or f"/dev/bus/usb/{vid}_{pid}_{serial}",
            vendor_id=vid,
            product_id=pid,
            serial_number=serial,
            device_class=dev_class,
            interface_classes=interface_classes,
            manufacturer=props.get("ID_VENDOR"),
            product_name=props.get("ID_MODEL"),
        )

    def build_mount_command(
        self,
        device: UsbDeviceDescriptor,
        mount_point: Path,
    ) -> list[str]:
        """Construct mount command line with Invariant 8 flags."""
        return [
            "mount",
            "-o",
            "ro,noexec,nosuid,nodev",
            device.device_id,
            str(mount_point),
        ]

    async def mount(self, device: UsbDeviceDescriptor) -> MountResult:
        """Mount USB device with ro,noexec,nosuid,nodev (Invariant 8)."""
        if not sys.platform.startswith("linux"):
            raise PlatformNotSupportedError("Mounting requires Linux OS")

        mount_point = self._mount_base_dir / f"usb_{device.serial_number}"
        mount_point.mkdir(parents=True, exist_ok=True)

        cmd = self.build_mount_command(device, mount_point)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()

        if proc.returncode != 0:
            return MountResult(
                success=False,
                error_message=stderr.decode().strip(),
                read_only=True,
            )

        self._mounted_devices[device.device_id] = mount_point
        return MountResult(
            success=True,
            mount_point=mount_point,
            read_only=True,
        )

    async def unmount(self, device: UsbDeviceDescriptor) -> None:
        """Unmount USB device."""
        if not sys.platform.startswith("linux"):
            return

        mount_point = self._mounted_devices.pop(device.device_id, None)
        if mount_point and mount_point.exists():
            proc = await asyncio.create_subprocess_exec("umount", str(mount_point))
            await proc.communicate()
