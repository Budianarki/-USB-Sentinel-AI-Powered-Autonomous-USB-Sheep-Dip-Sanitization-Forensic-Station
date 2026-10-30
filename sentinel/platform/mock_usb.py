"""Mock USB source implementation for development and testing on PC/Laptop."""

import asyncio
import time
from collections.abc import AsyncIterator
from pathlib import Path

from sentinel.platform.base import (
    MountResult,
    UsbDeviceDescriptor,
    UsbEvent,
    UsbSource,
)


class MockUsbSource(UsbSource):
    """Mock implementation of UsbSource that simulates USB devices using directories or queue."""

    def __init__(self, default_mount_dir: Path | None = None) -> None:
        self._event_queue: asyncio.Queue[UsbEvent] = asyncio.Queue()
        self._default_mount_dir = default_mount_dir
        self._device_paths: dict[str, Path] = {}
        self.simulate_mount_failure: bool = False
        self.mounted_devices: set[str] = set()

    def inject_connect(
        self,
        device: UsbDeviceDescriptor,
        filesystem_path: Path | None = None,
    ) -> None:
        """Inject a simulated USB insertion event."""
        if filesystem_path:
            self._device_paths[device.device_id] = filesystem_path
        elif self._default_mount_dir:
            self._device_paths[device.device_id] = self._default_mount_dir

        event = UsbEvent(
            event_type="CONNECT",
            device=device,
            timestamp=time.time(),
        )
        self._event_queue.put_nowait(event)

    def inject_disconnect(self, device: UsbDeviceDescriptor) -> None:
        """Inject a simulated USB removal event."""
        event = UsbEvent(
            event_type="DISCONNECT",
            device=device,
            timestamp=time.time(),
        )
        self._event_queue.put_nowait(event)

    async def events(self) -> AsyncIterator[UsbEvent]:
        """Yield injected USB events as they arrive."""
        while True:
            event = await self._event_queue.get()
            yield event
            self._event_queue.task_done()

    async def mount(self, device: UsbDeviceDescriptor) -> MountResult:
        """Simulate mounting the USB partition."""
        if self.simulate_mount_failure:
            return MountResult(
                success=False,
                error_message="Simulated mount failure",
                read_only=True,
            )

        mount_path = self._device_paths.get(device.device_id, self._default_mount_dir)
        if mount_path is None:
            # If no path specified, use a default fallback
            mount_path = Path("/tmp/mock_usb")

        self.mounted_devices.add(device.device_id)
        return MountResult(
            success=True,
            mount_point=mount_path,
            read_only=True,
        )

    async def unmount(self, device: UsbDeviceDescriptor) -> None:
        """Simulate unmounting the USB partition."""
        self.mounted_devices.discard(device.device_id)
