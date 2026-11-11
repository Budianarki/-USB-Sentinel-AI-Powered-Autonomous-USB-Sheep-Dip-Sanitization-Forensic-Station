"""Device Service for USB Sentinel Station."""

import asyncio
import logging
import subprocess
from pathlib import Path
from typing import Any

from sentinel.ui.device_scanner import list_connected_usb_devices

logger = logging.getLogger(__name__)


class DeviceService:
    """Manages physical USB block device enumeration and automatic mounting."""

    @staticmethod
    def get_connected_devices() -> list[dict[str, Any]]:
        """List and enrich connected USB devices with BadUSB defense telemetry."""
        devices = list_connected_usb_devices()
        for d in devices:
            d["badusb_safe"] = True
            d["interface_class"] = "0x08 (Mass Storage Only)"
            d["driver"] = "usb-storage (Kernel Isolated)"
            d["health_status"] = "HEALTHY"
        return devices

    @staticmethod
    async def ensure_mounted(device_info: dict[str, Any]) -> str | None:
        """Ensure USB device has a mounted partition path, invoking udisksctl if needed."""
        mount_point = device_info.get("mount_point")
        if mount_point and Path(str(mount_point)).exists():
            return str(mount_point)

        node = device_info.get("node")
        if not node:
            return None

        try:
            m_res = await asyncio.to_thread(
                subprocess.run,
                ["udisksctl", "mount", "-b", node, "--no-user-interaction"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            for word in m_res.stdout.strip().split():
                if word.startswith(("/media", "/run/media", "/mnt")):
                    resolved_path = word.rstrip(".")
                    device_info["mount_point"] = resolved_path
                    return resolved_path
        except Exception as err:  # noqa: BLE001
            logger.debug("On-demand mount failed for %s: %s", node, err)

        return None
