"""USB block devices endpoint router."""

import time
from typing import Any

from fastapi import APIRouter, Response

from sentinel.api.deps import device_service

router = APIRouter(prefix="/api/devices", tags=["Devices"])


@router.get("")
async def get_connected_devices(response: Response) -> dict[str, Any]:
    """Poll currently connected USB storage hardware with BadUSB telemetry."""
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    devices = device_service.get_connected_devices()
    return {
        "count": len(devices),
        "devices": devices,
        "timestamp": time.time(),
    }
