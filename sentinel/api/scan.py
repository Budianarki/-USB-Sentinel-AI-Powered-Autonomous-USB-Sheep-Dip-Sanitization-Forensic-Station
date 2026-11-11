"""Scanning lifecycle endpoint router."""

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from sentinel.api.deps import device_service, scan_service

router = APIRouter(prefix="/api/scan", tags=["Scanning"])


class ScanRequest(BaseModel):
    device_node: str | None = None
    target_subpath: str | None = None


@router.post("")
async def trigger_live_scan(req: ScanRequest) -> dict[str, Any]:
    """Execute live Sentinel inspection with multi-agent AI triage on selected USB device."""
    devices = device_service.get_connected_devices()
    if not devices:
        raise HTTPException(
            status_code=400,
            detail="0 perangkat USB terdeteksi! Silakan colokkan flashdisk terlebih dahulu.",
        )

    target_device_info = devices[0]
    if req.device_node:
        matched = [d for d in devices if d["node"] == req.device_node]
        if matched:
            target_device_info = matched[0]

    mount_point_str = await device_service.ensure_mounted(target_device_info)
    if not mount_point_str or not Path(mount_point_str).exists():
        raise HTTPException(
            status_code=400,
            detail=f"Perangkat {target_device_info['node']} belum memiliki mount point aktif di sistem.",
        )

    scan_target_path = Path(mount_point_str)
    if req.target_subpath:
        sub = scan_target_path / req.target_subpath.lstrip("/")
        if sub.exists():
            scan_target_path = sub

    return await scan_service.execute_scan(
        target_device_info=target_device_info,
        scan_target_path=scan_target_path,
    )
