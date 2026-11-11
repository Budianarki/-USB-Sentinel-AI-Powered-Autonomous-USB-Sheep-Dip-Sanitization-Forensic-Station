"""Disinfection, quarantine, and restore endpoint router."""

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from sentinel.api.deps import device_service, disinfection_service, scan_service

router = APIRouter(prefix="/api", tags=["Disinfection & Cleaner"])


class CleanRequest(BaseModel):
    device_node: str | None = None
    target_subpath: str | None = None
    action: str = "quarantine"  # 'quarantine' or 'delete'
    dangerous_files: list[str] = []
    session_id: str | None = None


@router.post("/clean")
async def trigger_flashdisk_clean(req: CleanRequest) -> dict[str, Any]:
    """Execute live USB disinfection and quarantine ('Pembersih Flashdisk')."""
    devices = device_service.get_connected_devices()
    if not devices:
        raise HTTPException(
            status_code=400,
            detail="0 perangkat USB terdeteksi. Hubungkan flashdisk untuk membersihkan.",
        )

    target_device = devices[0]
    if req.device_node:
        matched = [d for d in devices if d["node"] == req.device_node]
        if matched:
            target_device = matched[0]

    mount_point = Path(target_device["mount_point"])
    target_scan_dir = mount_point
    if req.target_subpath:
        sub = mount_point / req.target_subpath.lstrip("/")
        if sub.exists():
            target_scan_dir = sub

    # Execute disinfection
    clean_res = disinfection_service.clean_flashdisk(
        mount_point=target_scan_dir,
        dangerous_files=req.dangerous_files,
        action=req.action,
        session_id=req.session_id,
    )

    # Re-scan to verify clean status
    verify_scan = await scan_service.execute_scan(
        target_device_info=target_device,
        scan_target_path=target_scan_dir,
    )

    return {
        "clean_summary": clean_res,
        "re_scan": verify_scan,
    }


@router.post("/restore")
async def trigger_restore_quarantine(req: CleanRequest) -> dict[str, Any]:
    """Restore quarantined files back to active drive."""
    devices = device_service.get_connected_devices()
    if not devices:
        raise HTTPException(status_code=400, detail="Flashdisk tidak ditemukan.")

    mount_point = Path(devices[0]["mount_point"])
    if req.target_subpath:
        sub = mount_point / req.target_subpath.lstrip("/")
        if sub.exists():
            mount_point = sub

    return disinfection_service.restore_quarantine(mount_point)
