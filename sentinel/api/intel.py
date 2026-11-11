"""Threat Intelligence API Router for USB Sentinel."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from sentinel.services.intel_service import IntelService

router = APIRouter(prefix="/api/intel", tags=["Threat Intelligence"])


class IntelSyncRequest(BaseModel):
    tag: str = Field(default="usb", description="Tag to synchronize from MalwareBazaar")
    limit: int = Field(default=100, ge=1, le=500, description="Max samples to query")
    api_key: str | None = Field(default=None, description="Optional MalwareBazaar Auth-Key")


class IntelLookupRequest(BaseModel):
    sha256: str = Field(..., min_length=64, max_length=64, description="SHA-256 hex hash")


@router.get("/stats")
async def get_intel_statistics() -> dict[str, Any]:
    """Get threat intelligence database statistics and YARA catalog."""
    return IntelService.get_stats()


@router.post("/seed")
async def seed_bundled_threat_feeds() -> dict[str, Any]:
    """Seed local cache with bundled offline vx-underground and MalwareBazaar signatures."""
    inserted = IntelService.seed_offline_feed()
    stats = IntelService.get_stats()
    return {
        "success": True,
        "seeded_count": inserted,
        "stats": stats,
    }


@router.post("/sync")
async def sync_threat_intel_endpoint(req: IntelSyncRequest) -> dict[str, Any]:
    """Synchronize latest threat intelligence from MalwareBazaar into local SQLite cache."""
    return await IntelService.sync_malwarebazaar(tag=req.tag, limit=req.limit, api_key=req.api_key)
