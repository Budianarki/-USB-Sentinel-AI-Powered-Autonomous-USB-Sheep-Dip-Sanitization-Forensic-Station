"""API Router aggregator for USB Sentinel Station."""

from fastapi import APIRouter

from sentinel.api.certificate import router as certificate_router
from sentinel.api.clean import router as clean_router
from sentinel.api.devices import router as devices_router
from sentinel.api.forensics import router as forensics_router
from sentinel.api.intel import router as intel_router
from sentinel.api.scan import router as scan_router
from sentinel.api.settings import router as settings_router

api_router = APIRouter()
api_router.include_router(devices_router)
api_router.include_router(scan_router)
api_router.include_router(clean_router)
api_router.include_router(forensics_router)
api_router.include_router(certificate_router)
api_router.include_router(settings_router)
api_router.include_router(intel_router)

__all__ = ["api_router"]
