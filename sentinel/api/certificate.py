"""Forensic Certificate endpoint router."""

from typing import Any

from fastapi import APIRouter, HTTPException

from sentinel.api.deps import certificate_service

router = APIRouter(prefix="/api/certificate", tags=["Certificate"])


@router.get("/{session_id}")
async def get_audit_certificate(session_id: str) -> dict[str, Any]:
    """Generate ISO 27001 / NIST SP 800-88 compliant forensic sanitization certificate."""
    cert = certificate_service.generate_certificate(session_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Sesi audit tidak ditemukan di database.")
    return cert
