"""Binary Forensics endpoint router."""

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from sentinel.api.deps import forensics_service

router = APIRouter(prefix="/api/forensics", tags=["Forensics"])


@router.get("")
async def get_forensic_details(path: str = Query(...)) -> dict[str, Any]:
    """Retrieve deep hex dump, Shannon entropy blocks, and extracted strings."""
    file_p = Path(path)
    res = forensics_service.inspect_file(file_p)
    if not res.get("exists", True):
        raise HTTPException(status_code=404, detail="File tidak ditemukan.")
    return res
