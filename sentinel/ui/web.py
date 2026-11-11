"""Interactive Web Dashboard server for USB Sentinel Station (FastAPI + Claymorphism UI).

Provides:
- GET /api/devices: real-time detection of connected USB block devices with BadUSB analysis
- POST /api/scan: execute live inspection pipeline with full AI triage
- POST /api/clean: disinfect and sanitize threats (the 'Pembersih' engine)
- POST /api/restore: restore quarantined files for testing/reversion
- GET /api/forensics: deep hex dump, Shannon entropy curves, and strings
- GET /api/certificate/{session_id}: verifiable forensic audit certificate
- GET /api/settings/ai: inspect and update active AI provider and API keys
- GET /: rich Claymorphism interactive cybersecurity station UI
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from sentinel.api import api_router
from sentinel.api.clean import CleanRequest
from sentinel.api.deps import DEFAULT_DB_PATH
from sentinel.api.scan import ScanRequest
from sentinel.store.db import init_database

logger = logging.getLogger("sentinel.ui.web")

ui_app = FastAPI(
    title="USB Sentinel Sheep-Dip Station",
    version="2.5.0",
    description="Air-Gapped Hardware Inspection, Multi-Agent AI Triage & USB Sanitizer",
)

# Initialize audit SQLite database
init_database(DEFAULT_DB_PATH)

# Path resolutions for templates and static assets
UI_DIR = Path(__file__).parent
STATIC_DIR = UI_DIR / "static"
TEMPLATE_PATH = UI_DIR / "templates" / "index.html"

# Mount static asset directory
if STATIC_DIR.exists():
    ui_app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Mount modular API router aggregator
ui_app.include_router(api_router)


@ui_app.get("/", response_class=HTMLResponse)
async def serve_dashboard() -> HTMLResponse:
    """Serve the complete Claymorphism USB Sentinel station web interface."""
    if TEMPLATE_PATH.exists():
        content = TEMPLATE_PATH.read_text(encoding="utf-8")
        return HTMLResponse(content=content, status_code=200)
    return HTMLResponse(content="<h1>USB Sentinel Template Not Found</h1>", status_code=500)


__all__ = ["DEFAULT_DB_PATH", "CleanRequest", "ScanRequest", "ui_app"]
