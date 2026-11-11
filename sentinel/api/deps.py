"""Dependency injection and shared singletons for Sentinel API."""

from pathlib import Path

from sentinel.services import (
    AISettingsService,
    CertificateService,
    DeviceService,
    DisinfectionService,
    ForensicsService,
    ScanService,
)
from sentinel.store.db import init_database

DEFAULT_DB_PATH = Path("sentinel_audit.db")
init_database(DEFAULT_DB_PATH)

# Shared Service singletons
device_service = DeviceService()
scan_service = ScanService(DEFAULT_DB_PATH)
disinfection_service = DisinfectionService(DEFAULT_DB_PATH)
forensics_service = ForensicsService()
certificate_service = CertificateService(DEFAULT_DB_PATH)
ai_settings_service = AISettingsService()
