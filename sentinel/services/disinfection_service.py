"""Disinfection and Quarantine Vault Service for USB Sentinel Station."""

import logging
from pathlib import Path
from typing import Any

from sentinel.ui.cleaner import restore_quarantined_files, sanitize_flashdisk

logger = logging.getLogger(__name__)


class DisinfectionService:
    """Manages file quarantine, disinfection, and restoration on USB flashdisks."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def clean_flashdisk(
        self,
        mount_point: Path,
        dangerous_files: list[str],
        action: str = "quarantine",
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute disinfection on mount point, isolating threats to .sentinel_quarantine/."""
        return sanitize_flashdisk(
            mount_point=mount_point,
            dangerous_file_names=dangerous_files,
            action=action,
            db_path=self.db_path,
            session_id=session_id,
        )

    def restore_quarantine(self, mount_point: Path) -> dict[str, Any]:
        """Restore quarantined files back to active filesystem."""
        return restore_quarantined_files(mount_point)

