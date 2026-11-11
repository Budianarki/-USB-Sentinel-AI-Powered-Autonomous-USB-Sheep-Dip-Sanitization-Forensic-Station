"""Forensics Inspection Service for USB Sentinel Station."""

import logging
from pathlib import Path
from typing import Any

from sentinel.ui.forensics import get_file_forensics

logger = logging.getLogger(__name__)


class ForensicsService:
    """Provides deep binary hex dumping, block-by-block entropy analysis, and string extraction."""

    @staticmethod
    def inspect_file(file_path: Path) -> dict[str, Any]:
        if not file_path.exists() or not file_path.is_file():
            return {
                "error": f"File '{file_path}' does not exist or is not a regular file.",
                "exists": False,
            }
        return get_file_forensics(file_path)

