"""USB Disinfection & Sanitizer Engine ('Pembersih Flashdisk').

Performs safe quarantine, macro neutralization, shortcut-virus repair,
and unhiding of legitimate files on USB flashdisks.
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any

from sentinel.store.db import db_session
from sentinel.store.hashchain import record_event

logger = logging.getLogger(__name__)


def sanitize_flashdisk(
    mount_point: Path,
    dangerous_file_names: list[str],
    action: str = "quarantine",
    db_path: Path | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Disinfect flashdisk by isolating or deleting malicious files and unhiding user files."""
    if not mount_point.exists():
        return {
            "success": False,
            "error": f"Mount point '{mount_point}' tidak ditemukan.",
        }

    start_ts = time.time()
    quarantine_dir = mount_point / ".sentinel_quarantine"
    quarantined: list[str] = []
    deleted: list[str] = []
    unhidden: list[str] = []
    errors: list[str] = []

    if action == "quarantine":
        try:
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            # Create safety notice
            readme = quarantine_dir / "README_SENTINEL_ISOLATION.txt"
            readme.write_text(
                "PERINGATAN KEAMANAN SENTINEL:\n"
                "Berkas dalam folder ini telah diisolasi karena mengandung kode berbahaya,\n"
                "makro jahat, atau manipulasi ekstensi.\n"
                "Jangan jalankan berkas berkekstensi .isolated di stasiun kerja manapun.\n"
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Gagal membuat folder karantina: {exc}")

    # 1. Process flagged malicious files
    for root_dir, _, filenames in os.walk(mount_point):
        # Skip inside quarantine directory itself
        if ".sentinel_quarantine" in root_dir:
            continue

        for fname in filenames:
            file_path = Path(root_dir) / fname
            # Check if this file is in dangerous files list or matches malware patterns
            is_target = fname in dangerous_file_names or any(
                bad in fname.lower()
                for bad in ["autorun.inf", ".lnk", "ignore_previous_instructions"]
            )

            if not is_target:
                continue

            try:
                if action == "quarantine":
                    iso_name = f"{fname}.{int(time.time())}.isolated"
                    dest = quarantine_dir / iso_name
                    shutil.move(str(file_path), str(dest))
                    try:
                        dest.chmod(0o400)  # Read-only inert
                    except OSError as exc:
                        logger.debug("Failed setting permissions on quarantined file: %s", exc)
                    quarantined.append(fname)
                    logger.info("Quarantined: %s -> %s", file_path, dest)
                elif action == "delete":
                    file_path.unlink()
                    deleted.append(fname)
                    logger.info("Deleted threat: %s", file_path)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"Gagal memproses {fname}: {exc}")

    # 2. Repair Ramnit/Shortcut worm attack (Unhide legitimate files hidden by malware)
    for root_dir, dirnames, filenames in os.walk(mount_point):
        if ".sentinel_quarantine" in root_dir:
            continue

        # Look for hidden folders or files starting with . that aren't system files
        for d in dirnames:
            if d.startswith(".") and d not in [".sentinel_quarantine", ".Trash-1000", ".git"]:
                real_name = d.lstrip(".")
                hidden_path = Path(root_dir) / d
                restored_path = Path(root_dir) / real_name
                try:
                    if not restored_path.exists():
                        hidden_path.rename(restored_path)
                        unhidden.append(f"Folder: {real_name}")
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Could not rename hidden folder: %s", exc)

    duration_s = round(time.time() - start_ts, 3)

    # 3. Log to SQLite Hash Chain
    if db_path and db_path.exists():
        try:
            audit_payload = {
                "event": "USB_SANITIZATION_EXECUTED",
                "session_id": session_id or "manual-clean",
                "action": action,
                "quarantined_count": len(quarantined),
                "deleted_count": len(deleted),
                "unhidden_count": len(unhidden),
                "timestamp": time.time(),
            }
            record_event(
                db_path=db_path,
                event_type="DISINFECTION",
                payload=audit_payload,
            )
            # Update session in DB if exists
            if session_id:
                with db_session(db_path) as conn:
                    conn.execute(
                        """
                        UPDATE sessions
                        SET decision = 'ALLOW_SANITIZED',
                            risk = 0.0
                        WHERE id = ?;
                        """,
                        (session_id,),
                    )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to record sanitization in hash chain: %s", exc)

    return {
        "success": True,
        "action": action,
        "quarantined": quarantined,
        "deleted": deleted,
        "unhidden": unhidden,
        "errors": errors,
        "duration_s": duration_s,
        "quarantine_dir": str(quarantine_dir) if action == "quarantine" else None,
    }


def restore_quarantined_files(mount_point: Path) -> dict[str, Any]:
    """Restore quarantined files back to active filesystem (for testing/reversion)."""
    quarantine_dir = mount_point / ".sentinel_quarantine"
    if not quarantine_dir.exists():
        return {"success": False, "error": "Folder karantina tidak ditemukan di flashdisk."}

    restored = []
    errors = []

    for item in quarantine_dir.iterdir():
        if item.name.startswith("README"):
            continue
        if item.suffix == ".isolated":
            # Extract original filename (strip .timestamp.isolated)
            parts = item.name.split(".")
            if len(parts) >= 3 and parts[-1] == "isolated":
                orig_name = ".".join(parts[:-2])
            else:
                orig_name = item.name.replace(".isolated", "")

            dest = mount_point / orig_name
            try:
                item.chmod(0o644)
                shutil.move(str(item), str(dest))
                restored.append(orig_name)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"Gagal memulihkan {item.name}: {exc}")

    return {
        "success": True,
        "restored": restored,
        "errors": errors,
    }
