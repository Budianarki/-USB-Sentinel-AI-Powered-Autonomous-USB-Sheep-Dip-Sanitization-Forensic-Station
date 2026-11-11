"""Threat Intelligence Service for USB Sentinel.

Manages hash cache status, MalwareBazaar synchronization, and YARA rule catalogs.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

from sentinel.intel.malwarebazaar import MalwareBazaarClient
from sentinel.scan.yara_scanner import DEFAULT_YARA_RULES_PATH, YaraScanner
from sentinel.store.db import db_session

logger = logging.getLogger(__name__)

DEFAULT_AUDIT_DB = Path("sentinel_audit.db")
DEFAULT_SEED_FEED = Path(__file__).parent.parent / "intel" / "threat_feeds" / "usb_malware_hashes.csv"


class IntelService:
    """Manages threat intelligence statistics, synchronization, and feed integrations."""

    @staticmethod
    def get_stats(db_path: Path | str = DEFAULT_AUDIT_DB) -> dict[str, Any]:
        """Get summary statistics of cached threat hashes and compiled YARA rules."""
        db_p = Path(db_path)
        stats: dict[str, Any] = {
            "total_hashes": 0,
            "malicious_hashes": 0,
            "benign_hashes": 0,
            "yara_rules_count": 0,
            "yara_families": [],
            "malwarebazaar_configured": bool(
                os.environ.get("MB_API_KEY") or os.environ.get("MALWAREBAZAAR_API_KEY")
            ),
        }

        # Query database cache
        if db_p.exists():
            try:
                with db_session(db_p) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT status, COUNT(*) as cnt FROM hash_cache GROUP BY status;")
                    rows = cursor.fetchall()
                    for r in rows:
                        st = r["status"]
                        cnt = int(r["cnt"])
                        if st == "bad":
                            stats["malicious_hashes"] = cnt
                        elif st == "good":
                            stats["benign_hashes"] = cnt
                        stats["total_hashes"] += cnt
            except Exception as exc:  # noqa: BLE001
                logger.warning("Error reading hash_cache stats: %s", exc)

        # Query active YARA rules
        try:
            scanner = YaraScanner(rules_path=DEFAULT_YARA_RULES_PATH)
            if scanner.compiled_rules:
                rules_list = list(scanner.compiled_rules)
                stats["yara_rules_count"] = len(rules_list)
                families = set()
                for r in rules_list:
                    fam = r.meta.get("family") or r.meta.get("threat_type")
                    if fam:
                        families.add(fam)
                stats["yara_families"] = sorted(families)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Error inspecting YARA rules: %s", exc)

        return stats

    @staticmethod
    def seed_offline_feed(db_path: Path | str = DEFAULT_AUDIT_DB) -> int:
        """Seed SQLite hash_cache with bundled vx-underground & MalwareBazaar threat hashes."""
        db_p = Path(db_path)
        if not DEFAULT_SEED_FEED.exists() or not db_p.exists():
            return 0

        inserted = 0
        now_ts = str(time.time())
        lines = DEFAULT_SEED_FEED.read_text(encoding="utf-8", errors="ignore").splitlines()

        with db_session(db_p) as conn:
            for line in lines:
                cleaned = line.strip()
                if not cleaned or cleaned.startswith("#"):
                    continue
                parts = [p.strip().strip('"') for p in cleaned.split(",")]
                if len(parts) >= 3 and len(parts[0]) == 64:
                    sha256 = parts[0].lower()
                    status = parts[1]
                    family = parts[2]
                    source = f"vx_underground:{family}"
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO hash_cache (sha256, status, source, added_at)
                        VALUES (?, ?, ?, ?);
                        """,
                        (sha256, status, source, now_ts),
                    )
                    inserted += 1

        logger.info("Seeded %d threat hashes into %s", inserted, db_p)
        return inserted

    @staticmethod
    async def sync_malwarebazaar(
        db_path: Path | str = DEFAULT_AUDIT_DB,
        tag: str = "usb",
        limit: int = 100,
        api_key: str | None = None,
    ) -> dict[str, Any]:
        """Fetch latest tagged threat intelligence from MalwareBazaar and persist in hash_cache."""
        db_p = Path(db_path)
        client = MalwareBazaarClient(api_key=api_key)
        samples = await client.fetch_samples_by_tag(tag=tag, limit=limit)

        inserted = 0
        now_ts = str(time.time())
        if samples and db_p.exists():
            with db_session(db_p) as conn:
                for s in samples:
                    if s.sha256_hash and len(s.sha256_hash) == 64:
                        family_label = s.signature or f"tag:{tag}"
                        source = f"malwarebazaar:{family_label}"
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO hash_cache (sha256, status, source, added_at)
                            VALUES (?, 'bad', ?, ?);
                            """,
                            (s.sha256_hash.lower(), source, now_ts),
                        )
                        inserted += 1

        # Also ensure bundled feed is seeded
        seeded = IntelService.seed_offline_feed(db_p)

        stats = IntelService.get_stats(db_p)
        return {
            "success": True,
            "samples_fetched": len(samples),
            "hashes_inserted": inserted + seeded,
            "current_stats": stats,
        }
