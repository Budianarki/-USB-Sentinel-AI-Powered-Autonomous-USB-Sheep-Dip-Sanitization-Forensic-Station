#!/usr/bin/env python3
"""Threat Intelligence Synchronizer for USB Sentinel.

Synchronizes malware hashes and threat metadata from MalwareBazaar (abuse.ch)
and vx-underground offline threat feeds into local SQLite hash_cache for kiosk defense.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time
from pathlib import Path

from sentinel.intel.malwarebazaar import MalwareBazaarClient
from sentinel.store.db import db_session

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sync_threat_intel")

DEFAULT_DB = Path("sentinel_audit.db")
DEFAULT_FEED = Path(__file__).parent.parent / "sentinel" / "intel" / "threat_feeds" / "usb_malware_hashes.csv"


def count_cached_hashes(db_path: Path) -> dict[str, int]:
    """Count cached hashes grouped by status."""
    if not db_path.exists():
        return {"good": 0, "bad": 0, "total": 0}

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT status, COUNT(*) as cnt FROM hash_cache GROUP BY status;")
        rows = cursor.fetchall()
        counts = {r["status"]: r["cnt"] for r in rows}
        counts["total"] = sum(counts.values())
        return counts


def insert_hashes(
    db_path: Path,
    hash_list: list[tuple[str, str, str]],  # (sha256, status, source)
    dry_run: bool = False,
) -> int:
    """Insert or update hashes in SQLite hash_cache table."""
    if dry_run or not hash_list:
        return len(hash_list)

    inserted = 0
    now_ts = str(time.time())
    with db_session(db_path) as conn:
        for sha256, status, source in hash_list:
            clean_hash = sha256.strip().lower()
            if len(clean_hash) == 64:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO hash_cache (sha256, status, source, added_at)
                    VALUES (?, ?, ?, ?);
                    """,
                    (clean_hash, status, source, now_ts),
                )
                inserted += 1
    return inserted


async def sync_online_malwarebazaar(
    db_path: Path,
    tags: list[str],
    include_recent: bool = True,
    recent_limit: int = 500,
    api_key: str | None = None,
    dry_run: bool = False,
) -> int:
    """Fetch live malware threat intelligence from MalwareBazaar API."""
    client = MalwareBazaarClient(api_key=api_key)
    entries_to_insert: list[tuple[str, str, str]] = []

    # 1. Fetch by tags (e.g. usb, worm)
    for tag in tags:
        logger.info("Fetching MalwareBazaar samples tagged '%s'...", tag)
        samples = await client.fetch_samples_by_tag(tag=tag, limit=100)
        logger.info("Found %d samples for tag '%s'", len(samples), tag)
        for s in samples:
            if s.sha256_hash:
                family_label = s.signature or f"tag:{tag}"
                source = f"malwarebazaar:{family_label}"
                entries_to_insert.append((s.sha256_hash, "bad", source))

    # 2. Fetch recent plain text export if requested
    if include_recent:
        logger.info("Fetching MalwareBazaar recent SHA-256 export (limit=%d)...", recent_limit)
        recent_hashes = await client.fetch_recent_sha256_export(limit=recent_limit)
        logger.info("Retrieved %d recent malware hashes", len(recent_hashes))
        for h in recent_hashes:
            entries_to_insert.append((h, "bad", "malwarebazaar:recent_feed"))

    # Deduplicate before insertion
    unique_entries = {e[0]: e for e in entries_to_insert}
    final_list = list(unique_entries.values())

    logger.info("Inserting %d unique malware hashes into %s...", len(final_list), db_path)
    return insert_hashes(db_path, final_list, dry_run=dry_run)


def import_offline_file(db_path: Path, file_path: Path, source_label: str = "vx_underground", dry_run: bool = False) -> int:
    """Import list of hashes from an offline text or CSV feed file."""
    if not file_path.exists():
        logger.error("Import file not found: %s", file_path)
        return 0

    entries: list[tuple[str, str, str]] = []
    lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    for line in lines:
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            continue
        # Split CSV if comma separated
        parts = [p.strip().strip('"') for p in cleaned.split(",")]
        sha_candidate = None
        status_candidate = "bad"
        src = source_label

        if len(parts) >= 3 and len(parts[0]) == 64:
            sha_candidate = parts[0].lower()
            status_candidate = parts[1]
            family = parts[2]
            src = f"{source_label}:{family}"
        else:
            for p in parts:
                if len(p) == 64 and all(c in "0123456789abcdefABCDEF" for c in p):
                    sha_candidate = p.lower()
                    break

        if sha_candidate:
            entries.append((sha_candidate, status_candidate, src))

    logger.info("Parsed %d hashes from %s", len(entries), file_path)
    return insert_hashes(db_path, entries, dry_run=dry_run)


def main() -> None:
    parser = argparse.ArgumentParser(description="USB Sentinel - Threat Intelligence Synchronizer")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="Path to SQLite audit database")
    parser.add_argument("--seed", action="store_true", help="Seed database with bundled vx-underground threat hashes")
    parser.add_argument("--tags", nargs="+", default=["usb", "worm", "lnk"], help="Tags to sync from MalwareBazaar")
    parser.add_argument("--recent", type=int, default=100, help="Number of recent malware hashes to pull (0 to skip)")
    parser.add_argument("--api-key", type=str, default=None, help="MalwareBazaar Auth-Key")
    parser.add_argument("--import-file", type=Path, default=None, help="Import hashes from custom offline text/csv file")
    parser.add_argument("--source-label", type=str, default="vx_underground", help="Source label for offline import")
    parser.add_argument("--dry-run", action="store_true", help="Simulate without writing to database")
    parser.add_argument("--stats-only", action="store_true", help="Print current database cache stats and exit")

    args = parser.parse_args()

    # Initial stats
    initial_stats = count_cached_hashes(args.db)
    print("\n[USB SENTINEL THREAT INTEL STATUS]")
    print(f"Database: {args.db}")
    print(f"Total Hashes Cached: {initial_stats.get('total', 0)}")
    print(f"  - Malicious (bad): {initial_stats.get('bad', 0)}")
    print(f"  - Verified Benign (good): {initial_stats.get('good', 0)}")
    print("--------------------------------------------------\n")

    if args.stats_only:
        sys.exit(0)

    total_synced = 0

    # Bundled seed
    if args.seed:
        logger.info("Seeding database with bundled offline threat feeds (%s)...", DEFAULT_FEED)
        total_synced += import_offline_file(args.db, DEFAULT_FEED, "vx_underground", dry_run=args.dry_run)

    # Custom offline import if requested
    if args.import_file:
        logger.info("Importing offline hash list from %s...", args.import_file)
        total_synced += import_offline_file(args.db, args.import_file, args.source_label, dry_run=args.dry_run)

    # Online sync from MalwareBazaar if not strictly seeding/importing
    if not args.seed and not args.import_file:
        logger.info("Starting online sync from MalwareBazaar (abuse.ch)...")
        total_synced += asyncio.run(
            sync_online_malwarebazaar(
                db_path=args.db,
                tags=args.tags,
                include_recent=args.recent > 0,
                recent_limit=args.recent,
                api_key=args.api_key,
                dry_run=args.dry_run,
            )
        )

    updated_stats = count_cached_hashes(args.db)
    print("\n[SYNC COMPLETED]")
    print(f"Hashes Processed: {total_synced}")
    print(f"Updated Malicious Hashes in DB: {updated_stats.get('bad', 0)} (was {initial_stats.get('bad', 0)})\n")


if __name__ == "__main__":
    main()
