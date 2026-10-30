"""Tamper-evident audit log using cryptographic hash chain (Invariant 10).

Formula: this_hash = SHA256(prev_hash || canonical_json(event))
Genesis prev_hash: "0" * 64
"""

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

from sentinel.store.db import db_session

GENESIS_PREV_HASH = "0" * 64


def canonical_json(data: Any) -> str:
    """Serialize data to deterministic, canonical JSON."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def compute_event_hash(prev_hash: str, canonical_payload: str) -> str:
    """Calculate SHA256(prev_hash || canonical_json(payload))."""
    combined = f"{prev_hash}{canonical_payload}".encode()
    return hashlib.sha256(combined).hexdigest()


def record_event(
    db_path: Path | str,
    event_type: str,
    payload: dict[str, Any],
    ts: float | None = None,
) -> tuple[int, str]:
    """Append a new event to the cryptographic hash chain.

    Thread-safe and process-safe via SQLite BEGIN IMMEDIATE.
    Returns (event_id, this_hash).
    """
    event_ts = ts if ts is not None else time.time()
    payload_str = canonical_json(payload)

    with db_session(db_path) as conn:
        # Fetch the most recent event hash
        cursor = conn.cursor()
        cursor.execute("SELECT id, this_hash FROM events ORDER BY id DESC LIMIT 1;")
        last_row = cursor.fetchone()

        if last_row is None:
            prev_hash = GENESIS_PREV_HASH
        else:
            prev_hash = last_row["this_hash"]

        this_hash = compute_event_hash(prev_hash, payload_str)

        cursor.execute(
            """
            INSERT INTO events (ts, type, payload_json, prev_hash, this_hash)
            VALUES (?, ?, ?, ?, ?);
            """,
            (event_ts, event_type, payload_str, prev_hash, this_hash),
        )
        event_id = int(cursor.lastrowid or 0)
        return event_id, this_hash


def export_head(db_path: Path | str) -> tuple[int, str]:
    """Export the current head state of the hash chain (count, head_hash).

    Used for periodic off-device anchoring (e.g. sent to external syslog/SIEM/gateway)
    to protect against undetected tail-truncation attacks.
    """
    db_file = Path(db_path)
    if not db_file.exists():
        return 0, GENESIS_PREV_HASH

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, this_hash FROM events ORDER BY id DESC LIMIT 1;")
        row = cursor.fetchone()
        if row is None:
            return 0, GENESIS_PREV_HASH
        cursor.execute("SELECT COUNT(*) AS total FROM events;")
        count_row = cursor.fetchone()
        count = int(count_row["total"]) if count_row else 0
        return count, row["this_hash"]


def verify_hashchain(
    db_path: Path | str,
    expected_head: tuple[int, str] | None = None,
) -> tuple[bool, int, str | None]:
    """Verify integrity of event log chain.

    Honest Security Note:
    Without an external anchor (expected_head), deleting the N most recent events
    (tail truncation) cannot be detected from internal cryptographic links alone,
    because the remaining prefix forms a valid sub-chain. Passing an expected_head
    (exported earlier off-device) guarantees detection of truncation.

    Returns:
        (is_valid: bool, verified_count: int, error_message: str | None)
    """
    db_file = Path(db_path)
    if not db_file.exists():
        return False, 0, f"Database file not found: {db_path}"

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, ts, type, payload_json, prev_hash, this_hash FROM events ORDER BY id ASC;"
        )
        rows = cursor.fetchall()

        if not rows:
            if expected_head and expected_head[0] > 0:
                return (
                    False,
                    0,
                    f"Tail truncation detected: database has 0 events, but external anchor expected {expected_head[0]} events",
                )
            return True, 0, None

        expected_prev_hash = GENESIS_PREV_HASH
        for row in rows:
            event_id = row["id"]
            actual_prev_hash = row["prev_hash"]
            actual_this_hash = row["this_hash"]
            payload_str = row["payload_json"]

            # 1. Verify link to previous event
            if actual_prev_hash != expected_prev_hash:
                return (
                    False,
                    event_id,
                    (
                        f"Chain broken at event id={event_id}: expected prev_hash '{expected_prev_hash[:16]}...', "
                        f"got '{actual_prev_hash[:16]}...'"
                    ),
                )

            # 2. Recalculate hash of current payload
            calculated_this_hash = compute_event_hash(actual_prev_hash, payload_str)
            if calculated_this_hash != actual_this_hash:
                return (
                    False,
                    event_id,
                    (
                        f"Tamper detected at event id={event_id}: calculated hash '{calculated_this_hash[:16]}...', "
                        f"stored hash '{actual_this_hash[:16]}...'"
                    ),
                )

            expected_prev_hash = actual_this_hash

        # 3. Optional external anchor verification against tail truncation
        if expected_head is not None:
            expected_count, expected_hash = expected_head
            if len(rows) < expected_count:
                return (
                    False,
                    len(rows),
                    (
                        f"Tail truncation detected: database has {len(rows)} events, but external anchor "
                        f"expected at least {expected_count} events"
                    ),
                )
            # Find the row at expected_count index
            anchor_row = rows[expected_count - 1]
            if anchor_row["this_hash"] != expected_hash:
                return (
                    False,
                    expected_count,
                    (
                        f"External anchor mismatch at event id={expected_count}: expected '{expected_hash[:16]}...', "
                        f"got '{anchor_row['this_hash'][:16]}...'"
                    ),
                )

        return True, len(rows), None


def verify_log_cli(argv: list[str] | None = None) -> int:
    """CLI entrypoint for verify-log command."""
    parser = argparse.ArgumentParser(
        description="Verify cryptographic integrity of USB Sentinel hash chain event log."
    )
    parser.add_argument(
        "--db",
        type=str,
        default="data/sentinel.db",
        help="Path to SQLite database (default: data/sentinel.db)",
    )
    parser.add_argument(
        "--expected-count",
        type=int,
        default=None,
        help="Optional expected event count from external anchor to detect tail truncation",
    )
    parser.add_argument(
        "--expected-hash",
        type=str,
        default=None,
        help="Optional expected head hash from external anchor",
    )
    args = parser.parse_args(argv)

    db_path = Path(args.db)
    expected_head = None
    if args.expected_count is not None and args.expected_hash is not None:
        expected_head = (args.expected_count, args.expected_hash)

    print(f"[*] Verifying hash chain integrity in: {db_path}...")
    valid, count, err = verify_hashchain(db_path, expected_head=expected_head)

    if valid:
        print(f"[+] SUCCESS: Hash chain intact. {count} events verified without tampering.")
        return 0
    else:
        print(f"[-] FAILED: Hash chain integrity check failed at event {count}!")
        print(f"    Error: {err}")
        return 1


if __name__ == "__main__":
    sys.exit(verify_log_cli())
