"""Unit tests for SQLite database schema and cryptographic hash chain (Invariant 10)."""

import sqlite3
from pathlib import Path

import pytest

from sentinel.store.db import get_connection, init_database
from sentinel.store.hashchain import (
    export_head,
    record_event,
    verify_hashchain,
    verify_log_cli,
)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    """Fixture providing initialized SQLite database path."""
    db_file = tmp_path / "sentinel_test.db"
    init_database(db_file)
    return db_file


def test_init_database_creates_all_tables(db_path: Path) -> None:
    """Ensure all required tables from CLAUDE.md Section 12 are created."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {row["name"] for row in cursor.fetchall()}

    expected_tables = {
        "devices",
        "sessions",
        "file_results",
        "agent_runs",
        "hash_cache",
        "events",
        "reviews",
    }
    assert expected_tables.issubset(tables)
    conn.close()


def test_record_and_verify_clean_chain(db_path: Path) -> None:
    """Recording sequential events must produce a valid, verifiable hash chain."""
    # Empty chain is valid
    valid, count, err = verify_hashchain(db_path)
    assert valid is True
    assert count == 0
    assert err is None

    # Record events
    id1, h1 = record_event(db_path, "SESSION_START", {"session_id": "s1", "vid": "0781"})
    id2, h2 = record_event(db_path, "SCAN_COMPLETE", {"session_id": "s1", "files": 12})
    id3, h3 = record_event(db_path, "DECISION", {"session_id": "s1", "action": "ALLOW"})

    assert id1 == 1
    assert id2 == 2
    assert id3 == 3
    assert len(h1) == 64
    assert len(h2) == 64
    assert len(h3) == 64
    assert h1 != h2 != h3

    # Verify chain
    valid, count, err = verify_hashchain(db_path)
    assert valid is True
    assert count == 3
    assert err is None


def test_tampering_payload_fails_verification(db_path: Path) -> None:
    """Tampering with a single payload field must immediately fail verify-log."""
    record_event(db_path, "EVT_1", {"amount": 100})
    record_event(db_path, "EVT_2", {"action": "BLOCK", "reason": "BadUSB"})
    record_event(db_path, "EVT_3", {"amount": 300})

    # Tamper with row 2 payload: change 'BLOCK' to 'ALLOW' directly in SQLite!
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "UPDATE events SET payload_json = '{\"action\":\"ALLOW\",\"reason\":\"Faked\"}' WHERE id = 2;"
    )
    conn.commit()
    conn.close()

    # Verification must detect tamper at event 2
    valid, tampered_id, err = verify_hashchain(db_path)
    assert valid is False
    assert tampered_id == 2
    assert err is not None
    assert "Tamper detected at event id=2" in err


def test_tampering_prev_hash_breaks_chain(db_path: Path) -> None:
    """Tampering with prev_hash link must be caught as broken chain."""
    record_event(db_path, "EVT_A", {"data": "A"})
    record_event(db_path, "EVT_B", {"data": "B"})

    conn = sqlite3.connect(str(db_path))
    fake_prev_hash = "f" * 64
    conn.execute(f"UPDATE events SET prev_hash = '{fake_prev_hash}' WHERE id = 2;")
    conn.commit()
    conn.close()

    valid, broken_id, err = verify_hashchain(db_path)
    assert valid is False
    assert broken_id == 2
    assert err is not None
    assert "Chain broken at event id=2" in err


def test_deleting_row_breaks_chain(db_path: Path) -> None:
    """Deleting any historical event breaks the cryptographic link of subsequent events."""
    record_event(db_path, "E1", {"v": 1})
    record_event(db_path, "E2", {"v": 2})
    record_event(db_path, "E3", {"v": 3})

    # Delete event 2
    conn = sqlite3.connect(str(db_path))
    conn.execute("DELETE FROM events WHERE id = 2;")
    conn.commit()
    conn.close()

    # Event 3's prev_hash will point to event 2's hash, but previous row is event 1!
    valid, broken_id, err = verify_hashchain(db_path)
    assert valid is False
    assert broken_id == 3
    assert err is not None
    assert "Chain broken at event id=3" in err


def test_verify_log_cli_exit_codes(db_path: Path) -> None:
    """verify_log_cli must return 0 on intact chain, 1 on tampered chain."""
    record_event(db_path, "INIT", {"status": "ok"})
    exit_code_clean = verify_log_cli(["--db", str(db_path)])
    assert exit_code_clean == 0

    # Tamper with event
    conn = sqlite3.connect(str(db_path))
    conn.execute("UPDATE events SET this_hash = '1234567890abcdef' WHERE id = 1;")
    conn.commit()
    conn.close()

    exit_code_tampered = verify_log_cli(["--db", str(db_path)])
    assert exit_code_tampered == 1


def test_truncating_tail_undetected_without_external_anchor(db_path: Path) -> None:
    """Security verification: deleting N tail events CANNOT be detected without an external anchor.

    Because events 1..3 form an internally valid sub-chain, an attacker who truncates
    the most recent events (e.g. to hide a recent incident) passes internal verification.
    """
    for i in range(1, 6):
        record_event(db_path, f"EVENT_{i}", {"seq": i})

    # Attacker truncates events 4 and 5
    conn = sqlite3.connect(str(db_path))
    conn.execute("DELETE FROM events WHERE id >= 4;")
    conn.commit()
    conn.close()

    # Internal verification passes (demonstrating need for external anchor)
    valid_internal, count, err = verify_hashchain(db_path)
    assert valid_internal is True
    assert count == 3
    assert err is None


def test_truncating_tail_detected_with_external_anchor(db_path: Path) -> None:
    """When an external anchor is provided, tail truncation is immediately detected."""
    for i in range(1, 6):
        record_event(db_path, f"EVENT_{i}", {"seq": i})

    # Legitimate anchor exported earlier to external server/gateway
    anchor = export_head(db_path)
    assert anchor[0] == 5

    # Attacker truncates events 4 and 5
    conn = sqlite3.connect(str(db_path))
    conn.execute("DELETE FROM events WHERE id >= 4;")
    conn.commit()
    conn.close()

    # Verification WITH anchor fails and flags truncation!
    valid_anchored, count_detected, err = verify_hashchain(db_path, expected_head=anchor)
    assert valid_anchored is False
    assert count_detected == 3
    assert err is not None
    assert "Tail truncation detected" in err
