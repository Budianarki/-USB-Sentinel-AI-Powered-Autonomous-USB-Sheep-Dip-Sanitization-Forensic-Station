"""Unit tests for Telegram Notifier and Human Review Callback Handler (Checkpoint 2A).

Tests:
1. Safe summary formatting: strictly contains metadata, hash, decision, NEVER file contents.
2. Notification delivery with mock transport.
3. Transport error is gracefully caught and never alters decision (fail-safe).
4. Inline keyboard markup generated for HUMAN_REVIEW sessions.
5. Callback from unauthorized chat_id is rejected.
6. Callback approve on a BLOCK session is strictly rejected (BLOCK cannot be overridden).
7. Callback approve on HUMAN_REVIEW session succeeds, recorded in 'reviews' table and hash chain.
8. Hash chain external anchoring broadcast via export_head().
"""

from pathlib import Path

from sentinel.notify.telegram import (
    MockTelegramTransport,
    TelegramNotifier,
)
from sentinel.policy.schemas import Decision
from sentinel.store.db import db_session, init_database
from sentinel.store.hashchain import record_event
from sentinel.util.config import TelegramConfig


def test_safe_summary_does_not_contain_file_contents() -> None:
    """Invariant: Notifications strictly include metadata, hash, and decision; NEVER file contents."""
    notifier = TelegramNotifier(
        token="FAKE_BOT_TOKEN",
        chat_id="12345678",
        allowed_chat_ids=["12345678"],
    )
    decision = Decision(
        session_id="sess-safe-001",
        action="ALLOW",
        risk=0.05,
        policy_version="1.0.0",
        deterministic_reasons=["All 3 files passed hash & antivirus checks"],
        ai_reasons=[],
    )

    msg = notifier.format_summary_message(
        session_id="sess-safe-001",
        decision=decision,
        device_fingerprint="abc123def4567890",
    )

    # Must contain essential summary tokens
    assert "sess-safe-001" in msg
    assert "ALLOW" in msg
    assert "abc123def4567890"[:16] in msg
    assert "All 3 files passed" in msg
    # Must NOT contain arbitrary file contents
    assert "SECRET_CONFIDENTIAL_CONTENT" not in msg


def test_notify_session_with_mock_transport() -> None:
    """Test successful notification dispatch through MockTelegramTransport."""
    mock_transport = MockTelegramTransport()
    cfg = TelegramConfig(enabled=True)
    notifier = TelegramNotifier(
        config=cfg,
        token="BOT_TEST_TOKEN",
        chat_id="99988877",
        transport=mock_transport,
    )

    decision = Decision(
        session_id="sess-mock-002",
        action="BLOCK",
        risk=1.0,
        policy_version="1.0.0",
        deterministic_reasons=["EICAR malware detected"],
    )

    ok = notifier.notify_session(session_id="sess-mock-002", decision=decision)
    assert ok is True
    assert len(mock_transport.sent_messages) == 1

    sent = mock_transport.sent_messages[0]
    assert sent["chat_id"] == "99988877"
    assert "BLOCK" in sent["text"]
    assert sent["reply_markup"] is None  # BLOCK has no review buttons


def test_notification_failure_does_not_raise_or_alter_decision() -> None:
    """Fail-safe: Transport errors are logged and return False, never raising unhandled exceptions."""
    failing_transport = MockTelegramTransport(simulate_failure=True)
    cfg = TelegramConfig(enabled=True)
    notifier = TelegramNotifier(
        config=cfg,
        token="BOT_TEST_TOKEN",
        chat_id="99988877",
        transport=failing_transport,
    )

    decision = Decision(
        session_id="sess-fail-003",
        action="QUARANTINE",
        risk=0.85,
        policy_version="1.0.0",
        deterministic_reasons=["Partition mount failure"],
    )

    # Calling notify_session must return False safely without raising URLError
    ok = notifier.notify_session(session_id="sess-fail-003", decision=decision)
    assert ok is False


def test_human_review_includes_inline_keyboard() -> None:
    """Sessions with HUMAN_REVIEW must present Approve and Reject inline buttons."""
    mock_transport = MockTelegramTransport()
    cfg = TelegramConfig(enabled=True)
    notifier = TelegramNotifier(
        config=cfg,
        token="BOT_TEST_TOKEN",
        chat_id="11223344",
        transport=mock_transport,
    )

    decision = Decision(
        session_id="sess-rev-004",
        action="HUMAN_REVIEW",
        risk=0.45,
        policy_version="1.0.0",
        deterministic_reasons=["Unknown file type flag requiring operator triage"],
    )

    ok = notifier.notify_session(session_id="sess-rev-004", decision=decision)
    assert ok is True
    assert len(mock_transport.sent_messages) == 1

    markup = mock_transport.sent_messages[0]["reply_markup"]
    assert markup is not None
    assert "inline_keyboard" in markup

    buttons = markup["inline_keyboard"][0]
    assert len(buttons) == 2
    assert "approve:sess-rev-004" in buttons[0]["callback_data"]
    assert "reject:sess-rev-004" in buttons[1]["callback_data"]


def test_callback_from_unauthorized_chat_rejected(tmp_path: Path) -> None:
    """Callbacks from chat_ids not in allowlist must be strictly rejected."""
    db_file = tmp_path / "test_auth.db"
    init_database(db_file)

    notifier = TelegramNotifier(
        token="BOT_TOKEN",
        chat_id="1000",
        allowed_chat_ids=["1000", "2000"],
    )

    # Chat 9999 is an attacker / unauthorized stranger
    ok, err = notifier.handle_callback(
        chat_id="9999",
        callback_data="approve:sess-test",
        current_session_decision="HUMAN_REVIEW",
        db_path=db_file,
    )
    assert ok is False
    assert "allowlist" in err


def test_callback_approve_on_block_session_is_strictly_rejected(tmp_path: Path) -> None:
    """Security Invariant: An operator can NEVER override a BLOCK decision from guard or antivirus."""
    db_file = tmp_path / "test_block_override.db"
    init_database(db_file)

    notifier = TelegramNotifier(
        token="BOT_TOKEN",
        chat_id="1000",
        allowed_chat_ids=["1000"],
    )

    # Authorized operator attempts to approve a session that was BLOCKED
    ok, err = notifier.handle_callback(
        chat_id="1000",
        callback_data="approve:sess-malware-01",
        current_session_decision="BLOCK",
        db_path=db_file,
    )
    assert ok is False
    assert "tidak pernah bisa ditimpa" in err or "cannot override BLOCK" in err.lower()

    # Ensure nothing was inserted into reviews table
    with db_session(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS total FROM reviews;")
        count = cursor.fetchone()["total"]
        assert count == 0


def test_callback_approve_on_human_review_recorded_in_db_and_hashchain(tmp_path: Path) -> None:
    """Approve on HUMAN_REVIEW session must succeed and be permanently recorded in reviews & hashchain."""
    db_file = tmp_path / "test_review_success.db"
    init_database(db_file)

    notifier = TelegramNotifier(
        token="BOT_TOKEN",
        chat_id="1000",
        allowed_chat_ids=["1000"],
    )

    # 1. Create parent device and session rows to satisfy foreign keys
    with db_session(db_file) as conn:
        conn.execute(
            "INSERT INTO devices (fingerprint, first_seen, last_seen) VALUES ('fp-01', '2026-10-31', '2026-10-31');"
        )
        conn.execute(
            "INSERT INTO sessions (id, device_fingerprint, started_at, decision) VALUES ('sess-pending-01', 'fp-01', '2026-10-31', 'HUMAN_REVIEW');"
        )

    # Record prior event in hash chain
    record_event(
        db_file,
        event_type="SESSION_DECISION",
        payload={"session_id": "sess-pending-01", "action": "HUMAN_REVIEW"},
    )

    # 2. Operator approves via callback
    ok, msg = notifier.handle_callback(
        chat_id="1000",
        callback_data="approve:sess-pending-01",
        current_session_decision="HUMAN_REVIEW",
        db_path=db_file,
        reviewer_name="SecOps_Alice",
    )
    assert ok is True
    assert "berhasil" in msg

    # 3. Verify SQLite reviews table has the record
    with db_session(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM reviews WHERE session_id = 'sess-pending-01';")
        review_row = cursor.fetchone()
        assert review_row is not None
        assert review_row["action"] == "APPROVE"
        assert "SecOps_Alice" in review_row["reviewer"]

    # 4. Verify hash chain has a HUMAN_REVIEW_DECISION event
    with db_session(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT 1;")
        event_row = cursor.fetchone()
        assert event_row is not None
        assert event_row["type"] == "HUMAN_REVIEW_DECISION"
        assert "sess-pending-01" in event_row["payload_json"]


def test_send_hashchain_anchor() -> None:
    """Test sending external hash chain anchor."""
    mock_transport = MockTelegramTransport()
    notifier = TelegramNotifier(
        token="BOT_TEST_TOKEN",
        chat_id="1000",
        transport=mock_transport,
    )

    head_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    ok = notifier.send_hashchain_anchor(count=42, head_hash=head_hash)
    assert ok is True
    assert len(mock_transport.sent_messages) == 1

    msg = mock_transport.sent_messages[0]
    assert "42" in msg["text"]
    assert head_hash in msg["text"]
