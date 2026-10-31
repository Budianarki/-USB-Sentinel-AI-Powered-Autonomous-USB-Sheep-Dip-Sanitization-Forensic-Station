"""Telegram notification and human review callback handler (Phase 2A).

Features:
- Reads bot token and chat_id from environment variables (configurable names).
- Pluggable transport layer (MockTelegramTransport for testing, UrllibTelegramTransport for prod).
- Sends SAFE summaries only: session_id, action, risk, hash/fingerprint, reasons. NEVER file contents.
- Inline keyboard buttons [Setujui] / [Tolak] for HUMAN_REVIEW sessions.
- Callback validation:
  * Only whitelisted chat_ids are permitted.
  * Invariant: Approve can NEVER override a BLOCK decision from guard or antivirus.
  * Successful review records an entry in the 'reviews' table and an event in the cryptographic hash chain.
- Periodic and post-session hash chain anchoring (export_head()).
- Complete fail-safe: notification transport errors are logged and NEVER alter station decisions.
"""

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Protocol

from sentinel.policy.schemas import Decision
from sentinel.store.db import db_session
from sentinel.store.hashchain import record_event
from sentinel.util.config import TelegramConfig

logger = logging.getLogger(__name__)


class TelegramTransport(Protocol):
    """Protocol for sending HTTP requests to the Telegram Bot API."""

    def send_message(
        self,
        token: str,
        chat_id: str,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send a message to a chat, optionally with inline keyboard markup."""
        ...


class UrllibTelegramTransport:
    """Production Telegram transport using standard library urllib."""

    def __init__(self, timeout_s: float = 10.0) -> None:
        self.timeout_s = timeout_s

    def send_message(
        self,
        token: str,
        chat_id: str,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
        }
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout_s) as response:
            resp_body = response.read().decode("utf-8")
            return json.loads(resp_body)  # type: ignore[no-any-return]


class MockTelegramTransport:
    """In-memory mock transport for testing without network access."""

    def __init__(self, simulate_failure: bool = False) -> None:
        self.sent_messages: list[dict[str, Any]] = []
        self.simulate_failure = simulate_failure

    def send_message(
        self,
        token: str,
        chat_id: str,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self.simulate_failure:
            raise urllib.error.URLError("Simulated Telegram connection failure")

        msg = {
            "token": token,
            "chat_id": chat_id,
            "text": text,
            "reply_markup": reply_markup,
            "timestamp": time.time(),
        }
        self.sent_messages.append(msg)
        return {"ok": True, "result": {"message_id": len(self.sent_messages)}}


class TelegramNotifier:
    """Telegram alert and operator review integration for USB Sentinel."""

    def __init__(
        self,
        config: TelegramConfig | None = None,
        token: str | None = None,
        chat_id: str | None = None,
        allowed_chat_ids: list[str] | None = None,
        transport: TelegramTransport | None = None,
    ) -> None:
        self.config = config or TelegramConfig()
        # Resolve token and primary chat_id from env if not explicitly provided
        self.token = token or os.environ.get(self.config.token_env, "")
        self.chat_id = chat_id or os.environ.get(self.config.chat_id_env, "")

        # Allowlist of chat_ids authorized to perform reviews
        raw_allowed = allowed_chat_ids or self.config.allowed_chat_ids
        self.allowed_chat_ids = set(raw_allowed)
        if self.chat_id:
            self.allowed_chat_ids.add(self.chat_id)

        self.transport: TelegramTransport = transport or UrllibTelegramTransport()

    def format_summary_message(
        self,
        session_id: str,
        decision: Decision,
        device_fingerprint: str = "",
    ) -> str:
        """Format a safe session summary strictly omitting file contents."""
        reasons = decision.deterministic_reasons + decision.ai_reasons
        reasons_bullet = "\n".join(f"- {r}" for r in reasons) if reasons else "- None"

        fp_display = device_fingerprint[:16] if device_fingerprint else "UNKNOWN"
        return (
            f"*🛡️ [USB SENTINEL NOTIFIKASI]*\n"
            f"*Sesi ID:* `{session_id}`\n"
            f"*Keputusan:* `{decision.action}` (Risiko: {decision.risk:.2f})\n"
            f"*Fingerprint Perangkat:* `{fp_display}`\n"
            f"*Alasan:*\n{reasons_bullet}\n\n"
            f"_Catatan: Konten file tidak pernah dikirimkan ke Telegram demi kerahasiaan._"
        )

    def notify_session(
        self,
        session_id: str,
        decision: Decision,
        device_fingerprint: str = "",
    ) -> bool:
        """Send session decision summary to Telegram.

        Fail-safe: errors are logged and NEVER affect station operation or decision.
        """
        if not self.config.enabled and not os.environ.get(self.config.token_env):
            logger.debug("Telegram notification disabled; skipping.")
            return False

        if not self.token or not self.chat_id:
            logger.warning("Telegram token or chat_id missing; cannot send notification.")
            return False

        text = self.format_summary_message(session_id, decision, device_fingerprint)
        reply_markup: dict[str, Any] | None = None

        if decision.action == "HUMAN_REVIEW":
            # Provide inline keyboard buttons for human review
            reply_markup = {
                "inline_keyboard": [
                    [
                        {
                            "text": "✅ Setujui (Approve)",
                            "callback_data": f"approve:{session_id}",
                        },
                        {
                            "text": "❌ Tolak (Reject)",
                            "callback_data": f"reject:{session_id}",
                        },
                    ]
                ]
            }

        try:
            self.transport.send_message(
                token=self.token,
                chat_id=self.chat_id,
                text=text,
                reply_markup=reply_markup,
            )
            return True
        except Exception as e:  # noqa: BLE001
            # Invariant: Transport failure MUST NEVER alter decision
            logger.error("Failed to deliver Telegram notification (fail-safe preserved): %s", e)
            return False

    def send_hashchain_anchor(self, count: int, head_hash: str) -> bool:
        """Broadcast current cryptographic hash chain head state (external anchoring)."""
        if not self.token or not self.chat_id:
            return False

        text = (
            f"*⚓ [USB SENTINEL HASH CHAIN ANCHOR]*\n"
            f"*Total Events:* `{count}`\n"
            f"*Head Hash (SHA-256):*\n`{head_hash}`\n\n"
            f"_Jangkar eksternal untuk deteksi pemotongan log (tail-truncation attack)._"
        )
        try:
            self.transport.send_message(
                token=self.token,
                chat_id=self.chat_id,
                text=text,
            )
            return True
        except Exception as e:  # noqa: BLE001
            logger.error("Failed to send hash chain anchor to Telegram: %s", e)
            return False

    def handle_callback(
        self,
        chat_id: str | int,
        callback_data: str,
        current_session_decision: str,
        db_path: Path | str,
        reviewer_name: str = "telegram_operator",
        note: str = "",
    ) -> tuple[bool, str]:
        """Handle inline button callback from Telegram.

        Security constraints enforced:
        1. chat_id must belong to allowed_chat_ids.
        2. Approve can NEVER override a BLOCK decision from guard or AV.
        3. Approve is only permitted when current decision is 'HUMAN_REVIEW'.
        4. Decision is recorded in 'reviews' table and hashed into audit chain.
        """
        str_chat_id = str(chat_id)
        if str_chat_id not in self.allowed_chat_ids:
            msg = f"Unauthorized review attempt from chat_id {str_chat_id}"
            logger.warning(msg)
            return False, "Ditolak: chat_id tidak terdaftar dalam allowlist operator."

        if ":" not in callback_data:
            return False, "Format callback tidak valid."

        action_cmd, session_id = callback_data.split(":", 1)
        action_cmd = action_cmd.strip().lower()

        if action_cmd not in ("approve", "reject"):
            return False, f"Aksi tidak dikenal: {action_cmd}"

        # Invariant: BLOCK is final and immutable, can NEVER be overridden
        if current_session_decision == "BLOCK":
            msg = "Keputusan BLOCK dari hardware guard atau antivirus tidak pernah bisa ditimpa!"
            logger.error(
                "Rejected review attempt on BLOCK session %s by %s", session_id, str_chat_id
            )
            return False, msg

        # Approve is only valid for HUMAN_REVIEW sessions
        if action_cmd == "approve" and current_session_decision != "HUMAN_REVIEW":
            return False, f"Hanya sesi HUMAN_REVIEW yang dapat disetujui (status saat ini: {current_session_decision})."

        review_action = "APPROVE" if action_cmd == "approve" else "REJECT"
        review_id = str(uuid.uuid4())
        now_ts = time.time()

        # 1. Record review in SQLite reviews table
        with db_session(db_path) as conn:
            conn.execute(
                """
                INSERT INTO reviews (id, session_id, reviewer, action, note, ts)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (
                    review_id,
                    session_id,
                    f"{reviewer_name} (chat:{str_chat_id})",
                    review_action,
                    note or f"Callback via Telegram {action_cmd}",
                    now_ts,
                ),
            )

        # 2. Record immutable audit event into hash chain
        event_payload = {
            "review_id": review_id,
            "session_id": session_id,
            "reviewer": f"{reviewer_name} (chat:{str_chat_id})",
            "action": review_action,
            "prior_decision": current_session_decision,
            "note": note,
        }
        record_event(db_path, "HUMAN_REVIEW_DECISION", event_payload, ts=now_ts)

        logger.info(
            "Session %s reviewed successfully: action=%s by %s",
            session_id,
            review_action,
            str_chat_id,
        )
        return True, f"Sesi {session_id} berhasil di-{review_action}."
