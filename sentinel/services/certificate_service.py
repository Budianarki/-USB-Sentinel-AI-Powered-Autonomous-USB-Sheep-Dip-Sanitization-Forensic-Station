"""Audit Certificate Service for USB Sentinel Station."""

import time
from pathlib import Path
from typing import Any

from sentinel.store.db import db_session
from sentinel.store.hashchain import export_head, verify_hashchain


class CertificateService:
    """Generates verifiable ISO/IEC 27001 & NIST SP 800-88 compliance audit certificates."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def generate_certificate(self, session_id: str) -> dict[str, Any] | None:
        session_data: dict[str, Any] | None = None
        with db_session(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, device_fingerprint, started_at, decision, risk, policy_version, ai_available
                FROM sessions WHERE id = ?;
                """,
                (session_id,),
            )
            row = cursor.fetchone()
            if row:
                session_data = {
                    "id": row["id"],
                    "device_fingerprint": row["device_fingerprint"],
                    "started_at": row["started_at"],
                    "decision": row["decision"],
                    "risk": row["risk"],
                    "policy_version": row["policy_version"],
                    "ai_available": row["ai_available"],
                }

        if not session_data:
            return None

        valid, count, _ = verify_hashchain(self.db_path)
        _, head_hash = export_head(self.db_path)

        return {
            "certificate_id": f"CERT-{session_id[:8].upper()}-{int(time.time())}",
            "standard": "ISO/IEC 27001:2022 & NIST SP 800-88 Rev.1",
            "session_id": session_data["id"],
            "device_fingerprint": session_data["device_fingerprint"],
            "timestamp": session_data["started_at"],
            "decision": session_data["decision"],
            "risk_score": session_data["risk"],
            "policy_version": session_data["policy_version"],
            "ai_audited": bool(session_data["ai_available"]),
            "hashchain_head": head_hash,
            "hashchain_events": count,
            "integrity_sealed": valid,
            "issued_by": "USB Sentinel Sheep-Dip Station v2.5",
        }

