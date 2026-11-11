"""Threat Intelligence Agent client module with local SQLite hash cache and MalwareBazaar integration."""

from __future__ import annotations

import logging
import time
from pathlib import Path

from sentinel.agents.client import GatewayClient
from sentinel.agents.schemas import (
    AgentRequest,
    AgentResponse,
    AgentVerdict,
    FileFeatures,
    SessionContext,
)
from sentinel.intel.malwarebazaar import MalwareBazaarClient
from sentinel.store.db import db_session

logger = logging.getLogger(__name__)


class IntelAgent:
    """Performs hash intelligence lookup with local SQLite cache fallback and MalwareBazaar feeds."""

    def __init__(
        self,
        client: GatewayClient,
        db_path: Path | str | None = None,
        malwarebazaar_client: MalwareBazaarClient | None = None,
        enable_online_intel: bool = True,
    ) -> None:
        self.client = client
        self.db_path = Path(db_path) if db_path else None
        self.mb_client = malwarebazaar_client or MalwareBazaarClient()
        self.enable_online_intel = enable_online_intel

    def _lookup_cache(self, sha256: str) -> tuple[str, str] | None:
        """Lookup SHA256 in local SQLite hash_cache table returning (status, source)."""
        if not self.db_path or not self.db_path.exists():
            return None

        try:
            with db_session(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT status, source FROM hash_cache WHERE sha256 = ?;", (sha256,))
                row = cursor.fetchone()
                if row:
                    return str(row["status"]), str(row["source"])
        except Exception as exc:  # noqa: BLE001
            logger.warning("Error reading hash_cache: %s", exc)

        return None

    def _write_cache(self, sha256: str, status: str, source: str = "gateway_intel") -> None:
        """Record SHA256 intelligence result into hash_cache table."""
        if not self.db_path or not self.db_path.exists():
            return

        try:
            with db_session(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO hash_cache (sha256, status, source, added_at)
                    VALUES (?, ?, ?, ?);
                    """,
                    (sha256, status, source, str(time.time())),
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Error writing to hash_cache: %s", exc)

    async def lookup_hash(
        self,
        features: FileFeatures,
        context: SessionContext | None = None,
    ) -> AgentResponse:
        """Evaluate hash against local cache, MalwareBazaar, or Gateway intel."""
        sha256 = features.sha256

        # 1. Check local hash_cache
        cached_info = self._lookup_cache(sha256)
        if cached_info is not None:
            status_val, source_val = cached_info
            logger.info("Local hash cache hit for %s: %s (source: %s)", sha256[:16], status_val, source_val)
            is_bad = status_val == "bad"
            cached_verdict = AgentVerdict(
                agent="intel_cache",
                file_id=features.file_id,
                risk_score=1.0 if is_bad else 0.0,
                confidence=1.0,
                verdict="malicious" if is_bad else "benign",
                reasons=[f"SHA256 reputation verified from local cache ({source_val}): {status_val}"],
                injection_suspected=False,
            )
            return AgentResponse(
                agent="intel",
                status="success",
                verdict=cached_verdict,
                tokens_in=0,
                tokens_out=0,
            )

        # 2. Query MalwareBazaar threat intelligence if online
        if self.enable_online_intel:
            mb_res = await self.mb_client.lookup_hash(sha256)
            if mb_res.is_malicious:
                sig_label = mb_res.signature or "MalwareSample"
                tags_str = ", ".join(mb_res.tags) if mb_res.tags else "malware"
                src_label = f"malwarebazaar:{sig_label}"
                self._write_cache(sha256, "bad", source=src_label)
                logger.warning(
                    "MalwareBazaar threat detected for %s: %s [%s]",
                    sha256[:16],
                    sig_label,
                    tags_str,
                )
                mb_verdict = AgentVerdict(
                    agent="intel_malwarebazaar",
                    file_id=features.file_id,
                    risk_score=1.0,
                    confidence=1.0,
                    verdict="malicious",
                    reasons=[f"MalwareBazaar verified threat match: {sig_label} [{tags_str}]"],
                    injection_suspected=False,
                )
                return AgentResponse(
                    agent="intel",
                    status="success",
                    verdict=mb_verdict,
                    tokens_in=0,
                    tokens_out=0,
                )

        # 3. Fallback to Gateway intel
        request = AgentRequest(
            session_id=context.session_id if context else "unknown_session",
            file_features=features,
            context=context,
        )
        response = await self.client.call_agent("intel", request)

        # Cache outcome if successful
        if response.status == "success" and response.verdict:
            status_label = "bad" if response.verdict.verdict == "malicious" else "good"
            self._write_cache(sha256, status_label, source="gateway_intel")

        return response
