"""AI Agent Orchestrator and Triage Manager (Fase 3 / CLAUDE.md Section 7).

Coordinates:
- Selection of files requiring AI triage (GRAY files / always_ai)
- Budget controls: max steps per file, max tokens, session timeout
- Dispatching of Static Analyst, Intel, Critic, and Responder agents
- Risk Fusion calculation via RiskFusionEngine (noisy-OR)
- Persistent logging of all agent runs into SQLite agent_runs table
"""

import logging
import time
import uuid
from pathlib import Path

from sentinel.agents.client import GatewayClient
from sentinel.agents.critic import CriticAgent
from sentinel.agents.intel import IntelAgent
from sentinel.agents.responder import ResponderAgent
from sentinel.agents.schemas import (
    AgentVerdict,
    CritiqueResult,
    FileFeatures,
    SessionContext,
    TriageResult,
)
from sentinel.agents.static_analyst import StaticAnalystAgent
from sentinel.fusion.risk_fusion import RiskFusionEngine
from sentinel.store.db import db_session
from sentinel.util.config import AgentsConfig

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """Orchestrates AI agents triage workflow under strict budget bounds."""

    def __init__(
        self,
        config: AgentsConfig,
        gateway_client: GatewayClient,
        risk_fusion: RiskFusionEngine | None = None,
        db_path: Path | str | None = None,
    ) -> None:
        self.config = config
        self.client = gateway_client
        self.risk_fusion = risk_fusion or RiskFusionEngine()
        self.db_path = Path(db_path) if db_path else None

        # Instantiate agents
        self.static_analyst = StaticAnalystAgent(self.client)
        self.intel = IntelAgent(self.client, db_path=self.db_path)
        self.critic = CriticAgent(self.client)
        self.responder = ResponderAgent(self.client)

    def _record_agent_run(
        self,
        session_id: str,
        agent: str,
        model: str,
        tokens_in: int,
        tokens_out: int,
        cost_est: float,
        latency_ms: float,
        status: str,
        verdict: AgentVerdict | CritiqueResult | None,
    ) -> None:
        """Record agent execution details into SQLite agent_runs table."""
        if not self.db_path or not self.db_path.exists():
            return

        run_id = str(uuid.uuid4())
        verdict_json = verdict.model_dump_json() if verdict else None

        try:
            with db_session(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO agent_runs (
                        id, session_id, agent, model, tokens_in, tokens_out,
                        cost_est, latency_ms, status, verdict_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        run_id,
                        session_id,
                        agent,
                        model,
                        tokens_in,
                        tokens_out,
                        cost_est,
                        latency_ms,
                        status,
                        verdict_json,
                    ),
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to record agent_run to database: %s", exc)

    def _is_file_gray(self, f: FileFeatures) -> bool:
        """Identify if a file requires AI triage (GRAY status)."""
        if self.config.always_ai:
            return True

        # Files with suspicious flags, high entropy, or unusual types are GRAY
        suspicious_flags = {
            "office_macro_autoexec",
            "office_macro_present",
            "pe_packed",
            "script_detected",
            "high_entropy",
            "type_mismatch",
            "archive_encrypted",
            "untrusted_type",
        }
        return bool(any(flag in suspicious_flags for flag in f.flags) or f.ext_mismatch)

    async def triage_session(
        self,
        session_id: str,
        files: list[FileFeatures],
        deterministic_risk: float,
        context: SessionContext | None = None,
    ) -> TriageResult:
        """Run AI triage across candidate files adhering to session budgets."""
        start_time = time.time()
        max_seconds = self.config.budget.max_seconds_per_session
        max_tokens = self.config.budget.max_tokens_per_session

        total_tokens = 0
        total_cost = 0.0
        all_verdicts: list[AgentVerdict] = []
        all_critiques: list[CritiqueResult] = []
        critic_disagreement = False
        ai_available = True

        # Filter candidate files
        gray_files = [f for f in files if self._is_file_gray(f)]

        if not gray_files:
            return TriageResult(
                session_id=session_id,
                ai_available=True,
                ai_risk=0.0,
                ai_reasons=["No gray files requiring AI triage; all deterministic checks clean."],
            )

        for file_feat in gray_files:
            # Check session budget timeout
            if (time.time() - start_time) > max_seconds:
                logger.warning(
                    "Session AI budget timeout exceeded (%ds); halting triage", max_seconds
                )
                break
            if total_tokens > max_tokens:
                logger.warning("Session token budget exceeded (%d); halting triage", max_tokens)
                break

            file_verdicts: list[AgentVerdict] = []

            # 1. Static Analyst Agent
            if "static_analyst" in self.config.enabled:
                resp = await self.static_analyst.analyze_file(file_feat, context=context)
                total_tokens += resp.tokens_in + resp.tokens_out
                total_cost += resp.cost_est

                self._record_agent_run(
                    session_id=session_id,
                    agent="static_analyst",
                    model="gateway-default",
                    tokens_in=resp.tokens_in,
                    tokens_out=resp.tokens_out,
                    cost_est=resp.cost_est,
                    latency_ms=resp.latency_ms,
                    status=resp.status,
                    verdict=resp.verdict,
                )

                if resp.status == "success" and resp.verdict:
                    file_verdicts.append(resp.verdict)
                elif resp.status in ("error", "timeout", "budget_exhausted"):
                    ai_available = False

            # 2. Intel Agent
            if "intel" in self.config.enabled:
                intel_resp = await self.intel.lookup_hash(file_feat, context=context)
                total_tokens += intel_resp.tokens_in + intel_resp.tokens_out
                total_cost += intel_resp.cost_est

                self._record_agent_run(
                    session_id=session_id,
                    agent="intel",
                    model="gateway-default",
                    tokens_in=intel_resp.tokens_in,
                    tokens_out=intel_resp.tokens_out,
                    cost_est=intel_resp.cost_est,
                    latency_ms=intel_resp.latency_ms,
                    status=intel_resp.status,
                    verdict=intel_resp.verdict,
                )

                if intel_resp.status == "success" and intel_resp.verdict:
                    file_verdicts.append(intel_resp.verdict)
                elif intel_resp.status in ("error", "timeout", "budget_exhausted"):
                    ai_available = False

            # 3. Critic Agent (triggered if any verdict >= 0.40 or file has high suspicion)
            needs_critic = (
                any(v.risk_score >= 0.40 for v in file_verdicts) or file_feat.ext_mismatch
            )
            if "critic" in self.config.enabled and needs_critic and file_verdicts:
                critic_resp = await self.critic.review_verdicts(
                    file_feat, prior_verdicts=file_verdicts, context=context
                )
                total_tokens += critic_resp.tokens_in + critic_resp.tokens_out
                total_cost += critic_resp.cost_est

                self._record_agent_run(
                    session_id=session_id,
                    agent="critic",
                    model="gateway-default",
                    tokens_in=critic_resp.tokens_in,
                    tokens_out=critic_resp.tokens_out,
                    cost_est=critic_resp.cost_est,
                    latency_ms=critic_resp.latency_ms,
                    status=critic_resp.status,
                    verdict=critic_resp.critique,
                )

                if critic_resp.status == "success" and critic_resp.critique:
                    all_critiques.append(critic_resp.critique)
                    if not critic_resp.critique.agrees:
                        critic_disagreement = True
                        logger.info(
                            "Critic agent disagreed with prior verdicts on %s", file_feat.file_id
                        )

            all_verdicts.extend(file_verdicts)

        # 4. Fuse signals via Risk Fusion Engine
        fusion_res = self.risk_fusion.fuse(
            deterministic_risk=deterministic_risk,
            agent_verdicts=all_verdicts,
        )

        return TriageResult(
            session_id=session_id,
            ai_available=ai_available,
            ai_risk=fusion_res.risk_ai,
            ai_reasons=fusion_res.reasons,
            critic_disagreement=critic_disagreement,
            agent_verdicts=all_verdicts,
            critiques=all_critiques,
            total_tokens=total_tokens,
            total_cost_est=total_cost,
        )
