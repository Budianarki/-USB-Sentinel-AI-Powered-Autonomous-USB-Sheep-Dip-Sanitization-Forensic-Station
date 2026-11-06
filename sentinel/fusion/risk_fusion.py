"""Risk Fusion Engine combining deterministic and AI signals (Invariant 1 & Section 7).

Implements noisy-OR aggregation algorithm:
    risk_ai = 1 - PRODUCT_i (1 - clamp(w_i * s_i, 0, cap_i))
    final_risk = max(risk_deterministic, risk_ai)

Invariants enforced:
1. AI only escalates risk, never lowers it (max() ensures final_risk >= deterministic_risk).
2. Per-agent contribution caps prevent a single agent from dominating.
3. Failed or invalid agent verdicts contribute 0.0 (fail-safe).
4. Prompt injection attempts automatically escalate risk score.
"""

from dataclasses import dataclass, field

from sentinel.agents.schemas import AgentVerdict

DEFAULT_AGENT_CAPS = {
    "static_analyst": 0.85,
    "intel": 0.90,
    "context": 0.40,
    "critic": 0.50,
}

DEFAULT_AGENT_WEIGHTS = {
    "static_analyst": 1.0,
    "intel": 1.0,
    "context": 0.8,
    "critic": 0.7,
}


@dataclass
class FusionResult:
    """Outcome of risk fusion combining deterministic checks with AI agents."""

    final_risk: float
    risk_ai: float
    deterministic_risk: float
    agent_contributions: dict[str, float] = field(default_factory=dict)
    injection_detected: bool = False
    reasons: list[str] = field(default_factory=list)


class RiskFusionEngine:
    """Mathematical fusion of multi-agent assessment signals into calibrated risk score."""

    def __init__(
        self,
        agent_caps: dict[str, float] | None = None,
        agent_weights: dict[str, float] | None = None,
        injection_penalty: float = 0.85,
    ) -> None:
        self.agent_caps = {**DEFAULT_AGENT_CAPS, **(agent_caps or {})}
        self.agent_weights = {**DEFAULT_AGENT_WEIGHTS, **(agent_weights or {})}
        self.injection_penalty = injection_penalty

    def fuse(
        self,
        deterministic_risk: float,
        agent_verdicts: list[AgentVerdict],
    ) -> FusionResult:
        """Combine deterministic baseline risk with AI agent verdicts using noisy-OR."""
        contributions: dict[str, float] = {}
        reasons: list[str] = []
        injection_detected = False

        product = 1.0

        for verdict in agent_verdicts:
            agent_name = verdict.agent
            raw_score = verdict.risk_score

            # Invariant: Failed or unknown agent output contributes 0.0
            if verdict.verdict == "unknown" or raw_score < 0:
                contributions[agent_name] = 0.0
                continue

            # Check prompt injection signal
            if verdict.injection_suspected:
                injection_detected = True
                reasons.append(f"Prompt injection detected by agent '{agent_name}'")

            cap = self.agent_caps.get(agent_name, 0.75)
            weight = self.agent_weights.get(agent_name, 1.0)

            # Clamp contribution: clamp(w_i * s_i, 0, cap_i)
            effective_score = raw_score * weight
            clamped = min(cap, max(0.0, effective_score))

            # Factor into noisy-OR product
            contributions[agent_name] = round(clamped, 4)
            product *= 1.0 - clamped

            for r in verdict.reasons:
                if r not in reasons:
                    reasons.append(r)

        # Apply injection penalty if detected
        if injection_detected:
            product *= 1.0 - min(0.90, self.injection_penalty)

        # noisy-OR: risk_ai = 1 - PRODUCT_i (1 - clamped_i)
        risk_ai = max(0.0, min(1.0, 1.0 - product))

        # Invariant 1: final_risk = max(deterministic_risk, risk_ai)
        clamped_det = max(0.0, min(1.0, deterministic_risk))
        final_risk = max(clamped_det, risk_ai)

        return FusionResult(
            final_risk=round(final_risk, 4),
            risk_ai=round(risk_ai, 4),
            deterministic_risk=round(clamped_det, 4),
            agent_contributions=contributions,
            injection_detected=injection_detected,
            reasons=reasons,
        )
