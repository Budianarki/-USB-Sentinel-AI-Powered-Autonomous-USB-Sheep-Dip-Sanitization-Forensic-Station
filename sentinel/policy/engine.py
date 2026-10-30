"""Policy Engine (Layer 4) for USB Sentinel.

Purely deterministic decision logic based strictly on versioned PolicyConfig.
No AI involvement, no hardcoded thresholds or risk numbers (Invariants 1, 2, 3).
"""

from typing import Literal

from sentinel.agents.schemas import Decision
from sentinel.util.config import PolicyConfig


class PolicyEngine:
    """Deterministic Layer 4 Policy Engine implementing decision matrix from CLAUDE.md."""

    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    def evaluate_guard_violation(
        self,
        session_id: str,
        disallowed_classes: list[int],
    ) -> Decision:
        """Evaluate Layer 1 BadUSB / unallowed USB class violation."""
        risk = self.config.deterministic_risks.get("device_guard_violation", 1.0)
        return Decision(
            session_id=session_id,
            action="BLOCK",
            risk=risk,
            policy_version=self.config.version,
            deterministic_reasons=[
                f"BadUSB protection: disallowed interface class detected ({disallowed_classes})"
            ],
            ai_reasons=[],
            ai_available=False,
        )

    def evaluate_mount_failure(
        self,
        session_id: str,
        error_message: str,
    ) -> Decision:
        """Fail closed when partition mount fails (Invariant 2)."""
        risk = self.config.deterministic_risks.get("mount_failure", 0.85)
        return Decision(
            session_id=session_id,
            action="QUARANTINE",
            risk=risk,
            policy_version=self.config.version,
            deterministic_reasons=[f"Mount failed (fail-closed): {error_message}"],
            ai_reasons=[],
            ai_available=False,
        )

    def evaluate_session_failure(
        self,
        session_id: str,
        error_message: str,
    ) -> Decision:
        """Fail closed when unexpected exception occurs during session lifecycle."""
        risk = self.config.deterministic_risks.get("session_exception", 0.90)
        return Decision(
            session_id=session_id,
            action="QUARANTINE",
            risk=risk,
            policy_version=self.config.version,
            deterministic_reasons=[f"Exception during session (fail-closed): {error_message}"],
            ai_reasons=[],
            ai_available=False,
        )

    def evaluate_empty_session(self, session_id: str) -> Decision:
        """Evaluate a clean session with 0 files."""
        return Decision(
            session_id=session_id,
            action="ALLOW",
            risk=0.0,
            policy_version=self.config.version,
            deterministic_reasons=["Empty flashdisk / clean partition"],
            ai_reasons=[],
            ai_available=False,
        )

    def decide(
        self,
        session_id: str,
        device_guard_blocked: bool = False,
        deterministic_risk: float = 0.0,
        ai_risk: float | None = None,
        critic_disagreement: bool = False,
        has_risky_type: bool = False,
        ai_available: bool = False,
        av_or_yara_hit: bool = False,
        deterministic_reasons: list[str] | None = None,
        ai_reasons: list[str] | None = None,
    ) -> Decision:
        """Execute full Layer 4 decision matrix.

        Invariants enforced:
        - Invariant 1: final_risk = max(deterministic_risk, ai_risk)
        - Invariant 2: fail closed when AI is unavailable or risky type is unassessed
        - Invariant 3: pure deterministic evaluation based on policy.yaml thresholds
        """
        reasons_det = list(deterministic_reasons or [])
        reasons_ai = list(ai_reasons or [])

        # Invariant 1: AI only increases risk, never lowers it
        effective_ai_risk = ai_risk if (ai_risk is not None and ai_available) else 0.0
        final_risk = max(deterministic_risk, effective_ai_risk)
        final_risk = min(1.0, max(0.0, final_risk))  # Clamp to [0, 1]

        t_allow = self.config.thresholds.allow
        t_review = self.config.thresholds.review
        t_block = self.config.thresholds.block

        action: Literal["ALLOW", "QUARANTINE", "BLOCK", "HUMAN_REVIEW"]

        # Decision matrix from CLAUDE.md Section 7
        if device_guard_blocked:
            action = "BLOCK"
            if not reasons_det:
                reasons_det.append("Device guard blocked insertion")
        elif av_or_yara_hit:
            action = "BLOCK"
            if not reasons_det:
                reasons_det.append("Antivirus or YARA signature hit")
        elif final_risk >= t_block:
            action = "BLOCK"
            if not reasons_det and not reasons_ai:
                reasons_det.append(f"Risk score ({final_risk:.2f}) exceeds block threshold ({t_block})")
        elif critic_disagreement:
            action = "HUMAN_REVIEW"
            reasons_det.append("Critic agent disagreed with analysis verdict; escalating to human review")
        elif final_risk >= t_review:
            action = "HUMAN_REVIEW"
            if not reasons_det and not reasons_ai:
                reasons_det.append(f"Risk score ({final_risk:.2f}) exceeds review threshold ({t_review})")
        elif has_risky_type and not ai_available:
            # Invariant 2: Fail closed
            action = "QUARANTINE"
            reasons_det.append("Risky file type present but AI analyst unavailable (fail-closed)")
        elif final_risk <= t_allow and deterministic_risk <= t_allow and not has_risky_type:
            action = "ALLOW"
            if not reasons_det:
                reasons_det.append("All checks clean and risk within allowable threshold")
        else:
            action = "QUARANTINE"
            if not reasons_det:
                reasons_det.append("Risk level requires quarantine")

        return Decision(
            session_id=session_id,
            action=action,
            risk=final_risk,
            policy_version=self.config.version,
            deterministic_reasons=reasons_det,
            ai_reasons=reasons_ai,
            ai_available=ai_available,
        )
