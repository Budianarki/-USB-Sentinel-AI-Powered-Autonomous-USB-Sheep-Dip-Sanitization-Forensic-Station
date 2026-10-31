"""Policy Engine (Layer 4) for USB Sentinel.

Purely deterministic decision logic based strictly on versioned PolicyConfig.
No AI involvement, no hardcoded thresholds or risk numbers (Invariants 1, 2, 3).
"""

from typing import Literal

from sentinel.policy.schemas import Decision
from sentinel.util.config import PolicyConfig


class PolicyEngine:
    """Deterministic Layer 4 Policy Engine implementing decision matrix from CLAUDE.md."""

    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    def evaluate_guard_violation(
        self,
        session_id: str,
        disallowed_classes: list[int],
        reasons: list[str] | None = None,
    ) -> Decision:
        """Evaluate Layer 1 BadUSB / unallowed USB class violation."""
        risk = self.config.deterministic_risks.get("device_guard_violation", 1.0)
        det_reasons = (
            reasons
            if reasons
            else [f"BadUSB protection: disallowed interface class detected ({disallowed_classes})"]
        )
        return Decision(
            session_id=session_id,
            action="BLOCK",
            risk=risk,
            policy_version=self.config.version,
            deterministic_reasons=det_reasons,
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
        *,
        scan_complete: bool,
        scanners_ok: bool,
        filesystem_supported: bool,
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
        - Invariant 2: fail closed when AI is unavailable, scan is incomplete,
          scanners failed, or filesystem is unsupported.
        - Invariant 3: pure deterministic evaluation based on policy.yaml thresholds.
        ALLOW is emitted ONLY if scan_complete=True, scanners_ok=True, and filesystem_supported=True.
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

        # Decision matrix from CLAUDE.md Section 7 & Checkpoint 1A/1B requirements
        if device_guard_blocked:
            action = "BLOCK"
            if not reasons_det:
                reasons_det.append("Device guard blocked insertion")
        elif av_or_yara_hit:
            action = "BLOCK"
            if not reasons_det:
                reasons_det.append("Antivirus or YARA signature hit")
        elif not scan_complete:
            # Quota truncated, DoS limit hit, TOCTOU mismatch, or unreadable file -> fail closed
            action = "QUARANTINE"
            reasons_det.append(
                "Scan incomplete (quota truncated, DoS limit hit, or unreadable file; fail-closed)"
            )
        elif not scanners_ok:
            # ClamAV or YARA offline / error -> fail closed
            action = "QUARANTINE"
            reasons_det.append("Security scanners offline or reported error (fail-closed)")
        elif not filesystem_supported:
            # Filesystem unsupported or partial mount -> fail closed
            action = "QUARANTINE"
            reasons_det.append("Filesystem unsupported or partial mount (fail-closed)")
        elif final_risk >= t_block:
            action = "BLOCK"
            if not reasons_det and not reasons_ai:
                reasons_det.append(
                    f"Risk score ({final_risk:.2f}) exceeds block threshold ({t_block})"
                )
        elif critic_disagreement:
            action = "HUMAN_REVIEW"
            reasons_det.append(
                "Critic agent disagreed with analysis verdict; escalating to human review"
            )
        elif final_risk >= t_review:
            action = "HUMAN_REVIEW"
            if not reasons_det and not reasons_ai:
                reasons_det.append(
                    f"Risk score ({final_risk:.2f}) exceeds review threshold ({t_review})"
                )
        elif has_risky_type and not ai_available:
            # Invariant 2: Fail closed
            action = "QUARANTINE"
            reasons_det.append("Risky file type present but AI analyst unavailable (fail-closed)")
        elif (
            scan_complete
            and scanners_ok
            and filesystem_supported
            and not has_risky_type
            and final_risk <= t_allow
            and deterministic_risk <= t_allow
        ):
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

    def aggregate_session_decisions(
        self,
        session_id: str,
        file_decisions: list[Decision],
    ) -> Decision:
        """Aggregate per-file decisions into a single session decision.

        CLAUDE.md Section 7:
        'Keputusan sesi = keputusan terparah di antara semua file
        (satu file BLOCK = sesi BLOCK)'
        Severity order: BLOCK > QUARANTINE > HUMAN_REVIEW > ALLOW.
        """
        if not file_decisions:
            return self.evaluate_empty_session(session_id)

        severity_rank: dict[str, int] = {
            "BLOCK": 4,
            "QUARANTINE": 3,
            "HUMAN_REVIEW": 2,
            "ALLOW": 1,
        }

        worst_decision = max(
            file_decisions,
            key=lambda d: severity_rank.get(d.action, 0),
        )

        all_det_reasons: list[str] = []
        all_ai_reasons: list[str] = []
        max_risk = 0.0
        ai_available = any(d.ai_available for d in file_decisions)

        for d in file_decisions:
            max_risk = max(max_risk, d.risk)
            for r in d.deterministic_reasons:
                if r not in all_det_reasons:
                    all_det_reasons.append(r)
            for r in d.ai_reasons:
                if r not in all_ai_reasons:
                    all_ai_reasons.append(r)

        return Decision(
            session_id=session_id,
            action=worst_decision.action,
            risk=max_risk,
            policy_version=self.config.version,
            deterministic_reasons=all_det_reasons,
            ai_reasons=all_ai_reasons,
            ai_available=ai_available,
        )
