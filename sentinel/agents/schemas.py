"""Core data schemas for USB Sentinel (pydantic v2).

Defines FileFeatures, SessionContext, AgentVerdict, CritiqueResult, and Decision.
Strict validation is enforced according to Invariant 9.
"""

from typing import Any, Literal

from pydantic import BaseModel, Field


class FileFeatures(BaseModel):
    """Normalized feature extraction result for a single file on USB storage."""

    file_id: str  # Local opaque ID, NOT host path
    sha256: str
    size: int = Field(ge=0)
    detected_type: str  # Identified by magic bytes
    ext_mismatch: bool
    entropy: float = Field(ge=0.0, le=8.0)
    flags: list[str] = Field(default_factory=list)
    av_hits: list[str] = Field(default_factory=list)
    yara_hits: list[str] = Field(default_factory=list)
    static_summary: dict[str, Any] = Field(default_factory=dict)
    sanitized_name: str | None = None


class SessionContext(BaseModel):
    """Contextual metadata regarding current USB insertion session."""

    session_id: str
    device_fingerprint: str  # SHA256(vid || pid || serial)
    device_reputation: Literal["known_good", "unknown", "previously_blocked"] = "unknown"
    hour_of_day: int = Field(ge=0, le=23)
    recent_events: int = Field(default=0, ge=0)
    anon_user_id: str | None = None
    operator_id: str | None = None  # Optional operator identity


class AgentVerdict(BaseModel):
    """Output verdict from an AI analysis agent (Invariant 9)."""

    agent: str
    file_id: str | None = None
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    verdict: Literal["benign", "suspicious", "malicious", "unknown"]
    reasons: list[str] = Field(default_factory=list, max_length=8)
    injection_suspected: bool = False


class CritiqueResult(BaseModel):
    """Output from Critic Agent reviewing other agent verdicts."""

    agrees: bool
    counter_arguments: list[str] = Field(default_factory=list)
    adjusted_risk_hint: float | None = Field(default=None, ge=0.0, le=1.0)


class AgentRequest(BaseModel):
    """Structured request payload sent to Gateway for an agent run."""

    session_id: str
    file_features: FileFeatures | None = None
    context: SessionContext | None = None
    prior_verdicts: list[AgentVerdict] = Field(default_factory=list)
    prompt_override: str | None = None


class AgentResponse(BaseModel):
    """Structured response payload returned by Gateway for an agent run."""

    agent: str
    status: Literal["success", "timeout", "error", "budget_exhausted"]
    verdict: AgentVerdict | None = None
    critique: CritiqueResult | None = None
    report_text: str | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    cost_est: float = 0.0
    latency_ms: float = 0.0
    error_message: str | None = None


class TriageResult(BaseModel):
    """Aggregated outcome of AI Orchestrator triage across a session."""

    session_id: str
    ai_available: bool = False
    ai_risk: float = 0.0
    ai_reasons: list[str] = Field(default_factory=list)
    critic_disagreement: bool = False
    agent_verdicts: list[AgentVerdict] = Field(default_factory=list)
    critiques: list[CritiqueResult] = Field(default_factory=list)
    responder_summary: str | None = None
    total_tokens: int = 0
    total_cost_est: float = 0.0


from sentinel.policy.schemas import Decision

__all__ = [
    "AgentRequest",
    "AgentResponse",
    "AgentVerdict",
    "CritiqueResult",
    "Decision",
    "FileFeatures",
    "SessionContext",
    "TriageResult",
]
