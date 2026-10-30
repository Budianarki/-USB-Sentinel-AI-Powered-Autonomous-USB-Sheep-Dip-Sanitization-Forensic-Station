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


class Decision(BaseModel):
    """Final session or file decision emitted by Policy Engine (Layer 4)."""
    session_id: str
    action: Literal["ALLOW", "QUARANTINE", "BLOCK", "HUMAN_REVIEW"]
    risk: float = Field(ge=0.0, le=1.0)
    policy_version: str
    deterministic_reasons: list[str] = Field(default_factory=list)
    ai_reasons: list[str] = Field(default_factory=list)
    ai_available: bool = False
