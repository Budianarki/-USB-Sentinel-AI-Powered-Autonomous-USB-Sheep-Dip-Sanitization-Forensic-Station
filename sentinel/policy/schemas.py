"""Policy engine schema definitions (Layer 4)."""

from typing import Literal

from pydantic import BaseModel, Field


class Decision(BaseModel):
    """Final session or file decision emitted by Policy Engine (Layer 4)."""

    session_id: str
    action: Literal["ALLOW", "QUARANTINE", "BLOCK", "HUMAN_REVIEW"]
    risk: float = Field(ge=0.0, le=1.0)
    policy_version: str
    deterministic_reasons: list[str] = Field(default_factory=list)
    ai_reasons: list[str] = Field(default_factory=list)
    ai_available: bool = False
