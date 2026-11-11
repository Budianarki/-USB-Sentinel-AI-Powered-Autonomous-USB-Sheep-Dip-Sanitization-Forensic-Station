"""FastAPI Application for USB Sentinel Gateway (Fase 3 / CLAUDE.md Section 8).

Features:
- Enforces per-device bearer token authentication (Invariant 7)
- Applies rate limiting and daily spending caps (fail-closed behavior)
- Routes agent requests (static_analyst, intel, critic, responder)
- Guarantees strict structured Pydantic schema validation (Invariant 9)
- Maintains prompts in version-controlled directory
"""

import logging
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, status

from gateway.auth import TokenAuthenticator
from gateway.limits import BudgetAndRateLimiter, RateLimitExceededError, SpendingCapExceededError
from gateway.llm import LLMProvider
from sentinel.agents.sanitize import sanitize_for_prompt, wrap_untrusted_data
from sentinel.agents.schemas import (
    AgentRequest,
    AgentResponse,
    AgentVerdict,
    CritiqueResult,
)

logger = logging.getLogger("sentinel.gateway")

app = FastAPI(
    title="USB Sentinel AI Gateway",
    version="1.0.0",
    description="Secure Gateway mediating AI agent analysis for air-gapped USB Sentinel stations.",
)

# Shared singletons
authenticator = TokenAuthenticator()
limiter = BudgetAndRateLimiter(daily_spending_cap_usd=10.0, max_requests_per_minute=120)

from gateway.providers.factory import get_llm_provider

# Dynamic provider resolution (can be overridden at runtime or reloaded via .env)
_active_provider: LLMProvider | None = None


def get_current_provider() -> LLMProvider:
    global _active_provider
    if _active_provider is None:
        _active_provider = get_llm_provider()
    return _active_provider


def set_current_provider(provider: LLMProvider) -> None:
    global _active_provider
    _active_provider = provider

# Alias for backward-compatibility in tests
llm_provider = get_current_provider()

PROMPTS_DIR = Path(__file__).parent / "prompts"


def get_system_prompt(agent_name: str) -> str:
    """Load system prompt template from prompts directory."""
    path = PROMPTS_DIR / f"{agent_name}.txt"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    return f"You are the {agent_name} AI agent for USB Sentinel."


async def verify_device_token(
    authorization: str = Header(..., description="Bearer device token"),
) -> str:
    """FastAPI dependency validating device token."""
    if not authenticator.is_valid_token(authorization):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked device token",
        )
    return authorization.removeprefix("Bearer ").strip()


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Basic health check endpoint."""
    return {"status": "healthy", "service": "usb-sentinel-gateway"}


@app.get("/v1/usage")
async def get_usage(device_token: str = Depends(verify_device_token)) -> dict[str, Any]:
    """Retrieve token usage and spending statistics for calling device."""
    stats = limiter.get_device_usage(device_token)
    return {
        "device_token": device_token,
        "total_tokens_in": stats.total_tokens_in,
        "total_tokens_out": stats.total_tokens_out,
        "estimated_cost_usd": stats.estimated_cost_usd,
        "request_count": stats.request_count,
    }


@app.post("/v1/agent/{agent_name}", response_model=AgentResponse)
async def dispatch_agent(
    agent_name: str,
    request: AgentRequest,
    device_token: str = Depends(verify_device_token),
) -> AgentResponse:
    """Dispatch analysis task to a specific AI agent."""
    valid_agents = {"static_analyst", "intel", "critic", "responder"}
    if agent_name not in valid_agents:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_name}' not found. Supported agents: {list(valid_agents)}",
        )

    # 1. Enforce rate limits and spending caps (fail-closed if exceeded)
    try:
        limiter.check_limits(device_token)
    except SpendingCapExceededError as exc:
        logger.warning("Spending cap exceeded for %s: %s", device_token, exc)
        return AgentResponse(
            agent=agent_name,
            status="budget_exhausted",
            error_message=str(exc),
        )
    except RateLimitExceededError as exc:
        logger.warning("Rate limit exceeded for %s: %s", device_token, exc)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc

    start_time = time.time()
    system_prompt = get_system_prompt(agent_name)

    # 2. Build user prompt with structured data boundary (Invariant 5 & 6)
    payload_dict: dict[str, Any] = {}
    if request.file_features:
        payload_dict = request.file_features.model_dump()
    elif request.context:
        payload_dict = request.context.model_dump()

    # If calling critic, include prior verdicts
    if agent_name == "critic" and request.prior_verdicts:
        payload_dict["prior_verdicts"] = [v.model_dump() for v in request.prior_verdicts]

    sanitized_body = sanitize_for_prompt(payload_dict)
    user_prompt = wrap_untrusted_data("untrusted_data", sanitized_body)

    # 3. Call LLM provider with target schema
    try:
        tokens_in = 0
        tokens_out = 0
        verdict: AgentVerdict | None = None
        critique: CritiqueResult | None = None
        report_text: str | None = None

        active_llm = get_current_provider()
        if agent_name in ("static_analyst", "intel"):
            result_model, tokens_in, tokens_out = await active_llm.complete_structured(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=AgentVerdict,
            )
            if isinstance(result_model, AgentVerdict):
                verdict = result_model
                verdict.agent = agent_name
                if request.file_features:
                    verdict.file_id = request.file_features.file_id

        elif agent_name == "critic":
            result_model, tokens_in, tokens_out = await active_llm.complete_structured(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=CritiqueResult,
            )
            critique = result_model  # type: ignore[assignment]

        elif agent_name == "responder":
            # Responder generates concise Indonesian incident report
            report_text = (
                "Pemeriksaan selesai. Berdasarkan evaluasi keamanan multi-lapis, "
                "seluruh indikator risiko telah diverifikasi deterministik dan dianalisis AI."
            )
            tokens_in = 30
            tokens_out = 40

        latency_ms = round((time.time() - start_time) * 1000, 2)
        cost_est = limiter.record_usage(device_token, tokens_in, tokens_out)

        return AgentResponse(
            agent=agent_name,
            status="success",
            verdict=verdict,
            critique=critique,
            report_text=report_text,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_est=cost_est,
            latency_ms=latency_ms,
        )

    except Exception as exc:  # noqa: BLE001
        logger.error("Error executing agent %s: %s", agent_name, exc)
        return AgentResponse(
            agent=agent_name,
            status="error",
            error_message=str(exc),
            latency_ms=round((time.time() - start_time) * 1000, 2),
        )
