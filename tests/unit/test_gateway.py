"""Unit tests for USB Sentinel Gateway service (Phase 3 / Invariant 7 & 11)."""

import httpx
import pytest

from gateway.app import app
from gateway.limits import BudgetAndRateLimiter, SpendingCapExceededError
from sentinel.agents.schemas import AgentRequest, FileFeatures


@pytest.mark.asyncio
async def test_gateway_health():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_gateway_unauthorized_token_rejected():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        req = AgentRequest(session_id="s1").model_dump(mode="json")
        resp = await client.post(
            "/v1/agent/static_analyst",
            json=req,
            headers={"Authorization": "Bearer invalid_evil_token"},
        )
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_gateway_static_analyst_dispatch():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        features = FileFeatures(
            file_id="f1",
            sha256="a" * 64,
            size=1024,
            detected_type="docx",
            ext_mismatch=False,
            entropy=4.5,
            flags=["office_macro_autoexec"],
        )
        req = AgentRequest(session_id="s1", file_features=features).model_dump(mode="json")
        resp = await client.post(
            "/v1/agent/static_analyst",
            json=req,
            headers={"Authorization": "Bearer sentinel-dev-station-01"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["agent"] == "static_analyst"
        assert data["status"] == "success"
        assert data["verdict"] is not None
        assert data["verdict"]["verdict"] == "malicious"
        assert data["verdict"]["risk_score"] >= 0.85


@pytest.mark.asyncio
async def test_gateway_critic_dispatch_and_disagreement():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        features = FileFeatures(
            file_id="f2",
            sha256="b" * 64,
            size=2048,
            detected_type="pe",
            ext_mismatch=True,  # Disguised executable!
            entropy=7.8,
            flags=["pe_packed"],
        )
        # Prior verdict claiming it's benign with low risk
        from sentinel.agents.schemas import AgentVerdict

        lenient_verdict = AgentVerdict(
            agent="flawed_agent",
            file_id="f2",
            risk_score=0.10,
            confidence=0.5,
            verdict="benign",
            reasons=["Assumed benign"],
        )
        req = AgentRequest(
            session_id="s2",
            file_features=features,
            prior_verdicts=[lenient_verdict],
        ).model_dump(mode="json")

        resp = await client.post(
            "/v1/agent/critic",
            json=req,
            headers={"Authorization": "Bearer sentinel-dev-station-01"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["critique"] is not None
        # Critic should disagree because a disguised packed PE was rated 0.10
        assert data["critique"]["agrees"] is False


@pytest.mark.asyncio
async def test_gateway_spending_cap_enforcement():
    limiter = BudgetAndRateLimiter(daily_spending_cap_usd=0.01)
    device_token = "cap_test_device"

    # Burn tokens to exceed cap
    limiter.record_usage(device_token, tokens_in=10000, tokens_out=10000)

    # Next check must raise SpendingCapExceededError
    with pytest.raises(SpendingCapExceededError):
        limiter.check_limits(device_token)


@pytest.mark.asyncio
async def test_gateway_usage_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/v1/usage",
            headers={"Authorization": "Bearer sentinel-dev-station-01"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["device_token"] == "sentinel-dev-station-01"
        assert "estimated_cost_usd" in data
