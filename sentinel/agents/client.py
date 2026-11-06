"""Gateway HTTP Client for USB Sentinel (Fase 3 / Invariant 2 & 7).

Communicates with Gateway over async HTTP:
- Supplies device bearer token via Authorization header
- Supports pluggable transport (real HTTP or direct in-memory ASGI app for testing)
- Guarantees fail-closed handling on timeout, network failure, or HTTP errors
"""

import logging
import os
from typing import Any

import httpx

from sentinel.agents.schemas import AgentRequest, AgentResponse
from sentinel.util.config import GatewayConfig

logger = logging.getLogger(__name__)


class GatewayClient:
    """Async client interfacing Sentinel station with AI Gateway service."""

    def __init__(
        self,
        config: GatewayConfig | None = None,
        base_url: str | None = None,
        device_token: str | None = None,
        timeout_s: float | None = None,
        asgi_app: Any | None = None,  # For testing without external networking
    ) -> None:
        self.config = config or GatewayConfig()
        self.base_url = (base_url or self.config.url).rstrip("/")
        self.device_token = device_token or os.environ.get(
            self.config.device_token_env, "sentinel-dev-station-01"
        )
        self.timeout_s = timeout_s or self.config.timeout_s
        self.asgi_app = asgi_app

    def _get_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.device_token}",
            "Content-Type": "application/json",
        }

    async def call_agent(
        self,
        agent_name: str,
        request: AgentRequest,
    ) -> AgentResponse:
        """Invoke remote agent on Gateway with fail-closed error handling."""
        url = f"{self.base_url}/v1/agent/{agent_name}"
        headers = self._get_headers()
        payload = request.model_dump(mode="json")

        try:
            # If in-memory ASGI app provided (e.g. testing), call via ASGI transport
            transport = None
            if self.asgi_app is not None:
                transport = httpx.ASGITransport(app=self.asgi_app)

            async with httpx.AsyncClient(transport=transport, timeout=self.timeout_s) as client:
                resp = await client.post(url, json=payload, headers=headers)

                if resp.status_code == 200:
                    return AgentResponse.model_validate(resp.json())
                elif resp.status_code == 429:
                    logger.warning("Gateway rate limit hit for agent %s", agent_name)
                    return AgentResponse(
                        agent=agent_name,
                        status="budget_exhausted",
                        error_message="Gateway rate limit reached",
                    )
                else:
                    err_msg = f"Gateway returned HTTP {resp.status_code}: {resp.text}"
                    logger.error("Gateway error: %s", err_msg)
                    return AgentResponse(
                        agent=agent_name,
                        status="error",
                        error_message=err_msg,
                    )

        except httpx.TimeoutException as exc:
            logger.warning(
                "Gateway timeout after %.1fs calling agent %s: %s", self.timeout_s, agent_name, exc
            )
            return AgentResponse(
                agent=agent_name,
                status="timeout",
                error_message=f"Gateway timeout: {exc}",
            )
        except Exception as exc:  # noqa: BLE001 (Fail-closed invariant)
            logger.error("Gateway connection error calling agent %s: %s", agent_name, exc)
            return AgentResponse(
                agent=agent_name,
                status="error",
                error_message=f"Gateway connection error: {exc}",
            )
