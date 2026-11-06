"""Critic Agent client module (Fase 3)."""

from sentinel.agents.client import GatewayClient
from sentinel.agents.schemas import (
    AgentRequest,
    AgentResponse,
    AgentVerdict,
    FileFeatures,
    SessionContext,
)


class CriticAgent:
    """Invokes Critic Agent via Gateway to review prior analyst verdicts."""

    def __init__(self, client: GatewayClient) -> None:
        self.client = client

    async def review_verdicts(
        self,
        features: FileFeatures,
        prior_verdicts: list[AgentVerdict],
        context: SessionContext | None = None,
    ) -> AgentResponse:
        """Submit file features and prior verdicts for adversarial review."""
        request = AgentRequest(
            session_id=context.session_id if context else "unknown_session",
            file_features=features,
            context=context,
            prior_verdicts=prior_verdicts,
        )
        return await self.client.call_agent("critic", request)

