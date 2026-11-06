"""Static Analyst Agent client module (Fase 3)."""

from sentinel.agents.client import GatewayClient
from sentinel.agents.schemas import (
    AgentRequest,
    AgentResponse,
    FileFeatures,
    SessionContext,
)


class StaticAnalystAgent:
    """Invokes Static Analyst via Gateway to inspect file features."""

    def __init__(self, client: GatewayClient) -> None:
        self.client = client

    async def analyze_file(
        self,
        features: FileFeatures,
        context: SessionContext | None = None,
    ) -> AgentResponse:
        """Submit file features to Gateway static analyst."""
        request = AgentRequest(
            session_id=context.session_id if context else "unknown_session",
            file_features=features,
            context=context,
        )
        return await self.client.call_agent("static_analyst", request)
