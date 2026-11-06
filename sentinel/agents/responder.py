"""Incident Responder Agent client module (Fase 3)."""

from sentinel.agents.client import GatewayClient
from sentinel.agents.schemas import AgentRequest, AgentResponse, SessionContext
from sentinel.policy.schemas import Decision


class ResponderAgent:
    """Invokes Responder Agent via Gateway to compose human-readable incident reports."""

    def __init__(self, client: GatewayClient) -> None:
        self.client = client

    async def generate_incident_report(
        self,
        decision: Decision,
        context: SessionContext | None = None,
    ) -> AgentResponse:
        """Submit final decision to Gateway to formulate an incident explanation."""
        request = AgentRequest(
            session_id=decision.session_id,
            context=context,
            prompt_override=(
                f"Sesi: {decision.session_id}\n"
                f"Keputusan: {decision.action} (Skor Risiko: {decision.risk:.2f})\n"
                f"Alasan: {', '.join(decision.deterministic_reasons + decision.ai_reasons)}"
            ),
        )
        return await self.client.call_agent("responder", request)

