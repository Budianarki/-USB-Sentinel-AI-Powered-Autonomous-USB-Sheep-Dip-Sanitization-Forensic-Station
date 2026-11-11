"""Base LLM Provider abstraction for USB Sentinel Gateway."""

from abc import ABC, abstractmethod

from pydantic import BaseModel


class LLMProvider(ABC):
    """Abstract interface for LLM completion providers."""

    @abstractmethod
    async def complete_structured(
        self,
        system_prompt: str,
        user_prompt: str,
        response_model: type[BaseModel],
    ) -> tuple[BaseModel, int, int]:
        """Generate structured completion adhering to Pydantic model schema.

        Returns:
            (validated_model, tokens_in, tokens_out)
        """
        ...

    async def test_connection(self) -> tuple[bool, str]:
        """Verify API connectivity and credentials.

        Returns:
            (success: bool, message: str)
        """
        return True, "Mock provider connection OK"
