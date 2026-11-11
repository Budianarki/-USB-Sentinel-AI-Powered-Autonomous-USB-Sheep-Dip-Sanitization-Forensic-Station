"""AI Settings and API Key Management router."""

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from sentinel.api.deps import ai_settings_service

router = APIRouter(prefix="/api/settings", tags=["Settings & AI Keys"])


class AISettingsUpdateRequest(BaseModel):
    provider: str
    api_key: str | None = None
    model: str | None = None
    save_to_env: bool = True
    malwarebazaar_key: str | None = None


class AITestConnectionRequest(BaseModel):
    provider: str
    api_key: str | None = None
    model: str | None = None


@router.get("/ai")
async def get_ai_settings() -> dict[str, Any]:
    """Retrieve current AI configuration and list of supported providers."""
    return ai_settings_service.get_settings()


@router.post("/ai")
async def update_ai_settings(req: AISettingsUpdateRequest) -> dict[str, Any]:
    """Update active AI provider, API Key, and Threat Intel credentials."""
    return ai_settings_service.update_settings(
        provider=req.provider,
        api_key=req.api_key,
        model=req.model,
        save_to_env=req.save_to_env,
        malwarebazaar_key=req.malwarebazaar_key,
    )


@router.post("/ai/test")
async def test_ai_connection(req: AITestConnectionRequest) -> dict[str, Any]:
    """Test live connectivity for a chosen AI provider and API key."""
    return await ai_settings_service.test_provider_connection(
        provider=req.provider,
        api_key=req.api_key,
        model=req.model,
    )
