"""Universal LLM Provider Factory and Configuration Loader for USB Sentinel Gateway."""

import logging
import os
from pathlib import Path

from gateway.providers.anthropic_provider import AnthropicLLMProvider
from gateway.providers.base import LLMProvider
from gateway.providers.gemini import GeminiLLMProvider
from gateway.providers.mock_provider import MockLLMProvider
from gateway.providers.ollama_provider import OllamaLLMProvider
from gateway.providers.openai_provider import OpenAILLMProvider

logger = logging.getLogger(__name__)


def load_env_file(env_path: Path | str | None = None) -> dict[str, str]:
    """Parse a .env file and populate os.environ without third-party dependencies."""
    target_path = Path(env_path) if env_path else Path(".env")
    loaded: dict[str, str] = {}
    if not target_path.exists():
        return loaded

    try:
        lines = target_path.read_text(encoding="utf-8").splitlines()
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" in stripped:
                key, val = stripped.split("=", 1)
                k_clean = key.strip()
                v_clean = val.strip().strip("'\"")
                loaded[k_clean] = v_clean
                if k_clean not in os.environ:
                    os.environ[k_clean] = v_clean
    except Exception as exc:  # noqa: BLE001
        logger.debug("Failed reading .env file: %s", exc)

    return loaded


# Load .env upon module import
load_env_file()


def get_llm_provider(
    provider_name: str | None = None,
    api_key: str | None = None,
    model_name: str | None = None,
    api_base_url: str | None = None,
) -> LLMProvider:
    """Factory creating configured LLMProvider based on provider_name and environment."""
    # Reload environment to ensure recent changes are picked up
    load_env_file()

    selected_provider = (
        provider_name
        or os.environ.get("AI_PROVIDER")
        or "mock"
    ).strip().lower()

    # 1. Google Gemini
    if selected_provider == "gemini":
        key = api_key or os.environ.get("GEMINI_API_KEY", "")
        model = model_name or os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        if not key:
            logger.warning("GEMINI_API_KEY not found; falling back to MockLLMProvider")
            return MockLLMProvider()
        return GeminiLLMProvider(api_key=key, model_name=model)

    # 2. OpenAI
    elif selected_provider == "openai":
        key = api_key or os.environ.get("OPENAI_API_KEY", "")
        model = model_name or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        base_url = api_base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        if not key:
            logger.warning("OPENAI_API_KEY not found; falling back to MockLLMProvider")
            return MockLLMProvider()
        return OpenAILLMProvider(api_key=key, model_name=model, api_base_url=base_url)

    # 3. Groq (High-speed Llama)
    elif selected_provider == "groq":
        key = api_key or os.environ.get("GROQ_API_KEY", "")
        model = model_name or os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
        if not key:
            logger.warning("GROQ_API_KEY not found; falling back to MockLLMProvider")
            return MockLLMProvider()
        return OpenAILLMProvider(
            api_key=key,
            model_name=model,
            api_base_url="https://api.groq.com/openai/v1",
        )

    # 4. Anthropic Claude
    elif selected_provider in ("anthropic", "claude"):
        key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        model = model_name or os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
        if not key:
            logger.warning("ANTHROPIC_API_KEY not found; falling back to MockLLMProvider")
            return MockLLMProvider()
        return AnthropicLLMProvider(api_key=key, model_name=model)

    # 5. Ollama Local AI (Air-Gapped / Offline)
    elif selected_provider == "ollama":
        base_url = api_base_url or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        model = model_name or os.environ.get("OLLAMA_MODEL", "llama3:latest")
        return OllamaLLMProvider(base_url=base_url, model_name=model)

    # Default: Deterministic Mock
    return MockLLMProvider()
