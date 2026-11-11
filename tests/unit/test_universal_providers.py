"""Unit tests for Universal AI Providers and Factory in USB Sentinel Gateway."""

import pytest
from pydantic import BaseModel

from gateway.providers import (
    AnthropicLLMProvider,
    GeminiLLMProvider,
    MockLLMProvider,
    OllamaLLMProvider,
    OpenAILLMProvider,
    get_llm_provider,
)
from sentinel.agents.schemas import AgentVerdict


class DummyResponseModel(BaseModel):
    summary: str = "ok"


@pytest.mark.asyncio
async def test_provider_factory_resolution():
    """Verify factory returns appropriate provider instances."""
    # Mock
    p_mock = get_llm_provider("mock")
    assert isinstance(p_mock, MockLLMProvider)

    # Gemini
    p_gemini = get_llm_provider("gemini", api_key="AIzaSyTest123", model_name="gemini-2.5-flash")
    assert isinstance(p_gemini, GeminiLLMProvider)
    assert p_gemini.api_key == "AIzaSyTest123"
    assert p_gemini.model_name == "gemini-2.5-flash"

    # OpenAI
    p_openai = get_llm_provider("openai", api_key="sk-test-key", model_name="gpt-4o-mini")
    assert isinstance(p_openai, OpenAILLMProvider)
    assert p_openai.api_key == "sk-test-key"

    # Groq
    p_groq = get_llm_provider("groq", api_key="gsk-test-key")
    assert isinstance(p_groq, OpenAILLMProvider)
    assert "groq.com" in p_groq.api_base_url

    # Anthropic
    p_claude = get_llm_provider("anthropic", api_key="sk-ant-test")
    assert isinstance(p_claude, AnthropicLLMProvider)
    assert p_claude.api_key == "sk-ant-test"

    # Ollama
    p_ollama = get_llm_provider("ollama", model_name="llama3:latest")
    assert isinstance(p_ollama, OllamaLLMProvider)
    assert p_ollama.model_name == "llama3:latest"


@pytest.mark.asyncio
async def test_missing_api_key_falls_back_to_mock():
    """Verify cloud providers fall back safely to MockLLMProvider if no key is configured."""
    p_empty_gemini = get_llm_provider("gemini", api_key="")
    assert isinstance(p_empty_gemini, MockLLMProvider)

    p_empty_openai = get_llm_provider("openai", api_key="")
    assert isinstance(p_empty_openai, MockLLMProvider)

    p_empty_claude = get_llm_provider("anthropic", api_key="")
    assert isinstance(p_empty_claude, MockLLMProvider)


@pytest.mark.asyncio
async def test_mock_provider_structured_completion():
    """Verify mock provider completes schema successfully."""
    provider = MockLLMProvider()
    user_prompt = "Analyze this file: <untrusted_data>{\"flags\": [\"office_macro_autoexec\"], \"file_id\": \"f123\"}</untrusted_data>"
    verdict, tokens_in, tokens_out = await provider.complete_structured(
        system_prompt="You are analyst",
        user_prompt=user_prompt,
        response_model=AgentVerdict,
    )
    assert isinstance(verdict, AgentVerdict)
    assert verdict.risk_score >= 0.85
    assert verdict.verdict == "malicious"
    assert tokens_in > 0
    assert tokens_out > 0


@pytest.mark.asyncio
async def test_mock_provider_test_connection():
    """Verify mock provider test_connection returns True."""
    provider = MockLLMProvider()
    ok, msg = await provider.test_connection()
    assert ok is True
    assert "Mock" in msg

