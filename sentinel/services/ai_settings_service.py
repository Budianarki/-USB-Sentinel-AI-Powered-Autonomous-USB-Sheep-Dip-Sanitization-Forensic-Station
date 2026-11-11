"""AI Provider and Key Settings Service for USB Sentinel Station."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from gateway.app import set_current_provider
from gateway.providers.factory import get_llm_provider, load_env_file

logger = logging.getLogger(__name__)


class AISettingsService:
    """Manages active AI provider configuration, API key persistence, and connectivity tests."""

    @staticmethod
    def get_settings() -> dict[str, Any]:
        """Get current AI configuration without leaking raw API secret keys."""
        load_env_file()
        current_provider = os.environ.get("AI_PROVIDER", "gemini").lower()

        # Mask key utility
        def _mask(key: str | None) -> str:
            if not key or len(key) < 8:
                return "Belum Diatur" if not key else "********"
            return f"{key[:4]}...{key[-4:]}"

        providers_status = {
            "gemini": {
                "name": "Google Gemini (Recomended)",
                "configured": bool(os.environ.get("GEMINI_API_KEY")),
                "masked_key": _mask(os.environ.get("GEMINI_API_KEY")),
                "model": os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"),
                "models_available": ["gemini-2.5-flash", "gemini-1.5-flash", "gemini-1.5-pro"],
            },
            "openai": {
                "name": "OpenAI (GPT-4o)",
                "configured": bool(os.environ.get("OPENAI_API_KEY")),
                "masked_key": _mask(os.environ.get("OPENAI_API_KEY")),
                "model": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
                "models_available": ["gpt-4o-mini", "gpt-4o"],
            },
            "groq": {
                "name": "Groq (Llama-3.3 Ultra-Fast)",
                "configured": bool(os.environ.get("GROQ_API_KEY")),
                "masked_key": _mask(os.environ.get("GROQ_API_KEY")),
                "model": os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile"),
                "models_available": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"],
            },
            "anthropic": {
                "name": "Anthropic Claude (3.5 Sonnet)",
                "configured": bool(os.environ.get("ANTHROPIC_API_KEY")),
                "masked_key": _mask(os.environ.get("ANTHROPIC_API_KEY")),
                "model": os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022"),
                "models_available": ["claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022"],
            },
            "ollama": {
                "name": "Ollama Local AI (100% Offline Air-Gapped)",
                "configured": True,
                "masked_key": "Offline Localhost",
                "model": os.environ.get("OLLAMA_MODEL", "llama3:latest"),
                "models_available": ["llama3:latest", "mistral:latest", "qwen2.5:latest"],
            },
            "mock": {
                "name": "Deterministic Mock (Testing)",
                "configured": True,
                "masked_key": "Offline Built-in",
                "model": "rule-based-mock",
                "models_available": ["rule-based-mock"],
            },
        }

        mb_key = os.environ.get("MB_API_KEY") or os.environ.get("MALWAREBAZAAR_API_KEY")
        threat_intel = {
            "malwarebazaar_configured": bool(mb_key),
            "malwarebazaar_masked_key": _mask(mb_key),
        }

        return {
            "active_provider": current_provider,
            "providers": providers_status,
            "threat_intel": threat_intel,
        }

    @staticmethod
    def update_settings(
        provider: str,
        api_key: str | None = None,
        model: str | None = None,
        save_to_env: bool = True,
        malwarebazaar_key: str | None = None,
    ) -> dict[str, Any]:
        """Update active AI provider and key at runtime, optionally saving to .env."""
        prov = provider.strip().lower()
        os.environ["AI_PROVIDER"] = prov

        if api_key and api_key.strip():
            clean_k = api_key.strip()
            if prov == "gemini":
                os.environ["GEMINI_API_KEY"] = clean_k
            elif prov == "openai":
                os.environ["OPENAI_API_KEY"] = clean_k
            elif prov == "groq":
                os.environ["GROQ_API_KEY"] = clean_k
            elif prov == "anthropic":
                os.environ["ANTHROPIC_API_KEY"] = clean_k

        if malwarebazaar_key and malwarebazaar_key.strip():
            mb_clean = malwarebazaar_key.strip()
            os.environ["MALWAREBAZAAR_API_KEY"] = mb_clean
            os.environ["MB_API_KEY"] = mb_clean

        if model and model.strip():
            clean_m = model.strip()
            if prov == "gemini":
                os.environ["GEMINI_MODEL"] = clean_m
            elif prov == "openai":
                os.environ["OPENAI_MODEL"] = clean_m
            elif prov == "groq":
                os.environ["GROQ_MODEL"] = clean_m
            elif prov == "anthropic":
                os.environ["ANTHROPIC_MODEL"] = clean_m
            elif prov == "ollama":
                os.environ["OLLAMA_MODEL"] = clean_m

        # Re-instantiate active LLM provider in Gateway
        new_provider = get_llm_provider(prov)
        set_current_provider(new_provider)

        # Optional save to .env
        if save_to_env:
            env_file = Path(".env")
            current_lines = env_file.read_text(encoding="utf-8").splitlines() if env_file.exists() else []
            env_map = {}
            for l in current_lines:
                if "=" in l and not l.strip().startswith("#"):
                    k, v = l.split("=", 1)
                    env_map[k.strip()] = v.strip()

            env_map["AI_PROVIDER"] = prov
            if prov == "gemini" and api_key:
                env_map["GEMINI_API_KEY"] = api_key.strip()
            elif prov == "openai" and api_key:
                env_map["OPENAI_API_KEY"] = api_key.strip()
            elif prov == "groq" and api_key:
                env_map["GROQ_API_KEY"] = api_key.strip()
            elif prov == "anthropic" and api_key:
                env_map["ANTHROPIC_API_KEY"] = api_key.strip()

            if malwarebazaar_key and malwarebazaar_key.strip():
                env_map["MALWAREBAZAAR_API_KEY"] = malwarebazaar_key.strip()
                env_map["MB_API_KEY"] = malwarebazaar_key.strip()

            if model:
                if prov == "gemini":
                    env_map["GEMINI_MODEL"] = model.strip()
                elif prov == "openai":
                    env_map["OPENAI_MODEL"] = model.strip()
                elif prov == "groq":
                    env_map["GROQ_MODEL"] = model.strip()
                elif prov == "anthropic":
                    env_map["ANTHROPIC_MODEL"] = model.strip()
                elif prov == "ollama":
                    env_map["OLLAMA_MODEL"] = model.strip()

            out_lines = [
                "# USB Sentinel Environment Configuration",
                f"AI_PROVIDER={env_map.get('AI_PROVIDER', 'gemini')}",
                "",
                "# AI Provider Keys",
                f"GEMINI_API_KEY={env_map.get('GEMINI_API_KEY', '')}",
                f"GEMINI_MODEL={env_map.get('GEMINI_MODEL', 'gemini-2.5-flash')}",
                "",
                f"OPENAI_API_KEY={env_map.get('OPENAI_API_KEY', '')}",
                f"OPENAI_MODEL={env_map.get('OPENAI_MODEL', 'gpt-4o-mini')}",
                "",
                f"GROQ_API_KEY={env_map.get('GROQ_API_KEY', '')}",
                f"GROQ_MODEL={env_map.get('GROQ_MODEL', 'llama-3.3-70b-versatile')}",
                "",
                f"ANTHROPIC_API_KEY={env_map.get('ANTHROPIC_API_KEY', '')}",
                f"ANTHROPIC_MODEL={env_map.get('ANTHROPIC_MODEL', 'claude-3-5-sonnet-20241022')}",
                "",
                f"OLLAMA_BASE_URL={env_map.get('OLLAMA_BASE_URL', 'http://localhost:11434')}",
                f"OLLAMA_MODEL={env_map.get('OLLAMA_MODEL', 'llama3:latest')}",
                "",
                "# Threat Intelligence Keys (MalwareBazaar / abuse.ch)",
                f"MALWAREBAZAAR_API_KEY={env_map.get('MALWAREBAZAAR_API_KEY', '')}",
                f"MB_API_KEY={env_map.get('MB_API_KEY', '')}",
                "",
                "# Gateway Station Token",
                f"SENTINEL_DEVICE_TOKEN={env_map.get('SENTINEL_DEVICE_TOKEN', 'sentinel-dev-station-01')}",
                f"SENTINEL_GATEWAY_URL={env_map.get('SENTINEL_GATEWAY_URL', 'http://gateway.local:8080')}",
            ]
            env_file.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
            logger.info("Configuration successfully written to %s", env_file.resolve())

        return {
            "success": True,
            "message": f"Konfigurasi AI diperbarui ke {prov}.",
            "active_provider": prov,
        }

    @staticmethod
    async def test_provider_connection(
        provider: str,
        api_key: str | None = None,
        model: str | None = None,
    ) -> dict[str, Any]:
        """Test provider connectivity without permanently saving invalid credentials."""
        prov = provider.strip().lower()

        # Build temporary client
        client: Any
        if prov == "gemini":
            from gateway.providers.gemini import GeminiLLMProvider

            key = (api_key or os.environ.get("GEMINI_API_KEY") or "").strip()
            if not key:
                return {"success": False, "message": "API Key Gemini belum diisi."}
            m = model or os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
            client = GeminiLLMProvider(api_key=key, model_name=m)

        elif prov == "openai":
            from gateway.providers.openai_provider import OpenAILLMProvider

            key = (api_key or os.environ.get("OPENAI_API_KEY") or "").strip()
            if not key:
                return {"success": False, "message": "API Key OpenAI belum diisi."}
            m = model or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
            client = OpenAILLMProvider(api_key=key, model_name=m)

        elif prov == "groq":
            from gateway.providers.openai_provider import OpenAILLMProvider

            key = (api_key or os.environ.get("GROQ_API_KEY") or "").strip()
            if not key:
                return {"success": False, "message": "API Key Groq belum diisi."}
            m = model or os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
            client = OpenAILLMProvider(
                api_key=key,
                model_name=m,
                api_base_url=os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1"),
            )

        elif prov == "anthropic":
            from gateway.providers.anthropic_provider import AnthropicLLMProvider

            key = (api_key or os.environ.get("ANTHROPIC_API_KEY") or "").strip()
            if not key:
                return {"success": False, "message": "API Key Anthropic belum diisi."}
            m = model or os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
            client = AnthropicLLMProvider(api_key=key, model_name=m)

        elif prov == "ollama":
            from gateway.providers.ollama_provider import OllamaLLMProvider

            m = model or os.environ.get("OLLAMA_MODEL", "llama3:latest")
            b_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
            client = OllamaLLMProvider(base_url=b_url, model_name=m)

        elif prov == "mock":
            from gateway.providers.mock_provider import MockLLMProvider

            client = MockLLMProvider()

        else:
            return {"success": False, "message": f"Provider '{prov}' tidak dikenali."}

        # Run connection probe
        ok, msg = await client.test_connection()
        return {"success": ok, "message": msg}
