"""OpenAI & Groq / OpenAI-compatible LLM Provider for USB Sentinel Gateway."""

import json
import logging
import re
from typing import Any

import httpx
from pydantic import BaseModel

from gateway.providers.base import LLMProvider

logger = logging.getLogger(__name__)


class OpenAILLMProvider(LLMProvider):
    """OpenAI-compatible LLM Provider supporting OpenAI, Groq, OpenRouter, DeepSeek, etc."""

    def __init__(
        self,
        api_key: str,
        model_name: str = "gpt-4o-mini",
        api_base_url: str = "https://api.openai.com/v1",
        timeout_s: float = 20.0,
    ) -> None:
        self.api_key = api_key.strip()
        self.model_name = model_name.strip()
        self.api_base_url = api_base_url.rstrip("/")
        self.timeout_s = timeout_s

    async def complete_structured(
        self,
        system_prompt: str,
        user_prompt: str,
        response_model: type[BaseModel],
    ) -> tuple[BaseModel, int, int]:
        schema_json = response_model.model_json_schema()
        schema_instruction = (
            f"\n\nCRITICAL REQUIREMENT:\n"
            f"You MUST respond ONLY with valid, raw JSON matching this JSON schema:\n"
            f"{json.dumps(schema_json, indent=2)}\n"
            f"Do NOT include markdown formatting like ```json or any conversational prelude/epilogue."
        )

        full_system_prompt = system_prompt + schema_instruction
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload: dict[str, Any] = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": full_system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.0,
        }

        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            url = f"{self.api_base_url}/chat/completions"
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                err_text = resp.text
                logger.error("OpenAI-compatible API error (%d): %s", resp.status_code, err_text)
                raise RuntimeError(f"OpenAI-compatible API HTTP {resp.status_code}: {err_text}")

            data = resp.json()
            choice = data["choices"][0]["message"]["content"].strip()

            # Clean markdown wrappers if any
            if choice.startswith("```"):
                choice = re.sub(r"^```[a-zA-Z]*\n?", "", choice)
                choice = re.sub(r"\n?```$", "", choice).strip()

            tokens_in = data.get("usage", {}).get("prompt_tokens", len(user_prompt.split()))
            tokens_out = data.get("usage", {}).get("completion_tokens", len(choice.split()))

            parsed = response_model.model_validate_json(choice)
            return parsed, tokens_in, tokens_out

    async def test_connection(self) -> tuple[bool, str]:
        """Test API connectivity using models endpoint."""
        if not self.api_key:
            return False, "API Key kosong."

        url = f"{self.api_base_url}/models"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    return True, f"Koneksi sukses ke {self.api_base_url} (Model: {self.model_name})"
                return False, f"API Error ({resp.status_code}): {resp.text[:120]}"
        except Exception as exc:  # noqa: BLE001
            return False, f"Gagal terhubung ke {self.api_base_url}: {exc}"

