"""Anthropic Claude LLM Provider for USB Sentinel Gateway."""

import json
import logging
import re
from typing import Any

import httpx
from pydantic import BaseModel

from gateway.providers.base import LLMProvider

logger = logging.getLogger(__name__)


class AnthropicLLMProvider(LLMProvider):
    """Anthropic Claude API Provider (Claude 3.5 Sonnet / Claude 3 Haiku)."""

    def __init__(
        self,
        api_key: str,
        model_name: str = "claude-3-5-sonnet-20241022",
        timeout_s: float = 25.0,
    ) -> None:
        self.api_key = api_key.strip()
        self.model_name = model_name.strip()
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
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        payload: dict[str, Any] = {
            "model": self.model_name,
            "max_tokens": 2048,
            "system": full_system_prompt,
            "messages": [
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.0,
        }

        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            url = "https://api.anthropic.com/v1/messages"
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                err_text = resp.text
                logger.error("Anthropic API error (%d): %s", resp.status_code, err_text)
                raise RuntimeError(f"Anthropic API returned HTTP {resp.status_code}: {err_text}")

            data = resp.json()
            content_blocks = data.get("content", [])
            choice = ""
            for b in content_blocks:
                if b.get("type") == "text":
                    choice += b.get("text", "")

            choice = choice.strip()
            if choice.startswith("```"):
                choice = re.sub(r"^```[a-zA-Z]*\n?", "", choice)
                choice = re.sub(r"\n?```$", "", choice).strip()

            usage = data.get("usage", {})
            tokens_in = usage.get("input_tokens", len(user_prompt.split()))
            tokens_out = usage.get("output_tokens", len(choice.split()))

            parsed = response_model.model_validate_json(choice)
            return parsed, tokens_in, tokens_out

    async def test_connection(self) -> tuple[bool, str]:
        """Test Anthropic API connectivity using a minimal messages ping."""
        if not self.api_key:
            return False, "Anthropic API Key kosong."

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": self.model_name,
            "max_tokens": 5,
            "messages": [{"role": "user", "content": "ping"}],
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post("https://api.anthropic.com/v1/messages", json=payload, headers=headers)
                if resp.status_code == 200:
                    return True, f"Koneksi Anthropic Claude sukses! (Model: {self.model_name})"
                return False, f"Anthropic API Error ({resp.status_code}): {resp.text[:120]}"
        except Exception as exc:  # noqa: BLE001
            return False, f"Gagal terhubung ke Anthropic: {exc}"

