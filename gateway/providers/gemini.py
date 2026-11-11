"""Google Gemini LLM Provider for USB Sentinel Gateway."""

import json
import logging
import re
from typing import Any

import httpx
from pydantic import BaseModel

from gateway.providers.base import LLMProvider

logger = logging.getLogger(__name__)


class GeminiLLMProvider(LLMProvider):
    """Google Gemini API Provider with structured JSON output support."""

    def __init__(
        self,
        api_key: str,
        model_name: str = "gemini-2.5-flash",
        timeout_s: float = 20.0,
    ) -> None:
        self.api_key = api_key.strip()
        self.model_name = model_name.strip()
        self.timeout_s = timeout_s

    def _get_api_url(self) -> str:
        # Standard v1beta generateContent endpoint
        return (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model_name}:generateContent?key={self.api_key}"
        )

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
        payload: dict[str, Any] = {
            "system_instruction": {
                "parts": [{"text": full_system_prompt}]
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_prompt}],
                }
            ],
            "generationConfig": {
                "response_mime_type": "application/json",
                "temperature": 0.0,
            },
        }

        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            resp = await client.post(self._get_api_url(), json=payload)
            if resp.status_code != 200:
                err_text = resp.text
                logger.error("Gemini API error (%d): %s", resp.status_code, err_text)
                raise RuntimeError(f"Gemini API returned HTTP {resp.status_code}: {err_text}")

            data = resp.json()

            # Extract generated text
            candidates = data.get("candidates", [])
            if not candidates:
                raise RuntimeError("Gemini API returned no candidates.")

            part = candidates[0].get("content", {}).get("parts", [{}])[0]
            raw_text = part.get("text", "").strip()

            # Clean possible markdown wrap ```json ... ```
            if raw_text.startswith("```"):
                raw_text = re.sub(r"^```[a-zA-Z]*\n?", "", raw_text)
                raw_text = re.sub(r"\n?```$", "", raw_text).strip()

            usage = data.get("usageMetadata", {})
            tokens_in = usage.get("promptTokenCount", len(user_prompt.split()) + len(full_system_prompt.split()))
            tokens_out = usage.get("candidatesTokenCount", len(raw_text.split()))

            parsed = response_model.model_validate_json(raw_text)
            return parsed, tokens_in, tokens_out

    async def test_connection(self) -> tuple[bool, str]:
        """Test API key validity against Gemini list models or small generation."""
        if not self.api_key:
            return False, "Gemini API Key kosong."

        url = f"https://generativelanguage.googleapis.com/v1beta/models?key={self.api_key}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return True, f"Koneksi Google Gemini sukses! (Model: {self.model_name})"
                return False, f"Gemini API Error ({resp.status_code}): {resp.text[:120]}"
        except Exception as exc:  # noqa: BLE001
            return False, f"Gagal terhubung ke Google Gemini: {exc}"

