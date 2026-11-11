"""Ollama Local LLM Provider for USB Sentinel Gateway (Air-Gapped / Offline)."""

import json
import logging
import re
from typing import Any

import httpx
from pydantic import BaseModel

from gateway.providers.base import LLMProvider

logger = logging.getLogger(__name__)


class OllamaLLMProvider(LLMProvider):
    """Ollama Local AI Provider running on localhost for 100% offline air-gapped stations."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model_name: str = "llama3:latest",
        timeout_s: float = 60.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
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
        payload: dict[str, Any] = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": full_system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.0},
        }

        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            url = f"{self.base_url}/api/chat"
            resp = await client.post(url, json=payload)
            if resp.status_code != 200:
                err_text = resp.text
                logger.error("Ollama API error (%d): %s", resp.status_code, err_text)
                raise RuntimeError(f"Ollama API HTTP {resp.status_code}: {err_text}")

            data = resp.json()
            choice = data.get("message", {}).get("content", "").strip()

            if choice.startswith("```"):
                choice = re.sub(r"^```[a-zA-Z]*\n?", "", choice)
                choice = re.sub(r"\n?```$", "", choice).strip()

            tokens_in = data.get("prompt_eval_count", len(user_prompt.split()))
            tokens_out = data.get("eval_count", len(choice.split()))

            parsed = response_model.model_validate_json(choice)
            return parsed, tokens_in, tokens_out

    async def test_connection(self) -> tuple[bool, str]:
        """Test local Ollama server connectivity."""
        url = f"{self.base_url}/api/tags"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    models_data = resp.json().get("models", [])
                    model_names = [m.get("name") for m in models_data]
                    return True, f"Koneksi Ollama Lokal aktif! Model tersedia: {', '.join(model_names[:3]) or 'None'}"
                return False, f"Ollama HTTP {resp.status_code}: {resp.text}"
        except Exception as exc:  # noqa: BLE001
            return False, f"Tidak dapat terhubung ke Ollama di {self.base_url}: {exc}"

