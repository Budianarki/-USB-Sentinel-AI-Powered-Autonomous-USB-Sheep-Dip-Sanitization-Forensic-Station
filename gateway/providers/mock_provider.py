"""Deterministic Mock LLM Provider for USB Sentinel Gateway."""

import json
import logging
from typing import Any, Literal

from pydantic import BaseModel

from gateway.providers.base import LLMProvider
from sentinel.agents.sanitize import detect_prompt_injection
from sentinel.agents.schemas import AgentVerdict, CritiqueResult

logger = logging.getLogger(__name__)


class MockLLMProvider(LLMProvider):
    """Deterministic, offline LLM provider simulating analysis without network API calls."""

    async def complete_structured(
        self,
        system_prompt: str,
        user_prompt: str,
        response_model: type[BaseModel],
    ) -> tuple[BaseModel, int, int]:
        tokens_in = len(user_prompt.split()) + len(system_prompt.split())
        tokens_out = 50

        # 1. Extract JSON payload and raw untrusted data
        data_block: dict[str, Any] = {}
        raw_inner = ""
        if "<untrusted_data>" in user_prompt and "</untrusted_data>" in user_prompt:
            try:
                raw_inner = (
                    user_prompt.split("<untrusted_data>")[1].split("</untrusted_data>")[0].strip()
                )
                data_block = json.loads(raw_inner)
            except Exception:  # noqa: BLE001
                raw_inner = user_prompt
                data_block = {}
        else:
            raw_inner = user_prompt

        # 2. Scan for prompt injection attempts strictly on untrusted payload
        injection_detected, _matched_patterns = detect_prompt_injection(raw_inner)

        flags = data_block.get("flags", [])
        ext_mismatch = data_block.get("ext_mismatch", False)
        entropy = data_block.get("entropy", 0.0)

        # Generate response based on target model
        if issubclass(response_model, AgentVerdict):
            reasons: list[str] = []
            risk_score = 0.05
            verdict_label: Literal["benign", "suspicious", "malicious", "unknown"] = "benign"

            if injection_detected:
                risk_score = 0.95
                verdict_label = "malicious"
                reasons.append("Prompt injection attack sequence detected in file metadata")
            elif "office_macro_autoexec" in flags:
                risk_score = 0.90
                verdict_label = "malicious"
                reasons.append("Office macro contains AutoExec / Document_Open triggers")
            elif ext_mismatch:
                risk_score = 0.85
                verdict_label = "malicious"
                reasons.append("Executable file disguised with misleading extension")
            elif "pe_packed" in flags or entropy > 7.5:
                risk_score = 0.75
                verdict_label = "suspicious"
                reasons.append("High entropy packed binary indicative of obfuscated payload")
            elif "script_detected" in flags:
                risk_score = 0.65
                verdict_label = "suspicious"
                reasons.append("Automated script detected on removable media")
            else:
                risk_score = 0.05
                verdict_label = "benign"
                reasons.append("No active malicious features observed in static analysis")

            verdict = AgentVerdict(
                agent="mock_analyst",
                file_id=data_block.get("file_id"),
                risk_score=risk_score,
                confidence=0.90,
                verdict=verdict_label,
                reasons=reasons[:8],
                injection_suspected=injection_detected,
            )
            return verdict, tokens_in, tokens_out

        elif issubclass(response_model, CritiqueResult):
            # Critic logic: check if prior verdict was overly lenient
            prior_risk = data_block.get("risk_score", 0.0)
            has_bad_flags = (
                any(f in flags for f in ("office_macro_autoexec", "pe_packed", "script_detected"))
                or ext_mismatch
            )

            if has_bad_flags and prior_risk < 0.40:
                critique = CritiqueResult(
                    agrees=False,
                    counter_arguments=[
                        "Prior analyst failed to weigh suspicious macro/packed flags."
                    ],
                    adjusted_risk_hint=0.85,
                )
            else:
                critique = CritiqueResult(
                    agrees=True,
                    counter_arguments=[],
                    adjusted_risk_hint=prior_risk,
                )
            return critique, tokens_in, tokens_out

        # Fallback empty model
        return response_model(), tokens_in, tokens_out

    async def test_connection(self) -> tuple[bool, str]:
        return True, "Mock LLM Provider aktif (Deterministic Offline Mode)"

