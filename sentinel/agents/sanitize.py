"""Prompt sanitization and prompt injection defense for AI Agent Layer (Invariant 5 & 10).

Protects against:
- Prompt injection attempts within filenames, strings, and metadata
- Delimiter escape sequences (<system>, [INST], </untrusted_data>, ```)
- Jailbreak patterns (DAN mode, disregard instructions, bypass policy)
- Control characters and excessive input lengths
"""

import json
import re
from typing import Any

INJECTION_PATTERNS = [
    r"(?i)\bignore[\s_-]+(all[\s_-]+)?(previous|prior|above)[\s_-]+instructions\b",
    r"(?i)\bdisregard[\s_-]+(all[\s_-]+)?(previous|prior|above)\b",
    r"(?i)\byou[\s_-]+are[\s_-]+now[\s_-]+(in[\s_-]+)?(developer|dan|god|unrestricted)[\s_-]+mode\b",
    r"(?i)\bdo[\s_-]+anything[\s_-]+now\b",
    r"(?i)\bbypass[\s_-]+(all[\s_-]+)?(security|policy|restrictions|rules)\b",
    r"(?i)\bnew[\s_-]+system[\s_-]+prompt\b",
    r"(?i)\bsystem[\s_-]*:[\s_-]*you[\s_-]+are\b",
    r"(?i)\[system\]",
    r"(?i)\[inst\]",
    r"(?i)<\/?system>",
    r"(?i)<\/?instruction>",
    r"(?i)<\/?untrusted_data>",
    r"(?i)&lt;\/?untrusted_data&gt;",
    r"(?i)\bverdict[\s_-]*:[\s_-]*benign\b",
    r"(?i)\brisk_score[\s_-]*:[\s_-]*0\b",
    r"(?i)\bclassify[\s_-]+(this[\s_-]+file[\s_-]+as[\s_-]+)?clean\b",
    r"(?i)\bpretend[\s_-]+you[\s_-]+are\b",
]

COMPILED_INJECTION_REGEX = [re.compile(p) for p in INJECTION_PATTERNS]


def detect_prompt_injection(text: str) -> tuple[bool, list[str]]:
    """Scan untrusted string for prompt injection indicators.

    Returns:
        (injection_suspected: bool, matched_patterns: list[str])
    """
    if not text:
        return False, []

    # Normalize underscores and hyphens to spaces to catch snake_case and kebab-case injections in filenames
    normalized = text.replace("_", " ").replace("-", " ")

    matches: list[str] = []
    for pattern, regex in zip(INJECTION_PATTERNS, COMPILED_INJECTION_REGEX, strict=True):
        if regex.search(text) or regex.search(normalized):
            matches.append(pattern)

    return len(matches) > 0, matches


def sanitize_for_prompt(data: Any, max_length: int = 1500) -> str:
    """Sanitize arbitrary data object for safe insertion into LLM prompts.

    - Converts structures to clean JSON
    - Strips control characters
    - Escapes dangerous delimiters
    - Truncates to max_length
    """
    if isinstance(data, (dict, list)):
        raw_text = json.dumps(data, ensure_ascii=True, default=str)
    else:
        raw_text = str(data)

    # 1. Neutralize XML tags that could mimic delimiters
    sanitized = raw_text.replace("<", "&lt;").replace(">", "&gt;")

    # 2. Neutralize markdown backticks that could break prompt codeblocks
    sanitized = sanitized.replace("```", "'''")

    # 3. Strip non-printable ASCII control characters (keep newline and tab)
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", sanitized)

    # 4. Truncate
    if len(sanitized) > max_length:
        sanitized = sanitized[: max_length - 3] + "..."

    return sanitized


def wrap_untrusted_data(label: str, content: str) -> str:
    """Enclose sanitized untrusted data in an explicit data boundary tag.

    Instructs the LLM that content inside this tag is passive DATA, NOT instructions.
    """
    clean_label = re.sub(r"[^a-zA-Z0-9_]", "", label) or "untrusted_data"
    return f"<{clean_label}>\n{content}\n</{clean_label}>"
