"""Filename sanitization and Unicode security defense for Layer 2.

Protects against:
- Unicode Right-to-Left Override (RLO) and BiDi spoofing attacks (e.g. evil\u202edpx.exe)
- Zero-width and hidden control characters
- ASCII control characters and null bytes
- Path traversal sequences (../, ..\\) in filenames
"""

import re
from dataclasses import dataclass, field

# Unicode BiDi control characters used in extension spoofing attacks
BIDI_CHARS = {
    "\u202a": "LRE",  # Left-to-Right Embedding
    "\u202b": "RLE",  # Right-to-Left Embedding
    "\u202c": "PDF",  # Pop Directional Formatting
    "\u202d": "LRO",  # Left-to-Right Override
    "\u202e": "RLO",  # Right-to-Left Override (Critical extension spoofing weapon)
    "\u2066": "LRI",  # Left-to-Right Isolate
    "\u2067": "RLI",  # Right-to-Left Isolate
    "\u2068": "FSI",  # First Strong Isolate
    "\u2069": "PDI",  # Pop Directional Isolate
    "\u200e": "LRM",  # Left-to-Right Mark
    "\u200f": "RLM",  # Right-to-Left Mark
    "\u061c": "ALM",  # Arabic Letter Mark
}

# Zero-width / invisible characters
ZERO_WIDTH_CHARS = {
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\ufeff",  # Zero-width no-break space / BOM
    "\u00ad",  # Soft hyphen
}


@dataclass
class SanitizedNameResult:
    """Outcome of filename sanitization."""

    original_name: str
    sanitized_name: str
    flags: list[str] = field(default_factory=list)
    bidi_detected: bool = False
    traversal_detected: bool = False
    control_chars_detected: bool = False


def sanitize_filename(filename: str, max_length: int = 255) -> SanitizedNameResult:
    """Sanitize an untrusted filename extracted from USB media.

    Strips control characters, strips BiDi overrides and zero-width chars,
    neutralizes directory separators, and flags malicious spoofing patterns.
    """
    flags: list[str] = []
    bidi_detected = False
    traversal_detected = False
    control_chars_detected = False

    # 1. Detect BiDi control overrides
    detected_bidi = [char for char in filename if char in BIDI_CHARS]
    if detected_bidi:
        bidi_detected = True
        flags.append("unicode_bidi_override")

    # 2. Detect zero-width characters
    has_zero_width = any(char in ZERO_WIDTH_CHARS for char in filename)
    if has_zero_width:
        flags.append("zero_width_chars_in_name")

    # 3. Detect path traversal patterns in the name
    if ".." in filename or "/" in filename or "\\" in filename:
        traversal_detected = True
        flags.append("path_traversal_name")

    # 4. Detect control characters (\x00-\x1f, \x7f)
    if any(ord(c) < 32 or ord(c) == 127 for c in filename):
        control_chars_detected = True
        flags.append("control_chars_in_name")

    # Strip dangerous characters
    cleaned = filename
    # Remove BiDi chars
    for bidi_char in BIDI_CHARS:
        cleaned = cleaned.replace(bidi_char, "")
    # Remove zero-width chars
    for zw_char in ZERO_WIDTH_CHARS:
        cleaned = cleaned.replace(zw_char, "")
    # Replace path separators and nulls with underscores
    cleaned = cleaned.replace("/", "_").replace("\\", "_").replace("\x00", "")
    # Strip remaining ASCII control chars
    cleaned = re.sub(r"[\x01-\x1f\x7f]", "", cleaned)

    # Neutralize any directory traversal sequences
    while ".." in cleaned:
        cleaned = cleaned.replace("..", "_")

    # Strip leading/trailing whitespaces and dots (Windows/FAT evasion)
    cleaned = cleaned.strip(". _")

    if not cleaned:
        cleaned = "unnamed_file"

    # Truncate to max_length
    if len(cleaned) > max_length:
        cleaned = cleaned[: max_length - 3] + "..."

    return SanitizedNameResult(
        original_name=filename,
        sanitized_name=cleaned,
        flags=flags,
        bidi_detected=bidi_detected,
        traversal_detected=traversal_detected,
        control_chars_detected=control_chars_detected,
    )
