"""Forensic utilities for USB Sentinel: Hex dump, Entropy curve, and String extraction."""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any


def get_file_forensics(file_path: Path, max_bytes: int = 2048) -> dict[str, Any]:
    """Extract deep forensic features from a file for inspection."""
    if not file_path.exists() or not file_path.is_file():
        return {
            "error": f"File '{file_path}' does not exist or is not a regular file.",
            "exists": False,
        }

    raw = file_path.read_bytes()
    size = len(raw)

    # 1. Hex Dump (up to max_bytes)
    sample = raw[:max_bytes]
    hex_lines = []
    for i in range(0, len(sample), 16):
        chunk = sample[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        hex_lines.append({
            "offset": f"{i:08x}",
            "hex": hex_part.ljust(48),
            "ascii": ascii_part,
        })

    # 2. Shannon Entropy per 64-byte block
    block_size = 64
    entropy_blocks: list[float] = []
    for i in range(0, len(raw), block_size):
        blk = raw[i : i + block_size]
        if not blk:
            continue
        freq: dict[int, int] = {}
        for b in blk:
            freq[b] = freq.get(b, 0) + 1
        ent = 0.0
        for count in freq.values():
            p = count / len(blk)
            ent -= p * math.log2(p)
        entropy_blocks.append(round(ent, 2))

    if not entropy_blocks:
        entropy_blocks = [0.0]

    # Total file Shannon entropy
    total_freq: dict[int, int] = {}
    for b in raw:
        total_freq[b] = total_freq.get(b, 0) + 1
    total_entropy = 0.0
    if raw:
        for count in total_freq.values():
            p = count / len(raw)
            total_entropy -= p * math.log2(p)

    # 3. Printable Strings (URLs, IP, APIs, scripts)
    pattern = re.compile(rb"[\x20-\x7e]{4,}")
    raw_strings = pattern.findall(raw)
    strings_found: list[str] = []
    for s in raw_strings[:60]:
        try:
            strings_found.append(s.decode("ascii", errors="replace"))
        except (UnicodeDecodeError, ValueError):
            continue

    # Detect high-signal tokens
    suspicious_tokens: list[str] = []
    lower_raw = raw.lower()
    signals = [
        b"autoexec",
        b"document_open",
        b"workbook_open",
        b"powershell",
        b"-encodedcommand",
        b"cmd.exe",
        b"wscript",
        b"cscript",
        b"downloadstring",
        b"invoke-expression",
        b"virtualalloc",
        b"writeprocessmemory",
        b"eicar",
        b"reg add",
    ]
    for sig in signals:
        if sig in lower_raw:
            suspicious_tokens.append(sig.decode("ascii", errors="replace"))

    return {
        "exists": True,
        "name": file_path.name,
        "size_bytes": size,
        "total_entropy": round(total_entropy, 4),
        "entropy_blocks": entropy_blocks[:32],  # sample up to 32 blocks
        "hex_lines": hex_lines,
        "strings": strings_found,
        "suspicious_tokens": suspicious_tokens,
    }
