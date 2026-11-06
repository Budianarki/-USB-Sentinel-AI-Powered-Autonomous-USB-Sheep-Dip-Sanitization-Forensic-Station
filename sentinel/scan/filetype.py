"""File type detection via magic bytes and extension verification (Layer 2).

Determines actual file format from raw header bytes rather than untrusted extensions.
Flags extension mismatches (e.g., invoice.pdf containing an MZ executable).
"""

import math
from dataclasses import dataclass, field
from pathlib import Path

MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"%PDF-", "pdf"),
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole_compound"),
    (b"PK\x03\x04", "zip"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x4c\x00\x00\x00", "lnk"),
]

SCRIPT_EXTENSIONS = {
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".sh",
    ".py",
    ".bash",
    ".wsf",
    ".hta",
    ".inf",
}
EXEC_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".cpl", ".bin"}
DANGEROUS_DOUBLE_TARGETS = {"pdf", "docx", "xlsx", "pptx", "jpg", "jpeg", "png", "txt", "mp4", "mp3"}


@dataclass
class TypeDetectionResult:
    detected_type: str
    ext_mismatch: bool
    entropy: float
    flags: list[str] = field(default_factory=list)


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data (0.0 to 8.0)."""
    if not data:
        return 0.0

    length = len(data)
    frequencies: dict[int, int] = {}
    for b in data:
        frequencies[b] = frequencies.get(b, 0) + 1

    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def detect_file_type(
    header: bytes, filename: str, sample_data: bytes | None = None
) -> TypeDetectionResult:
    """Identify file format by inspecting initial header bytes and compare with extension."""
    flags: list[str] = []
    ext = Path(filename).suffix.lower()
    detected_type = "unknown"

    # Check magic signatures
    for sig, ftype in MAGIC_SIGNATURES:
        if header.startswith(sig):
            detected_type = ftype
            break

    # OOXML refinement (DOCX/XLSX/PPTX are zip files)
    if detected_type == "zip" and sample_data:
        if b"word/" in sample_data:
            detected_type = "docx"
        elif b"xl/" in sample_data:
            detected_type = "xlsx"
        elif b"ppt/" in sample_data:
            detected_type = "pptx"

    # Text / Script fallback
    if detected_type == "unknown":
        if header.startswith(b"#!") or ext in SCRIPT_EXTENSIONS:
            detected_type = "script"
        else:
            # Check if majority is readable ASCII
            if header and all(32 <= b <= 126 or b in (9, 10, 13) for b in header[:128]):
                detected_type = "txt"

    # Check double extension deception (e.g., invoice.pdf.exe, tender.xlsx.vbs)
    parts = Path(filename).name.split(".")
    if len(parts) >= 3:
        inner_ext = parts[-2].lower()
        outer_ext = parts[-1].lower()
        if inner_ext in DANGEROUS_DOUBLE_TARGETS and (
            f".{outer_ext}" in EXEC_EXTENSIONS or f".{outer_ext}" in SCRIPT_EXTENSIONS
        ):
            flags.append("double_extension_deception")
            flags.append(f"disguised_as_{inner_ext}")

    # Check Autorun
    if Path(filename).name.lower() == "autorun.inf":
        flags.append("autorun_inf_present")
        detected_type = "autorun"

    # Check Windows Shortcut (.lnk)
    if ext == ".lnk" or detected_type == "lnk":
        flags.append("windows_shortcut_detected")

    # Check Ransomware Note / Encrypted extension
    lower_fname = filename.lower()
    if any(k in lower_fname for k in ["readme_decrypt", "restore_files", "how_to_recover", "decrypt_files"]):
        flags.append("ransomware_note_detected")
    if ext in (".locked", ".crypto", ".crypted", ".enc"):
        flags.append("ransomware_encrypted_extension")

    # Extension mismatch logic
    ext_mismatch = False
    clean_ext = ext.lstrip(".")

    # Flag critical dangerous mismatches
    if detected_type in ("pe", "elf"):
        if clean_ext not in ("exe", "dll", "sys", "bin", "elf", "so", "scr", "com"):
            ext_mismatch = True
            flags.append("type_mismatch")
            flags.append(f"executable_disguised_as_{clean_ext or 'none'}")
    elif (
        detected_type == "pdf"
        and clean_ext != "pdf"
        or detected_type in ("docx", "xlsx", "pptx")
        and clean_ext != detected_type
    ):
        ext_mismatch = True
        flags.append("type_mismatch")

    if ext in SCRIPT_EXTENSIONS:
        flags.append("script_detected")

    data_to_measure = sample_data if sample_data is not None else header
    entropy = calculate_entropy(data_to_measure)

    # Packed / encrypted detection threshold
    if entropy > 7.5:
        flags.append("high_entropy")

    return TypeDetectionResult(
        detected_type=detected_type,
        ext_mismatch=ext_mismatch,
        entropy=entropy,
        flags=flags,
    )
