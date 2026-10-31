"""Unit tests for filename sanitization and Unicode BiDi defense."""

from sentinel.scan.sanitize import sanitize_filename


def test_benign_filename_remains_clean() -> None:
    res = sanitize_filename("annual_report_2026.pdf")
    assert res.sanitized_name == "annual_report_2026.pdf"
    assert res.flags == []
    assert not res.bidi_detected
    assert not res.traversal_detected


def test_unicode_rlo_extension_spoofing_detected_and_neutralized() -> None:
    # Classic malware trick: "invoice_\u202edpx.exe" displays as "invoice_exe.xpd"
    spoofed = "invoice_\u202edpx.exe"
    res = sanitize_filename(spoofed)
    assert res.bidi_detected is True
    assert "unicode_bidi_override" in res.flags
    assert "\u202e" not in res.sanitized_name
    assert res.sanitized_name == "invoice_dpx.exe"


def test_path_traversal_in_filename_detected_and_neutralized() -> None:
    res = sanitize_filename("../../etc/passwd")
    assert res.traversal_detected is True
    assert "path_traversal_name" in res.flags
    assert "/" not in res.sanitized_name
    assert ".." not in res.sanitized_name


def test_null_bytes_and_control_characters_stripped() -> None:
    malformed = "evil_payload.pdf\x00.exe\x07\x1b"
    res = sanitize_filename(malformed)
    assert res.control_chars_detected is True
    assert "control_chars_in_name" in res.flags
    assert "\x00" not in res.sanitized_name
    assert "\x07" not in res.sanitized_name
    assert "\x1b" not in res.sanitized_name


def test_zero_width_spaces_detected_and_stripped() -> None:
    hidden = "secure\u200bdocument\ufeff.docx"
    res = sanitize_filename(hidden)
    assert "zero_width_chars_in_name" in res.flags
    assert "\u200b" not in res.sanitized_name
    assert "\ufeff" not in res.sanitized_name
    assert res.sanitized_name == "securedocument.docx"


def test_excessively_long_filename_truncated() -> None:
    long_name = "a" * 300 + ".txt"
    res = sanitize_filename(long_name, max_length=50)
    assert len(res.sanitized_name) == 50
    assert res.sanitized_name.endswith("...")
