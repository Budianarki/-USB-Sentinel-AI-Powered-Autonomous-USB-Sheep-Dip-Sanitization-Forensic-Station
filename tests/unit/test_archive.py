"""Unit tests for archive inspection and zip bomb defense."""

import zipfile
from pathlib import Path

from sentinel.scan.archive import inspect_archive


def test_normal_zip_archive_passes(tmp_path: Path) -> None:
    zip_path = tmp_path / "normal.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test1.txt", "Hello World! " * 50)
        zf.writestr("test2.txt", "Some regular data content.")

    res = inspect_archive(zip_path, max_decompress_ratio=100.0)
    assert res.is_archive is True
    assert res.is_bomb is False
    assert res.quota_exceeded is False
    assert res.file_count == 2
    assert res.decompress_ratio < 100.0


def test_zip_bomb_extreme_ratio_detected(tmp_path: Path) -> None:
    # Create a synthetic zip bomb: highly compressible repeated byte buffer
    # 500 KB of zeros compresses to ~500 bytes (ratio > 1000:1)
    zip_path = tmp_path / "bomb.zip"
    payload = b"0" * 500_000

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("huge_file.dat", payload)

    res = inspect_archive(zip_path, max_decompress_ratio=50.0)
    assert res.is_archive is True
    assert res.is_bomb is True
    assert "archive_zip_bomb_ratio" in res.flags or "archive_zip_bomb_entry" in res.flags
    assert res.decompress_ratio > 50.0


def test_archive_entry_count_quota_exceeded(tmp_path: Path) -> None:
    zip_path = tmp_path / "many_files.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED) as zf:
        for i in range(15):
            zf.writestr(f"file_{i}.txt", f"data {i}")

    # Set quota threshold to max 10 files
    res = inspect_archive(zip_path, max_files_in_archive=10)
    assert res.is_archive is True
    assert res.quota_exceeded is True
    assert "archive_entry_count_exceeded" in res.flags


def test_non_archive_file_returns_not_archive(tmp_path: Path) -> None:
    text_file = tmp_path / "readme.txt"
    text_file.write_text("Just plain text.")

    res = inspect_archive(text_file)
    assert res.is_archive is False
    assert res.is_bomb is False
