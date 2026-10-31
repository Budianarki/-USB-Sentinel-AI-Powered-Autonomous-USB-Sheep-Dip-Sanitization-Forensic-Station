"""Archive inspection and Zip Bomb / Quota protection (Layer 2).

Reads archive metadata WITHOUT extracting files to disk.
Detects:
- Extreme decompression ratios (Zip bombs like 42.zip)
- Archive quota violations (total uncompressed size, entry count)
- Nested archive depth violations
- Encrypted archives
"""

import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO


@dataclass
class ArchiveInspectionResult:
    """Outcome of archive inspection."""

    is_archive: bool
    is_bomb: bool = False
    quota_exceeded: bool = False
    is_encrypted: bool = False
    file_count: int = 0
    total_compressed_size: int = 0
    total_uncompressed_size: int = 0
    decompress_ratio: float = 1.0
    max_depth: int = 0
    flags: list[str] = field(default_factory=list)


def inspect_archive(
    file_or_path: Path | BinaryIO,
    max_decompress_ratio: float = 100.0,
    max_uncompressed_mb: int = 200,
    max_files_in_archive: int = 5000,
    max_depth: int = 3,
) -> ArchiveInspectionResult:
    """Inspect archive metadata without writing or extracting files to disk.

    Supports ZIP and TAR archives.
    Calculates decompression ratio and enforces resource quotas.
    """
    max_bytes = max_uncompressed_mb * 1024 * 1024

    archive_exts = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar"}
    if isinstance(file_or_path, (str, Path)):
        ext = Path(file_or_path).suffix.lower()
        if ext not in archive_exts:
            return ArchiveInspectionResult(is_archive=False)

    # Try ZIP first
    try:
        if zipfile.is_zipfile(file_or_path):
            return _inspect_zip(
                file_or_path,
                max_decompress_ratio=max_decompress_ratio,
                max_bytes=max_bytes,
                max_files=max_files_in_archive,
                max_depth=max_depth,
            )
    except (zipfile.BadZipFile, OSError):
        pass

    # Try TAR if it's a file path
    try:
        if isinstance(file_or_path, (str, Path)) and tarfile.is_tarfile(str(file_or_path)):
            return _inspect_tar(
                Path(file_or_path),
                max_decompress_ratio=max_decompress_ratio,
                max_bytes=max_bytes,
                max_files=max_files_in_archive,
                max_depth=max_depth,
            )
    except (tarfile.TarError, OSError):
        pass

    return ArchiveInspectionResult(is_archive=False)


def _inspect_zip(
    file_or_path: Path | BinaryIO,
    max_decompress_ratio: float,
    max_bytes: int,
    max_files: int,
    max_depth: int,
) -> ArchiveInspectionResult:
    flags: list[str] = []
    is_bomb = False
    quota_exceeded = False
    is_encrypted = False

    try:
        with zipfile.ZipFile(file_or_path, "r") as zf:
            infolist = zf.infolist()
            total_compressed = 0
            total_uncompressed = 0
            file_count = len(infolist)
            calculated_max_depth = 0

            if file_count > max_files:
                flags.append("archive_entry_count_exceeded")
                quota_exceeded = True
                is_bomb = True

            for info in infolist:
                # Check for encryption flag (bit 0 of flag_bits)
                if info.flag_bits & 0x1:
                    is_encrypted = True

                total_compressed += info.compress_size
                total_uncompressed += info.file_size

                # Track directory depth
                depth = info.filename.strip("/").count("/")
                calculated_max_depth = max(calculated_max_depth, depth)

                # Check per-file extreme decompression ratio
                # (Ignore trivial tiny files < 1024 bytes)
                if info.compress_size > 0 and info.file_size > 1024:
                    per_file_ratio = info.file_size / info.compress_size
                    if per_file_ratio > max_decompress_ratio:
                        flags.append("archive_zip_bomb_entry")
                        is_bomb = True

            if calculated_max_depth > max_depth:
                flags.append("archive_depth_exceeded")
                quota_exceeded = True

            ratio = total_uncompressed / max(1, total_compressed)
            if ratio > max_decompress_ratio:
                flags.append("archive_zip_bomb_ratio")
                is_bomb = True

            if total_uncompressed > max_bytes:
                flags.append("archive_uncompressed_quota_exceeded")
                quota_exceeded = True
                is_bomb = True

            if is_encrypted:
                flags.append("archive_encrypted")

            return ArchiveInspectionResult(
                is_archive=True,
                is_bomb=is_bomb,
                quota_exceeded=quota_exceeded,
                is_encrypted=is_encrypted,
                file_count=file_count,
                total_compressed_size=total_compressed,
                total_uncompressed_size=total_uncompressed,
                decompress_ratio=ratio,
                max_depth=calculated_max_depth,
                flags=flags,
            )

    except (zipfile.BadZipFile, OSError) as exc:
        return ArchiveInspectionResult(
            is_archive=True,
            is_bomb=True,
            flags=[f"archive_corrupt_or_malformed: {exc}"],
        )


def _inspect_tar(
    path: Path,
    max_decompress_ratio: float,
    max_bytes: int,
    max_files: int,
    max_depth: int,
) -> ArchiveInspectionResult:
    flags: list[str] = []
    is_bomb = False
    quota_exceeded = False

    try:
        compressed_size = path.stat().st_size
        total_uncompressed = 0
        file_count = 0
        calculated_max_depth = 0

        with tarfile.open(path, "r:*") as tf:
            for member in tf.getmembers():
                file_count += 1
                if file_count > max_files:
                    flags.append("archive_entry_count_exceeded")
                    quota_exceeded = True
                    is_bomb = True
                    break

                total_uncompressed += member.size
                depth = member.name.strip("/").count("/")
                calculated_max_depth = max(calculated_max_depth, depth)

                if total_uncompressed > max_bytes:
                    flags.append("archive_uncompressed_quota_exceeded")
                    quota_exceeded = True
                    is_bomb = True
                    break

        if calculated_max_depth > max_depth:
            flags.append("archive_depth_exceeded")
            quota_exceeded = True

        ratio = total_uncompressed / max(1, compressed_size)
        if ratio > max_decompress_ratio:
            flags.append("archive_zip_bomb_ratio")
            is_bomb = True

        return ArchiveInspectionResult(
            is_archive=True,
            is_bomb=is_bomb,
            quota_exceeded=quota_exceeded,
            is_encrypted=False,
            file_count=file_count,
            total_compressed_size=compressed_size,
            total_uncompressed_size=total_uncompressed,
            decompress_ratio=ratio,
            max_depth=calculated_max_depth,
            flags=flags,
        )
    except (tarfile.TarError, OSError) as exc:
        return ArchiveInspectionResult(
            is_archive=True,
            is_bomb=True,
            flags=[f"archive_corrupt_or_malformed: {exc}"],
        )
