"""Anti-TOCTOU single-pass streaming reader and temporary RAM working copy (Layer 2).

Protects against untrusted USB hardware (e.g. Facedancer / BadUSB devices) that may
return different bytes on subsequent reads:
- Reads file from USB storage EXACTLY ONCE via streaming.
- Simultaneously computes SHA256 and streams chunks to ClamAV via INSTREAM.
- Writes chunks to a bounded temporary working copy in tmpfs/RAM.
- Verifies SHA256 of the temporary working copy against the stream hash.
- If hash differs -> flags 'integrity_hash_mismatch' (triggers QUARANTINE).
- Cleans up and deletes temporary working copy immediately after static analysis.
"""

import hashlib
import logging
import os
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.scan.clamav import ClamAvScanner, MockClamAvScanner, ScanStreamResult

logger = logging.getLogger(__name__)


@dataclass
class StreamedFileResult:
    """Outcome of single-pass stream read, hash calculation, and AV scan."""

    sha256: str
    size: int
    av_result: ScanStreamResult
    temp_path: Path | None
    integrity_verified: bool
    quota_exceeded: bool = False
    flags: list[str] = field(default_factory=list)


def get_ram_tmp_dir() -> Path:
    """Return path to RAM-backed tmpfs (/dev/shm on Linux) or system temp directory."""
    shm_path = Path("/dev/shm")
    if shm_path.exists() and os.access(shm_path, os.W_OK):
        return shm_path
    return Path(tempfile.gettempdir())


@contextmanager
def process_untrusted_file_stream(
    usb_file_path: Path,
    clamav_scanner: ClamAvScanner | MockClamAvScanner,
    max_file_mb: int = 200,
    chunk_size: int = 65536,  # 64 KB
    _simulate_tamper_on_temp: bool = False,  # For fault injection tests
) -> Generator[StreamedFileResult, None, None]:
    """Single-pass streaming reader for untrusted USB media.

    Yields StreamedFileResult with temporary copy in RAM for static analysis,
    then automatically deletes the temporary file upon exit.
    """
    tmp_dir = get_ram_tmp_dir()
    max_bytes = max_file_mb * 1024 * 1024

    # Create temporary working copy in RAM/tmpfs
    tmp_fd, tmp_path_str = tempfile.mkstemp(prefix="sentinel_work_", dir=str(tmp_dir))
    tmp_path = Path(tmp_path_str)
    flags: list[str] = []
    quota_exceeded = False

    try:
        hasher = hashlib.sha256()
        total_bytes = 0

        with (
            open(tmp_fd, "wb", closefd=True) as tmp_file,
            open(usb_file_path, "rb") as usb_stream,
        ):

            def _chunk_generator() -> Generator[bytes, None, None]:
                nonlocal total_bytes, quota_exceeded
                while True:
                    chunk = usb_stream.read(chunk_size)
                    if not chunk:
                        break

                    total_bytes += len(chunk)
                    if total_bytes > max_bytes:
                        quota_exceeded = True
                        flags.append("file_size_quota_exceeded")
                        break

                    hasher.update(chunk)
                    tmp_file.write(chunk)
                    yield chunk

            # Stream to ClamAV via INSTREAM
            av_result = clamav_scanner.scan_stream(_chunk_generator())

        stream_sha256 = hasher.hexdigest()

        # Fault injection simulation: simulate bytes differing on disk
        if _simulate_tamper_on_temp:
            tmp_path.write_bytes(b"tampered_payload_different_from_stream")

        # Verify integrity of written temporary file
        verify_hasher = hashlib.sha256()
        with open(tmp_path, "rb") as f:
            while True:
                buf = f.read(chunk_size)
                if not buf:
                    break
                verify_hasher.update(buf)

        temp_sha256 = verify_hasher.hexdigest()

        if temp_sha256 != stream_sha256:
            logger.critical(
                "TOCTOU Integrity Violation: Temporary copy hash %s does not match stream hash %s!",
                temp_sha256,
                stream_sha256,
            )
            integrity_verified = False
            flags.append("integrity_hash_mismatch")
        else:
            integrity_verified = True

        result = StreamedFileResult(
            sha256=stream_sha256,
            size=total_bytes,
            av_result=av_result,
            temp_path=tmp_path,
            integrity_verified=integrity_verified,
            quota_exceeded=quota_exceeded,
            flags=flags,
        )

        yield result

    finally:
        # Guarantee cleanup: temporary file is strictly working copy, deleted immediately
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError as exc:
                logger.warning("Failed to remove temporary working file %s: %s", tmp_path, exc)
