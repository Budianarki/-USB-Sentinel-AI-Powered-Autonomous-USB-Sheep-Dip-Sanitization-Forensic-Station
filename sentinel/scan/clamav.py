"""ClamAV INSTREAM scanner client and mock scanner (Layer 2).

Implements the official ClamAV clamd INSTREAM protocol:
- Sends stream data chunked: <4-byte length in network order><chunk>
- Terminates with 4-byte 0x00000000
- Parses responses: 'stream: OK' or 'stream: <VirusName> FOUND'
- Enforces scanners_ok=False if ClamAV daemon is unreachable in IoT mode.
- Provides MockClamAvScanner for laptop_mock mode with prominent MOCK labeling.
"""

import logging
import socket
import struct
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# EICAR signature test sequence constructed at runtime (never stored as plain string in repo)
# Invariant: constructed dynamically to avoid false flags by host antivirus
EICAR_MAGIC_CHUNKS = [
    b"X5O!P%@AP[4\\",
    b"PZX54(P^)7CC)7}",
    b"$EICAR-STANDARD-",
    b"ANTIVIRUS-TEST-",
    b"FILE!$H+H*",
]
RUNTIME_EICAR_BYTES = b"".join(EICAR_MAGIC_CHUNKS)

# Safe mock malware test token for cross-platform integration tests (unintercepted by host OS AV)
MOCK_MALWARE_SIG = b"SENTINEL_MOCK_TEST_VIRUS_SIGNATURE"


@dataclass
class ScanStreamResult:
    """Outcome of virus scanning on a data stream."""

    clean: bool
    virus_name: str | None = None
    scanners_ok: bool = True
    error_message: str | None = None
    is_mock: bool = False


class ClamAvScanner:
    """Production ClamAV daemon client communicating via INSTREAM protocol."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 3310,
        socket_path: str | Path | None = None,
        timeout_s: float = 10.0,
    ) -> None:
        self.host = host
        self.port = port
        self.socket_path = str(socket_path) if socket_path else None
        self.timeout_s = timeout_s

    def _connect(self) -> socket.socket:
        """Create socket connection to clamd (UNIX domain socket or TCP)."""
        if self.socket_path and Path(self.socket_path).exists() and hasattr(socket, "AF_UNIX"):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)  # type: ignore[attr-defined]
            sock.settimeout(self.timeout_s)
            sock.connect(self.socket_path)
            return sock

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout_s)
        sock.connect((self.host, self.port))
        return sock

    def is_available(self) -> bool:
        """Ping clamd daemon using PING command."""
        try:
            with self._connect() as sock:
                sock.sendall(b"zPING\0")
                response = sock.recv(1024)
                return b"PONG" in response
        except Exception:  # noqa: BLE001
            return False

    def scan_stream(self, chunk_generator: Iterable[bytes]) -> ScanStreamResult:
        """Stream chunks to clamd via INSTREAM protocol and return verdict."""
        sock: socket.socket | None = None
        try:
            sock = self._connect()
            # Send INSTREAM command
            sock.sendall(b"zINSTREAM\0")

            for chunk in chunk_generator:
                if not chunk:
                    continue
                chunk_len = len(chunk)
                header = struct.pack(">I", chunk_len)
                sock.sendall(header + chunk)

            # Terminate stream with zero length chunk
            sock.sendall(struct.pack(">I", 0))

            # Receive clamd verdict
            response = b""
            while True:
                part = sock.recv(1024)
                if not part:
                    break
                response += part

            resp_str = response.decode("utf-8", errors="replace").strip("\x00\r\n")

            if "OK" in resp_str:
                return ScanStreamResult(clean=True, scanners_ok=True)
            elif "FOUND" in resp_str:
                # Format: "stream: <VirusName> FOUND"
                virus_name = "Threat"
                parts = resp_str.split(":")
                if len(parts) >= 2:
                    virus_name = parts[1].replace("FOUND", "").strip()
                return ScanStreamResult(clean=False, virus_name=virus_name, scanners_ok=True)
            else:
                return ScanStreamResult(
                    clean=False,
                    scanners_ok=False,
                    error_message=f"Unexpected ClamAV response: {resp_str}",
                )

        except Exception as exc:  # noqa: BLE001
            logger.error("ClamAV daemon offline or communication error: %s", exc)
            return ScanStreamResult(
                clean=False,
                scanners_ok=False,
                error_message=f"ClamAV offline or error: {exc}",
            )
        finally:
            if sock:
                sock.close()


class MockClamAvScanner:
    """Mock ClamAV scanner for laptop_mock mode.

    Labels all outputs explicitly with [MOCK] so it can never be mistaken for production.
    Detects runtime-constructed EICAR strings.
    """

    def __init__(self, simulate_daemon_down: bool = False) -> None:
        self.simulate_daemon_down = simulate_daemon_down
        self.is_mock = True

    def is_available(self) -> bool:
        return not self.simulate_daemon_down

    def scan_stream(self, chunk_generator: Iterable[bytes]) -> ScanStreamResult:
        logger.info("[MOCK SCANNER] Evaluating data stream in laptop_mock mode.")
        if self.simulate_daemon_down:
            return ScanStreamResult(
                clean=False,
                scanners_ok=False,
                error_message="[MOCK] Simulated ClamAV offline failure",
                is_mock=True,
            )

        buffer = bytearray()
        for chunk in chunk_generator:
            buffer.extend(chunk)

        # Check for runtime EICAR sequence or safe mock malware token
        if RUNTIME_EICAR_BYTES in buffer or MOCK_MALWARE_SIG in buffer:
            return ScanStreamResult(
                clean=False,
                virus_name="[MOCK] Win.Test.EICAR_HDB-1",
                scanners_ok=True,
                is_mock=True,
            )

        return ScanStreamResult(clean=True, scanners_ok=True, is_mock=True)


def create_clamav_scanner(
    mode: str,
    host: str = "127.0.0.1",
    port: int = 3310,
    socket_path: str | Path | None = None,
) -> ClamAvScanner | MockClamAvScanner:
    """Factory creating appropriate ClamAV scanner based on system mode."""
    if mode == "laptop_mock":
        return MockClamAvScanner()
    return ClamAvScanner(host=host, port=port, socket_path=socket_path)
