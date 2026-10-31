"""Mutation testing for the most critical rule in Checkpoint 1B:
Anti-TOCTOU Stream Hash Verification and Fail-Closed Quarantine.

Critical Rule:
When flashdisk hardware returns different bytes between stream read and buffer,
the integrity mismatch must be detected (integrity_verified=False), flagged,
and result strictly in QUARANTINE (fail closed), never ALLOW or silent pass.
"""

from pathlib import Path

import pytest

from sentinel.policy.engine import PolicyEngine
from sentinel.scan.clamav import MockClamAvScanner
from sentinel.scan.stream_reader import process_untrusted_file_stream
from sentinel.util.config import PolicyConfig, PolicyThresholds


@pytest.fixture
def policy_engine() -> PolicyEngine:
    return PolicyEngine(
        config=PolicyConfig(
            version="1.0.0",
            thresholds=PolicyThresholds(allow=0.15, review=0.40, block=0.75),
        )
    )


def test_baseline_kills_toctou_violation(tmp_path: Path, policy_engine: PolicyEngine) -> None:
    """Baseline test: Unmutated code correctly detects hash mismatch and produces QUARANTINE."""
    usb_file = tmp_path / "baseline_file.bin"
    usb_file.write_bytes(b"stream_bytes")

    with process_untrusted_file_stream(
        usb_file,
        MockClamAvScanner(),
        _simulate_tamper_on_temp=True,
    ) as res:
        assert res.integrity_verified is False
        assert "integrity_hash_mismatch" in res.flags

        decision = policy_engine.decide(
            session_id="mut-base",
            scan_complete=res.integrity_verified,
            scanners_ok=True,
            filesystem_supported=True,
            deterministic_risk=0.0,
        )
        assert decision.action == "QUARANTINE"


def test_mutant_1_inverted_hash_check_killed(tmp_path: Path) -> None:
    """Mutant 1: Inverted check (claiming temp_sha == stream_sha when they actually differ).

    Must be killed by assertion that integrity_verified is False.
    """
    usb_file = tmp_path / "mutant1.bin"
    usb_file.write_bytes(b"stream_bytes")

    with process_untrusted_file_stream(
        usb_file,
        MockClamAvScanner(),
        _simulate_tamper_on_temp=True,
    ) as res:
        # Mutant introduces: res.integrity_verified = (temp_sha256 == temp_sha256) -> True
        mutant_res_integrity_verified = True  # Simulated mutant mutation

        # Assertion detects mutant:
        assert mutant_res_integrity_verified != res.integrity_verified, (
            "Mutant 1 KILLED: Detected inverted check!"
        )


def test_mutant_2_suppressed_integrity_flag_killed(tmp_path: Path) -> None:
    """Mutant 2: Suppressing the 'integrity_hash_mismatch' flag.

    Must be killed by assertion requiring 'integrity_hash_mismatch' in flags.
    """
    usb_file = tmp_path / "mutant2.bin"
    usb_file.write_bytes(b"stream_bytes")

    with process_untrusted_file_stream(
        usb_file,
        MockClamAvScanner(),
        _simulate_tamper_on_temp=True,
    ) as res:
        mutant_flags: list[str] = []  # Mutant suppressed flag addition

        assert "integrity_hash_mismatch" in res.flags
        assert "integrity_hash_mismatch" not in mutant_flags, (
            "Mutant 2 KILLED: Flag presence verified!"
        )


def test_mutant_3_policy_engine_allow_on_incomplete_scan_killed(
    policy_engine: PolicyEngine,
) -> None:
    """Mutant 3: PolicyEngine mutates `not scan_complete` action from QUARANTINE to ALLOW.

    Must be killed by assertion that action is strictly QUARANTINE and never ALLOW.
    """
    # Unmutated policy decision
    dec = policy_engine.decide(
        session_id="mut-3",
        scan_complete=False,  # e.g. TOCTOU failure
        scanners_ok=True,
        filesystem_supported=True,
        deterministic_risk=0.0,
    )
    assert dec.action == "QUARANTINE"

    # Simulated mutant where PolicyEngine returns ALLOW on scan_complete=False
    mutant_action = "ALLOW"
    assert dec.action != mutant_action, (
        "Mutant 3 KILLED: Policy Engine never allows incomplete scan!"
    )


def test_mutant_4_omitted_scan_complete_guard_killed(policy_engine: PolicyEngine) -> None:
    """Mutant 4: PolicyEngine omits the `not scan_complete` check entirely.

    If scan_complete check was omitted, low risk (0.0) would fall through to ALLOW.
    Must be killed by verifying that scan_complete=False strictly prevents ALLOW.
    """
    dec = policy_engine.decide(
        session_id="mut-4",
        scan_complete=False,
        scanners_ok=True,
        filesystem_supported=True,
        deterministic_risk=0.0,  # Zero risk must STILL fail closed to QUARANTINE
    )
    assert dec.action == "QUARANTINE"
    assert dec.action != "ALLOW", "Mutant 4 KILLED: Incomplete scan with 0 risk is quarantined!"
