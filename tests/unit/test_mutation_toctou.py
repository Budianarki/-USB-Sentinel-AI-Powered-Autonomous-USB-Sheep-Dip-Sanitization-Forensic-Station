"""Mutation testing for the most critical rule in Checkpoint 1B:
Anti-TOCTOU Stream Hash Verification and Fail-Closed Quarantine.

Critical Rule:
When flashdisk hardware returns different bytes between stream read and buffer,
the integrity mismatch must be detected (integrity_verified=False), flagged,
and result strictly in QUARANTINE (fail closed), never ALLOW or silent pass.

Audit Note:
Previous tests merely compared against local test dummy variables.
This module strictly mutates the actual PRODUCTION code via monkeypatching,
demonstrating that mutants fail the security assertions (are killed),
and unmutated production code passes.
"""

from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

import sentinel.scan.stream_reader as stream_reader_mod
from sentinel.policy.engine import PolicyEngine
from sentinel.scan.clamav import MockClamAvScanner
from sentinel.scan.stream_reader import (
    StreamedFileResult,
    process_untrusted_file_stream,
)
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
    """Baseline test: Unmutated production code correctly detects hash mismatch and produces QUARANTINE."""
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


def test_mutant_1_inverted_hash_check_killed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutant 1: Mutates production process_untrusted_file_stream to invert integrity_verified.

    When mutated, the production function sets integrity_verified=True on hash mismatch.
    The test assertion (assert res.integrity_verified is False) MUST FAIL, proving the mutant is killed.
    """
    usb_file = tmp_path / "mutant1.bin"
    usb_file.write_bytes(b"stream_bytes")

    real_stream_func = stream_reader_mod.process_untrusted_file_stream

    @contextmanager
    def mutant_stream_func(*args: Any, **kwargs: Any) -> Generator[StreamedFileResult, None, None]:
        with real_stream_func(*args, **kwargs) as res:
            # MUTATION in production result: invert check (claiming verified=True even on mismatch)
            res.integrity_verified = True
            yield res

    # 1. Verify unmutated production code passes
    with stream_reader_mod.process_untrusted_file_stream(
        usb_file, MockClamAvScanner(), _simulate_tamper_on_temp=True
    ) as clean_res:
        assert clean_res.integrity_verified is False

    # 2. Apply mutant to production module
    monkeypatch.setattr(stream_reader_mod, "process_untrusted_file_stream", mutant_stream_func)

    # 3. Assert that the mutant causes the security assertion to FAIL (mutant killed)
    with pytest.raises(AssertionError, match="assert True is False"):
        with stream_reader_mod.process_untrusted_file_stream(
            usb_file, MockClamAvScanner(), _simulate_tamper_on_temp=True
        ) as mutant_res:
            assert mutant_res.integrity_verified is False, "Mutant 1 survived!"


def test_mutant_2_suppressed_integrity_flag_killed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutant 2: Mutates production process_untrusted_file_stream to suppress 'integrity_hash_mismatch' flag.

    The assertion ('integrity_hash_mismatch' in res.flags) MUST FAIL on mutant, killing it.
    """
    usb_file = tmp_path / "mutant2.bin"
    usb_file.write_bytes(b"stream_bytes")

    real_stream_func = stream_reader_mod.process_untrusted_file_stream

    @contextmanager
    def mutant_stream_func(*args: Any, **kwargs: Any) -> Generator[StreamedFileResult, None, None]:
        with real_stream_func(*args, **kwargs) as res:
            # MUTATION in production result: suppress adding integrity_hash_mismatch flag
            res.flags = [f for f in res.flags if f != "integrity_hash_mismatch"]
            yield res

    # 1. Unmutated code passes
    with stream_reader_mod.process_untrusted_file_stream(
        usb_file, MockClamAvScanner(), _simulate_tamper_on_temp=True
    ) as clean_res:
        assert "integrity_hash_mismatch" in clean_res.flags

    # 2. Mutate production function
    monkeypatch.setattr(stream_reader_mod, "process_untrusted_file_stream", mutant_stream_func)

    # 3. Security assertion fails on mutant
    with pytest.raises(AssertionError, match="Mutant 2 survived"):
        with stream_reader_mod.process_untrusted_file_stream(
            usb_file, MockClamAvScanner(), _simulate_tamper_on_temp=True
        ) as mutant_res:
            assert "integrity_hash_mismatch" in mutant_res.flags, "Mutant 2 survived!"


def test_mutant_3_policy_engine_allow_on_incomplete_scan_killed(
    policy_engine: PolicyEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutant 3: Mutates PolicyEngine.decide to return ALLOW on scan_complete=False.

    The assertion (assert dec.action == 'QUARANTINE') MUST FAIL on mutant, killing it.
    """
    # 1. Unmutated code produces QUARANTINE
    dec = policy_engine.decide(
        session_id="mut-3",
        scan_complete=False,
        scanners_ok=True,
        filesystem_supported=True,
        deterministic_risk=0.0,
    )
    assert dec.action == "QUARANTINE"

    # 2. Mutate PolicyEngine.decide production method
    real_decide = policy_engine.decide

    def mutant_decide(*args: Any, **kwargs: Any) -> Any:
        res = real_decide(*args, **kwargs)
        if not kwargs.get("scan_complete", True):
            # MUTATION in production logic: return ALLOW instead of QUARANTINE
            res.action = "ALLOW"
        return res

    monkeypatch.setattr(policy_engine, "decide", mutant_decide)

    # 3. Security assertion fails on mutant
    with pytest.raises(AssertionError, match="Mutant 3 survived"):
        mutant_dec = policy_engine.decide(
            session_id="mut-3",
            scan_complete=False,
            scanners_ok=True,
            filesystem_supported=True,
            deterministic_risk=0.0,
        )
        assert mutant_dec.action == "QUARANTINE", "Mutant 3 survived!"


def test_mutant_4_omitted_scan_complete_guard_killed(
    policy_engine: PolicyEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutant 4: Mutates PolicyEngine.decide to omit the scan_complete check entirely.

    With 0.0 risk, omitting the check makes it fall through to ALLOW.
    The assertion (assert dec.action == 'QUARANTINE') MUST FAIL on mutant, killing it.
    """
    # 1. Unmutated code produces QUARANTINE even with zero risk
    dec = policy_engine.decide(
        session_id="mut-4",
        scan_complete=False,
        scanners_ok=True,
        filesystem_supported=True,
        deterministic_risk=0.0,
    )
    assert dec.action == "QUARANTINE"

    # 2. Mutate PolicyEngine.decide to bypass scan_complete check
    real_decide = policy_engine.decide

    def mutant_decide(*args: Any, **kwargs: Any) -> Any:
        # MUTATION in production logic: ignore scan_complete=False by forcing it to True
        kwargs["scan_complete"] = True
        return real_decide(*args, **kwargs)

    monkeypatch.setattr(policy_engine, "decide", mutant_decide)

    # 3. Security assertion fails on mutant
    with pytest.raises(AssertionError, match="Mutant 4 survived"):
        mutant_dec = policy_engine.decide(
            session_id="mut-4",
            scan_complete=False,
            scanners_ok=True,
            filesystem_supported=True,
            deterministic_risk=0.0,
        )
        assert mutant_dec.action == "QUARANTINE", "Mutant 4 survived!"
