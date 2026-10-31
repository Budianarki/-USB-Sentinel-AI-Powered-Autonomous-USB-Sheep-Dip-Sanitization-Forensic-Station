"""Unit and Property-based tests for Policy Engine (Layer 4).

Validates full decision matrix and enforces Invariants 1, 2, and 3.
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sentinel.policy.engine import PolicyEngine
from sentinel.policy.schemas import Decision
from sentinel.util.config import PolicyConfig, PolicyThresholds


@pytest.fixture
def policy_engine() -> PolicyEngine:
    config = PolicyConfig(
        version="1.0.0",
        thresholds=PolicyThresholds(allow=0.15, review=0.40, block=0.75),
    )
    return PolicyEngine(config=config)


# --- Unit Tests for Decision Matrix ---


def test_device_guard_blocked_yields_block(policy_engine: PolicyEngine) -> None:
    """Device guard violation must always produce BLOCK with alarm severity."""
    dec = policy_engine.decide(
        session_id="test-1",
        scan_complete=True,
        scanners_ok=True,
        filesystem_supported=True,
        device_guard_blocked=True,
        deterministic_risk=0.0,
    )
    assert dec.action == "BLOCK"
    assert "Device guard" in dec.deterministic_reasons[0]


def test_av_or_yara_hit_yields_block(policy_engine: PolicyEngine) -> None:
    """AV or YARA hit must always produce BLOCK."""
    dec = policy_engine.decide(
        session_id="test-2",
        scan_complete=True,
        scanners_ok=True,
        filesystem_supported=True,
        av_or_yara_hit=True,
        deterministic_risk=0.1,
    )
    assert dec.action == "BLOCK"
    assert "Antivirus or YARA" in dec.deterministic_reasons[0]


def test_high_risk_yields_block(policy_engine: PolicyEngine) -> None:
    """Risk at or above block threshold (0.75) must produce BLOCK."""
    dec = policy_engine.decide(
        session_id="test-3",
        scan_complete=True,
        scanners_ok=True,
        filesystem_supported=True,
        deterministic_risk=0.75,
    )
    assert dec.action == "BLOCK"


def test_critic_disagreement_escalates_to_human_review(policy_engine: PolicyEngine) -> None:
    """Critic disagreement must escalate to HUMAN_REVIEW even if risk is below review threshold."""
    dec = policy_engine.decide(
        session_id="test-4",
        scan_complete=True,
        scanners_ok=True,
        filesystem_supported=True,
        deterministic_risk=0.20,
        critic_disagreement=True,
    )
    assert dec.action == "HUMAN_REVIEW"
    assert "Critic agent disagreed" in dec.deterministic_reasons[0]


def test_moderate_risk_yields_human_review(policy_engine: PolicyEngine) -> None:
    """Risk at or above review threshold (0.40) must produce HUMAN_REVIEW."""
    dec = policy_engine.decide(
        session_id="test-5",
        scan_complete=True,
        scanners_ok=True,
        filesystem_supported=True,
        deterministic_risk=0.50,
    )
    assert dec.action == "HUMAN_REVIEW"


def test_risky_type_ai_unavailable_fails_closed_to_quarantine(policy_engine: PolicyEngine) -> None:
    """Invariant 2: Risky file type when AI is unavailable must fail-closed to QUARANTINE."""
    dec = policy_engine.decide(
        session_id="test-6",
        scan_complete=True,
        scanners_ok=True,
        filesystem_supported=True,
        deterministic_risk=0.10,
        has_risky_type=True,
        ai_available=False,
    )
    assert dec.action == "QUARANTINE"
    assert "fail-closed" in dec.deterministic_reasons[0]


def test_clean_session_yields_allow(policy_engine: PolicyEngine) -> None:
    """Low risk and no risky types must produce ALLOW."""
    dec = policy_engine.decide(
        session_id="test-7",
        scan_complete=True,
        scanners_ok=True,
        filesystem_supported=True,
        deterministic_risk=0.05,
        ai_risk=0.05,
        ai_available=True,
        has_risky_type=False,
    )
    assert dec.action == "ALLOW"


def test_mandatory_scan_parameters_enforced(policy_engine: PolicyEngine) -> None:
    """scan_complete, scanners_ok, filesystem_supported must be required keyword-only args."""
    with pytest.raises(TypeError):
        # Missing required keyword arguments
        policy_engine.decide("test-missing")  # type: ignore[call-arg]


def test_aggregate_session_decisions_worst_case(policy_engine: PolicyEngine) -> None:
    """Session decision must reflect the worst decision across all files."""
    d_allow = Decision(session_id="s1", action="ALLOW", risk=0.05, policy_version="1.0.0")
    d_quarantine = Decision(session_id="s1", action="QUARANTINE", risk=0.60, policy_version="1.0.0")
    d_block = Decision(session_id="s1", action="BLOCK", risk=0.95, policy_version="1.0.0")

    # Allow + Quarantine -> Quarantine
    res1 = policy_engine.aggregate_session_decisions("s1", [d_allow, d_quarantine])
    assert res1.action == "QUARANTINE"
    assert res1.risk == 0.60

    # Allow + Quarantine + Block -> Block
    res2 = policy_engine.aggregate_session_decisions("s1", [d_allow, d_quarantine, d_block])
    assert res2.action == "BLOCK"
    assert res2.risk == 0.95


# --- Property-Based Tests (Hypothesis) ---


DEFAULT_ENGINE = PolicyEngine(
    config=PolicyConfig(
        version="1.0.0",
        thresholds=PolicyThresholds(allow=0.15, review=0.40, block=0.75),
    )
)


@given(
    det_risk=st.floats(min_value=0.0, max_value=1.0),
    ai_risk=st.floats(min_value=0.0, max_value=1.0),
    ai_available=st.booleans(),
)
def test_property_invariant_1_monotonic_escalation(
    det_risk: float,
    ai_risk: float,
    ai_available: bool,
) -> None:
    """Invariant 1: final_risk must ALWAYS be >= deterministic_risk for all inputs."""
    dec = DEFAULT_ENGINE.decide(
        session_id="prop-1",
        scan_complete=True,
        scanners_ok=True,
        filesystem_supported=True,
        deterministic_risk=det_risk,
        ai_risk=ai_risk,
        ai_available=ai_available,
    )
    # The final risk emitted must never be less than the deterministic risk
    assert dec.risk >= (det_risk - 1e-9)


@given(
    det_risk=st.floats(min_value=0.0, max_value=0.14),  # below allow threshold (0.15)
    ai_risk=st.floats(min_value=0.0, max_value=1.0),
)
def test_property_invariant_2_fail_closed_on_risky_type(
    det_risk: float,
    ai_risk: float,
) -> None:
    """Invariant 2: When risky type exists and AI is unavailable, action CANNOT be ALLOW."""
    dec = DEFAULT_ENGINE.decide(
        session_id="prop-2",
        scan_complete=True,
        scanners_ok=True,
        filesystem_supported=True,
        deterministic_risk=det_risk,
        ai_risk=ai_risk,
        has_risky_type=True,
        ai_available=False,  # Gateway down, timeout, error
    )
    assert dec.action in ("QUARANTINE", "BLOCK", "HUMAN_REVIEW")
    assert dec.action != "ALLOW"


@given(
    det_risk=st.floats(min_value=0.0, max_value=1.0),
    ai_risk=st.floats(min_value=0.0, max_value=1.0),
    ai_available=st.booleans(),
    critic_disagree=st.booleans(),
)
def test_property_hardware_or_av_hit_is_always_blocked(
    det_risk: float,
    ai_risk: float,
    ai_available: bool,
    critic_disagree: bool,
) -> None:
    """Device guard violation or AV hit must ALWAYS result in BLOCK."""
    dec_guard = DEFAULT_ENGINE.decide(
        session_id="prop-3a",
        scan_complete=True,
        scanners_ok=True,
        filesystem_supported=True,
        device_guard_blocked=True,
        deterministic_risk=det_risk,
        ai_risk=ai_risk,
        ai_available=ai_available,
        critic_disagreement=critic_disagree,
    )
    assert dec_guard.action == "BLOCK"

    dec_av = DEFAULT_ENGINE.decide(
        session_id="prop-3b",
        scan_complete=True,
        scanners_ok=True,
        filesystem_supported=True,
        av_or_yara_hit=True,
        deterministic_risk=det_risk,
        ai_risk=ai_risk,
        ai_available=ai_available,
        critic_disagreement=critic_disagree,
    )
    assert dec_av.action == "BLOCK"


@given(
    det_risk=st.floats(min_value=0.0, max_value=1.0),
    ai_risk=st.floats(min_value=0.0, max_value=1.0),
    ai_available=st.booleans(),
    critic_disagree=st.booleans(),
    scan_complete=st.booleans(),
    scanners_ok=st.booleans(),
    filesystem_supported=st.booleans(),
)
def test_property_scan_health_failure_never_yields_allow(
    det_risk: float,
    ai_risk: float,
    ai_available: bool,
    critic_disagree: bool,
    scan_complete: bool,
    scanners_ok: bool,
    filesystem_supported: bool,
) -> None:
    """Property test: if scan_complete=False or scanners_ok=False or filesystem_supported=False,

    the decision can NEVER be ALLOW across any combination of inputs.
    """
    if not (scan_complete and scanners_ok and filesystem_supported):
        dec = DEFAULT_ENGINE.decide(
            session_id="prop-health",
            deterministic_risk=det_risk,
            ai_risk=ai_risk,
            ai_available=ai_available,
            critic_disagreement=critic_disagree,
            scan_complete=scan_complete,
            scanners_ok=scanners_ok,
            filesystem_supported=filesystem_supported,
        )
        assert dec.action != "ALLOW"


def test_policy_engine_import_boundaries() -> None:
    """Invariant 3 & 4: sentinel/policy must NEVER import agents or network libraries.

    Policy Engine must remain 100% deterministic, offline, and independent of LLM agents.
    """
    import ast
    from pathlib import Path

    policy_dir = Path("sentinel/policy")
    prohibited_prefixes = (
        "agents",
        "sentinel.agents",
        "httpx",
        "requests",
        "socket",
        "urllib",
        "aiohttp",
    )

    for py_file in policy_dir.glob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    for prohibited in prohibited_prefixes:
                        assert not alias.name.startswith(prohibited), (
                            f"Prohibited import '{alias.name}' in {py_file}"
                        )
            elif isinstance(node, ast.ImportFrom) and node.module:
                for prohibited in prohibited_prefixes:
                    assert not node.module.startswith(prohibited), (
                        f"Prohibited import-from '{node.module}' in {py_file}"
                    )
