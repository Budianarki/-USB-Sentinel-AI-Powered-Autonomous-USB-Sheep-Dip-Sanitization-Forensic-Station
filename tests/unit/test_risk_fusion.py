"""Unit tests and invariant verification for Risk Fusion Engine (Phase 3 / Invariant 1)."""

from hypothesis import given
from hypothesis import strategies as st

from sentinel.agents.schemas import AgentVerdict
from sentinel.fusion.risk_fusion import RiskFusionEngine


def test_clean_deterministic_and_clean_agents_yields_clean_risk():
    fusion = RiskFusionEngine()
    verdict1 = AgentVerdict(
        agent="static_analyst",
        file_id="f1",
        risk_score=0.05,
        confidence=0.9,
        verdict="benign",
        reasons=["Clean"],
    )
    res = fusion.fuse(deterministic_risk=0.0, agent_verdicts=[verdict1])
    assert res.final_risk <= 0.15
    assert res.deterministic_risk == 0.0
    assert not res.injection_detected


def test_agent_cap_clamps_single_agent_contribution():
    # static_analyst default cap is 0.85
    fusion = RiskFusionEngine(agent_caps={"static_analyst": 0.85})
    extreme_verdict = AgentVerdict(
        agent="static_analyst",
        file_id="f1",
        risk_score=1.0,  # Claims 1.0 risk
        confidence=1.0,
        verdict="malicious",
        reasons=["Malicious"],
    )
    res = fusion.fuse(deterministic_risk=0.0, agent_verdicts=[extreme_verdict])
    # Contribution should be capped at 0.85
    assert res.agent_contributions["static_analyst"] == 0.85
    assert res.risk_ai == 0.85


def test_multiple_agents_accumulate_via_noisy_or():
    fusion = RiskFusionEngine(
        agent_caps={"static_analyst": 0.85, "intel": 0.90},
        agent_weights={"static_analyst": 1.0, "intel": 1.0},
    )
    v1 = AgentVerdict(
        agent="static_analyst",
        file_id="f1",
        risk_score=0.50,
        confidence=0.9,
        verdict="suspicious",
        reasons=["Suspicious section"],
    )
    v2 = AgentVerdict(
        agent="intel",
        file_id="f1",
        risk_score=0.50,
        confidence=0.9,
        verdict="suspicious",
        reasons=["Low prevalence hash"],
    )
    res = fusion.fuse(deterministic_risk=0.0, agent_verdicts=[v1, v2])
    # noisy-OR: 1 - (1 - 0.50)*(1 - 0.50) = 1 - 0.25 = 0.75
    assert res.risk_ai == 0.75
    assert res.final_risk == 0.75


def test_failed_or_unknown_agent_contributes_zero():
    fusion = RiskFusionEngine()
    unknown_verdict = AgentVerdict(
        agent="static_analyst",
        file_id="f1",
        risk_score=0.80,
        confidence=0.0,
        verdict="unknown",  # Agent failed/unknown
        reasons=["Analysis error"],
    )
    res = fusion.fuse(deterministic_risk=0.10, agent_verdicts=[unknown_verdict])
    assert res.agent_contributions["static_analyst"] == 0.0
    assert res.final_risk == 0.10


def test_prompt_injection_flags_risk_penalty():
    fusion = RiskFusionEngine(injection_penalty=0.85)
    injected_verdict = AgentVerdict(
        agent="static_analyst",
        file_id="f1",
        risk_score=0.10,
        confidence=0.8,
        verdict="suspicious",
        reasons=["Prompt injection seen"],
        injection_suspected=True,
    )
    res = fusion.fuse(deterministic_risk=0.0, agent_verdicts=[injected_verdict])
    assert res.injection_detected is True
    assert res.final_risk >= 0.85


@given(
    det_risk=st.floats(min_value=0.0, max_value=1.0),
    ai_score_1=st.floats(min_value=0.0, max_value=1.0),
    ai_score_2=st.floats(min_value=0.0, max_value=1.0),
)
def test_property_invariant_1_ai_never_lowers_risk(
    det_risk: float, ai_score_1: float, ai_score_2: float
):
    """Property test verifying Invariant 1: final_risk >= deterministic_risk for all inputs."""
    fusion = RiskFusionEngine()
    v1 = AgentVerdict(
        agent="static_analyst",
        risk_score=ai_score_1,
        confidence=0.8,
        verdict="suspicious" if ai_score_1 > 0.4 else "benign",
        reasons=[],
    )
    v2 = AgentVerdict(
        agent="intel",
        risk_score=ai_score_2,
        confidence=0.8,
        verdict="suspicious" if ai_score_2 > 0.4 else "benign",
        reasons=[],
    )
    res = fusion.fuse(deterministic_risk=det_risk, agent_verdicts=[v1, v2])

    assert res.final_risk >= round(det_risk, 4) - 1e-6
    assert 0.0 <= res.final_risk <= 1.0
