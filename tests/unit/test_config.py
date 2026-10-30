"""Unit tests for configuration loaders and Pydantic validation."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinel.util.config import (
    PolicyConfig,
    PolicyThresholds,
    SentinelConfig,
    load_policy_config,
    load_sentinel_config,
)


def test_load_default_sentinel_config() -> None:
    """Ensure example config loads and adheres to expected schema defaults."""
    cfg = load_sentinel_config("config/sentinel.example.yaml")
    assert isinstance(cfg, SentinelConfig)
    assert cfg.mode in ("iot", "laptop_mock")
    assert cfg.scan.max_files == 5000
    assert cfg.scan.max_file_mb == 200
    assert 0x08 in cfg.usb.allow_classes
    assert cfg.agents.budget.max_steps_per_file == 6
    assert cfg.agents.budget.max_tokens_per_session == 30000


def test_load_default_policy_config() -> None:
    """Ensure policy.yaml loads correctly with quarantine retention of 90 days."""
    pol = load_policy_config("config/policy.yaml")
    assert isinstance(pol, PolicyConfig)
    assert pol.version == "1.0.0"
    assert pol.thresholds.allow == 0.15
    assert pol.thresholds.review == 0.40
    assert pol.thresholds.block == 0.75
    assert pol.quarantine.retention_days == 90
    assert "av_hit" in pol.deterministic_risks
    assert pol.deterministic_risks["av_hit"] == 1.0


def test_threshold_ordering_validation() -> None:
    """Review threshold must be >= allow, block threshold must be >= review."""
    with pytest.raises(ValidationError):
        # review (0.10) is less than allow (0.20)
        PolicyThresholds(allow=0.20, review=0.10, block=0.80)

    with pytest.raises(ValidationError):
        # block (0.30) is less than review (0.50)
        PolicyThresholds(allow=0.10, review=0.50, block=0.30)


def test_missing_config_file() -> None:
    """Non-existent path must raise FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        load_sentinel_config("non_existent_config.yaml")

    with pytest.raises(FileNotFoundError):
        load_policy_config("non_existent_policy.yaml")


def test_corrupt_config(tmp_path: Path) -> None:
    """Corrupt config file must raise ValidationError."""
    bad_cfg = tmp_path / "bad_sentinel.yaml"
    bad_cfg.write_text("scan:\n  max_files: -10\n", encoding="utf-8")

    with pytest.raises(ValidationError):
        load_sentinel_config(bad_cfg)
