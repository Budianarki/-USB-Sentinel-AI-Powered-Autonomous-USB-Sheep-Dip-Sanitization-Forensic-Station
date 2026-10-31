"""Configuration loader and schema validation using Pydantic."""

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator


class GatewayConfig(BaseModel):
    url: str = Field(default="https://gateway.local:8443")
    device_token_env: str = Field(default="SENTINEL_DEVICE_TOKEN")
    timeout_s: float = Field(default=20.0, gt=0)


class AgentBudgetConfig(BaseModel):
    max_steps_per_file: int = Field(default=6, ge=1)
    max_tokens_per_session: int = Field(default=30000, ge=100)
    max_seconds_per_session: int = Field(default=90, ge=1)


class AgentsConfig(BaseModel):
    enabled: list[str] = Field(
        default_factory=lambda: [
            "static_analyst",
            "intel",
            "context",
            "critic",
            "responder",
        ]
    )
    always_ai: bool = Field(default=False)
    budget: AgentBudgetConfig = Field(default_factory=AgentBudgetConfig)


class ScanConfig(BaseModel):
    max_files: int = Field(default=5000, ge=1)
    max_file_mb: int = Field(default=200, ge=1)
    max_static_analysis_mb: int = Field(default=50, ge=1)
    max_archive_depth: int = Field(default=3, ge=0)
    max_decompress_ratio: float = Field(default=100.0, ge=1.0)
    allowed_types: list[str] = Field(
        default_factory=lambda: ["pdf", "docx", "xlsx", "pptx", "txt", "jpg", "png", "zip"]
    )
    allowed_filesystems: list[str] = Field(
        default_factory=lambda: ["vfat", "exfat"]
    )


class PolicyThresholds(BaseModel):
    allow: float = Field(default=0.15, ge=0.0, le=1.0)
    review: float = Field(default=0.40, ge=0.0, le=1.0)
    block: float = Field(default=0.75, ge=0.0, le=1.0)

    @field_validator("review")
    @classmethod
    def validate_review(cls, v: float, info: Any) -> float:
        allow = info.data.get("allow", 0.15)
        if v < allow:
            raise ValueError(
                f"review threshold ({v}) cannot be less than allow threshold ({allow})"
            )
        return v

    @field_validator("block")
    @classmethod
    def validate_block(cls, v: float, info: Any) -> float:
        review = info.data.get("review", 0.40)
        if v < review:
            raise ValueError(
                f"block threshold ({v}) cannot be less than review threshold ({review})"
            )
        return v


class SentinelPolicyRef(BaseModel):
    file: str = Field(default="config/policy.yaml")
    thresholds: PolicyThresholds = Field(default_factory=PolicyThresholds)


class UsbConfig(BaseModel):
    allow_classes: list[int] = Field(default_factory=lambda: [0x08])  # 0x08 = Mass Storage
    serial_whitelist_file: str = Field(default="config/trusted_devices.yaml")


class TelegramConfig(BaseModel):
    enabled: bool = Field(default=False)
    chat_id_env: str = Field(default="TG_CHAT_ID")
    token_env: str = Field(default="TG_TOKEN")


class NotifyConfig(BaseModel):
    telegram: TelegramConfig = Field(default_factory=TelegramConfig)


class SentinelConfig(BaseModel):
    mode: Literal["iot", "laptop_mock"] = Field(default="laptop_mock")
    gateway: GatewayConfig = Field(default_factory=GatewayConfig)
    agents: AgentsConfig = Field(default_factory=AgentsConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    policy: SentinelPolicyRef = Field(default_factory=SentinelPolicyRef)
    usb: UsbConfig = Field(default_factory=UsbConfig)
    notify: NotifyConfig = Field(default_factory=NotifyConfig)


class QuarantineConfig(BaseModel):
    retention_days: int = Field(default=90, ge=1)
    action_description: str = Field(
        default="Flashdisk ditahan petugas, tidak boleh dibawa masuk ruang server. "
        "Hanya hash dan metadata dicatat, file tidak disalin."
    )


class PolicyConfig(BaseModel):
    version: str = Field(default="1.0.0")
    thresholds: PolicyThresholds = Field(default_factory=PolicyThresholds)
    quarantine: QuarantineConfig = Field(default_factory=QuarantineConfig)
    deterministic_risks: dict[str, float] = Field(
        default_factory=lambda: {
            "av_hit": 1.0,
            "yara_hit": 1.0,
            "device_guard_violation": 1.0,
            "mount_failure": 0.85,
            "session_exception": 0.90,
            "type_mismatch": 0.85,
            "office_macro_autoexec": 0.90,
            "pe_packed": 0.70,
            "archive_encrypted": 0.60,
            "script_detected": 0.65,
            "untrusted_type": 0.50,
        }
    )
    agent_caps: dict[str, float] = Field(
        default_factory=lambda: {
            "static_analyst": 0.85,
            "intel": 0.90,
            "context": 0.40,
            "critic": 0.50,
        }
    )


def load_sentinel_config(config_path: str | Path | None = None) -> SentinelConfig:
    """Load and validate SentinelConfig from YAML file."""
    if config_path is None:
        default_paths = [
            Path("config/sentinel.yaml"),
            Path("config/sentinel.example.yaml"),
        ]
        target = None
        for p in default_paths:
            if p.exists():
                target = p
                break
        if target is None:
            return SentinelConfig()
        config_path = target
    else:
        config_path = Path(config_path)

    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found at: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    return SentinelConfig.model_validate(data)


def load_policy_config(policy_path: str | Path | None = None) -> PolicyConfig:
    """Load and validate PolicyConfig from YAML file."""
    if policy_path is None:
        default_paths = [
            Path("config/policy.yaml"),
        ]
        target = None
        for p in default_paths:
            if p.exists():
                target = p
                break
        if target is None:
            return PolicyConfig()
        policy_path = target
    else:
        policy_path = Path(policy_path)

    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found at: {policy_path}")

    with open(policy_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    return PolicyConfig.model_validate(data)
