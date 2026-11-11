"""Scanning Orchestration Service for USB Sentinel Station."""

import json
import logging
import time
from pathlib import Path
from typing import Any

from gateway.app import app as gateway_app
from sentinel.agents.client import GatewayClient
from sentinel.agents.orchestrator import AgentOrchestrator
from sentinel.fusion.risk_fusion import RiskFusionEngine
from sentinel.main import SentinelStation
from sentinel.platform.base import UsbDeviceDescriptor, UsbEvent
from sentinel.platform.display_console import ConsoleDisplay
from sentinel.platform.gpio import MockIndicator
from sentinel.platform.mock_usb import MockUsbSource
from sentinel.policy.engine import PolicyEngine
from sentinel.scan.clamav import MockClamAvScanner
from sentinel.scan.engine import ScanEngine
from sentinel.scan.yara_scanner import MockYaraScanner, YaraScanner
from sentinel.store.db import db_session
from sentinel.store.hashchain import export_head, verify_hashchain
from sentinel.util.config import PolicyConfig, SentinelConfig

logger = logging.getLogger(__name__)

THREAT_KEYWORDS = (
    "macro",
    "powershell",
    "autorun",
    "shortcut",
    "double_extension",
    "disguised",
    "ransomware",
    "wscript",
    "reverse_shell",
    "high_entropy",
    "type_mismatch",
)


class ScanService:
    """Coordinates Layer 1 through Layer 4 live inspection and forensics aggregation."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    async def execute_scan(
        self,
        target_device_info: dict[str, Any],
        scan_target_path: Path,
    ) -> dict[str, Any]:
        """Execute full 4-layer Sentinel scan on target mounted directory."""
        config = SentinelConfig(mode="laptop_mock")
        config.agents.always_ai = True
        policy_config = PolicyConfig()

        usb_source = MockUsbSource(default_mount_dir=scan_target_path)
        display = ConsoleDisplay(silent=True)
        indicator = MockIndicator()

        clamav = MockClamAvScanner()
        real_yara = YaraScanner()
        yara = real_yara if not real_yara.init_error else MockYaraScanner()
        scan_engine = ScanEngine(
            config=config,
            policy_config=policy_config,
            clamav_scanner=clamav,
            yara_scanner=yara,
        )

        client = GatewayClient(
            base_url="http://gateway.local",
            device_token="sentinel-dev-station-01",
            asgi_app=gateway_app,
        )
        orchestrator = AgentOrchestrator(
            config=config.agents,
            gateway_client=client,
            risk_fusion=RiskFusionEngine(agent_caps=policy_config.agent_caps),
            db_path=self.db_path,
        )

        station = SentinelStation(
            config=config,
            usb_source=usb_source,
            display=display,
            indicator=indicator,
            scan_engine=scan_engine,
            policy_engine=PolicyEngine(policy_config),
            db_path=self.db_path,
            orchestrator=orchestrator,
        )

        device_desc = UsbDeviceDescriptor(
            device_id=target_device_info["node"],
            vendor_id="0781",
            product_id="5567",
            serial_number=target_device_info.get("serial", "UNKNOWN"),
            device_class=0x00,
            interface_classes=[0x08],  # Mass storage
            manufacturer=target_device_info.get("vendor", "Generic"),
            product_name=target_device_info.get("model", "USB Drive"),
        )

        start_ts = time.time()
        event = UsbEvent(event_type="CONNECT", device=device_desc, timestamp=start_ts)
        decision = await station.handle_usb_event(event)
        duration_s = round(time.time() - start_ts, 3)

        if decision is None:
            raise RuntimeError("Decision returned None during scan execution.")

        # Query agent_runs from SQLite
        agent_runs_data = []
        with db_session(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT agent, model, tokens_in, tokens_out, cost_est, latency_ms, status, verdict_json
                FROM agent_runs WHERE session_id = ?;
                """,
                (decision.session_id,),
            )
            for row in cursor.fetchall():
                verdict_val = None
                if row["verdict_json"]:
                    try:
                        verdict_val = json.loads(row["verdict_json"])
                    except (json.JSONDecodeError, TypeError, ValueError):
                        verdict_val = row["verdict_json"]
                agent_runs_data.append({
                    "agent": row["agent"],
                    "model": row["model"],
                    "tokens": row["tokens_in"] + row["tokens_out"],
                    "cost_est": row["cost_est"],
                    "latency_ms": row["latency_ms"],
                    "status": row["status"],
                    "verdict": verdict_val,
                })

        # Hash chain status
        chain_valid, event_count, chain_err = verify_hashchain(self.db_path)
        _, head_hash = export_head(self.db_path)

        # Scanned files metadata with absolute paths
        scanned_files = []
        scan_mount_res = station.scan_engine.scan_mount(scan_target_path)
        for f in scan_mount_res.file_features:
            target_name = f.sanitized_name or f.file_id
            found_path = None
            for candidate in scan_target_path.rglob(target_name):
                if candidate.is_file():
                    found_path = candidate
                    break
            abs_p = found_path or (scan_target_path / target_name)
            is_bad = bool(
                f.av_hits
                or f.yara_hits
                or f.ext_mismatch
                or any(any(k in fl for k in THREAT_KEYWORDS) for fl in f.flags)
            )
            scanned_files.append({
                "name": target_name,
                "rel_path": target_name,
                "abs_path": str(abs_p),
                "type": f.detected_type,
                "size_bytes": f.size,
                "entropy": round(f.entropy, 4),
                "flags": f.flags,
                "av_hits": f.av_hits,
                "yara_hits": f.yara_hits,
                "ext_mismatch": f.ext_mismatch,
                "is_dangerous": is_bad,
            })

        return {
            "device": target_device_info,
            "session": {
                "session_id": decision.session_id,
                "action": decision.action,
                "risk": decision.risk,
                "duration_s": duration_s,
                "policy_version": decision.policy_version,
                "ai_available": decision.ai_available,
                "deterministic_reasons": decision.deterministic_reasons,
                "ai_reasons": decision.ai_reasons,
                "led_indicator": indicator.current_state,
            },
            "hashchain": {
                "valid": chain_valid,
                "total_events": event_count,
                "head_hash": head_hash,
                "error": chain_err,
            },
            "agent_runs": agent_runs_data,
            "scanned_files": scanned_files,
        }

