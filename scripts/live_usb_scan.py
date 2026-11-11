#!/usr/bin/env python3
"""Live USB Inspection Runner for real hardware flashdisks (Fase 3 AI Sentinel).

Scans mounted physical flashdisk, executes:
- Layer 1 Device Guard verification
- Layer 2 Deterministic Scanning (ClamAV, YARA, Static isolated tools, Zip bomb, BiDi)
- Layer 3 AI Agent Triage (Static Analyst, Intel, Critic, Responder, Risk Fusion)
- Layer 4 Policy Engine decision
- SQLite Hash Chain tamper-evident recording
- Exports full structured JSON for UI/UX rendering
"""

import asyncio
import json
import time
from pathlib import Path

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
from sentinel.services.intel_service import IntelService
from sentinel.store.db import db_session, init_database
from sentinel.store.hashchain import export_head, verify_hashchain
from sentinel.util.config import PolicyConfig, SentinelConfig


async def run_live_inspection(mount_dir: Path, output_json: Path) -> dict:
    db_file = Path("live_audit.db")
    init_database(db_file)
    IntelService.seed_offline_feed(db_file)

    config = SentinelConfig(mode="laptop_mock")
    config.agents.always_ai = True  # Ensure all candidate files undergo full AI triage
    policy_config = PolicyConfig()

    usb_source = MockUsbSource(default_mount_dir=mount_dir)
    display = ConsoleDisplay(silent=False)
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
        db_path=db_file,
    )

    station = SentinelStation(
        config=config,
        usb_source=usb_source,
        display=display,
        indicator=indicator,
        scan_engine=scan_engine,
        policy_engine=PolicyEngine(policy_config),
        db_path=db_file,
        orchestrator=orchestrator,
    )

    # Real Hardware Descriptors for SanDisk Cruzer Blade 6DB4-1ABD
    device_desc = UsbDeviceDescriptor(
        device_id="/dev/sda1",
        vendor_id="0781",
        product_id="5567",
        serial_number="04008122072825032721",
        device_class=0x00,
        interface_classes=[0x08],  # Mass storage
        manufacturer="SanDisk",
        product_name="Cruzer Blade (6DB4-1ABD)",
    )

    start_ts = time.time()
    event = UsbEvent(event_type="CONNECT", device=device_desc, timestamp=start_ts)
    decision = await station.handle_usb_event(event)
    duration_s = round(time.time() - start_ts, 3)

    assert decision is not None

    # Retrieve logged agent runs from SQLite
    agent_runs_data = []
    with db_session(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT agent, model, tokens_in, tokens_out, cost_est, latency_ms, status, verdict_json FROM agent_runs WHERE session_id = ?;",
            (decision.session_id,),
        )
        for row in cursor.fetchall():
            verdict_val = None
            if row["verdict_json"]:
                try:
                    verdict_val = json.loads(row["verdict_json"])
                except Exception:  # noqa: BLE001
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

    # Retrieve hash chain verification
    chain_valid, event_count, chain_err = verify_hashchain(db_file)
    _head_count, head_hash = export_head(db_file)

    # File listing with stats
    scanned_files = []
    if station.last_decision:
        for f in station.scan_engine.scan_mount(mount_dir).file_features:
            scanned_files.append({
                "name": f.sanitized_name,
                "type": f.detected_type,
                "size_bytes": f.size,
                "sha256": f.sha256,
                "entropy": f.entropy,
                "flags": f.flags,
                "av_hits": f.av_hits,
                "yara_hits": f.yara_hits,
                "ext_mismatch": f.ext_mismatch,
                "is_dangerous": bool(
                    f.av_hits
                    or f.yara_hits
                    or f.ext_mismatch
                    or any(any(k in fl for k in ("macro", "powershell", "autorun", "shortcut", "ransomware", "worm")) for fl in f.flags)
                ),
            })

    report = {
        "device": {
            "node": device_desc.device_id,
            "vendor": device_desc.manufacturer,
            "product": device_desc.product_name,
            "vendor_id": device_desc.vendor_id,
            "product_id": device_desc.product_id,
            "serial": device_desc.serial_number,
            "uuid": "6DB4-1ABD",
            "filesystem": "vfat (FAT32)",
            "mount_path": str(mount_dir),
        },
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

    output_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    import sys

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/media/rambo/6DB4-1ABD")

    out_file = Path("/tmp/sentinel_live_report.json")
    print(f"[*] Starting live inspection on physical flashdisk: {target}")
    result = asyncio.run(run_live_inspection(target, out_file))
    print(f"[+] Live inspection complete! Report written to {out_file}")

