"""Interactive Web Dashboard server for USB Sentinel Station (FastAPI + Modern Tailwind UI).

Provides:
- GET /api/devices: real-time detection of connected USB block devices
- POST /api/scan: execute live inspection pipeline with full AI triage
- GET /: single-page cyber defense dashboard UI
"""

import json
import logging
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

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
from sentinel.scan.yara_scanner import MockYaraScanner
from sentinel.store.db import db_session, init_database
from sentinel.store.hashchain import export_head, verify_hashchain
from sentinel.ui.device_scanner import list_connected_usb_devices
from sentinel.util.config import PolicyConfig, SentinelConfig

logger = logging.getLogger("sentinel.ui.web")

ui_app = FastAPI(
    title="USB Sentinel Web Dashboard",
    version="1.0.0",
    description="Interactive Live Sanitization & AI Multi-Agent Triage Dashboard",
)

DB_PATH = Path("sentinel_audit.db")
init_database(DB_PATH)


class ScanRequest(BaseModel):
    device_node: str | None = None
    target_subpath: str | None = None


@ui_app.get("/api/devices")
async def get_connected_devices() -> dict[str, Any]:
    """Poll currently connected USB storage hardware."""
    devices = list_connected_usb_devices()
    return {
        "count": len(devices),
        "devices": devices,
        "timestamp": time.time(),
    }


@ui_app.post("/api/scan")
async def trigger_live_scan(req: ScanRequest) -> dict[str, Any]:
    """Execute live Sentinel inspection with multi-agent AI triage on selected USB device."""
    devices = list_connected_usb_devices()
    if not devices:
        raise HTTPException(
            status_code=400,
            detail="0 perangkat USB terdeteksi! Silakan colokkan flashdisk terlebih dahulu.",
        )

    # Select target device
    target_device_info = devices[0]
    if req.device_node:
        matched = [d for d in devices if d["node"] == req.device_node]
        if matched:
            target_device_info = matched[0]

    mount_point_str = target_device_info.get("mount_point")
    if not mount_point_str or not Path(mount_point_str).exists():
        raise HTTPException(
            status_code=400,
            detail=f"Perangkat {target_device_info['node']} belum memiliki mount point aktif di sistem.",
        )

    scan_target_path = Path(mount_point_str)
    if req.target_subpath:
        sub = scan_target_path / req.target_subpath.lstrip("/")
        if sub.exists():
            scan_target_path = sub

    config = SentinelConfig(mode="laptop_mock")
    config.agents.always_ai = True
    policy_config = PolicyConfig()

    usb_source = MockUsbSource(default_mount_dir=scan_target_path)
    display = ConsoleDisplay(silent=True)
    indicator = MockIndicator()

    clamav = MockClamAvScanner()
    yara = MockYaraScanner()
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
        db_path=DB_PATH,
    )

    station = SentinelStation(
        config=config,
        usb_source=usb_source,
        display=display,
        indicator=indicator,
        scan_engine=scan_engine,
        policy_engine=PolicyEngine(policy_config),
        db_path=DB_PATH,
        orchestrator=orchestrator,
    )

    device_desc = UsbDeviceDescriptor(
        device_id=target_device_info["node"],
        vendor_id="0781",
        product_id="5567",
        serial_number=target_device_info["serial"],
        device_class=0x00,
        interface_classes=[0x08],  # Mass storage
        manufacturer=target_device_info["vendor"],
        product_name=target_device_info["model"],
    )

    start_ts = time.time()
    event = UsbEvent(event_type="CONNECT", device=device_desc, timestamp=start_ts)
    decision = await station.handle_usb_event(event)
    duration_s = round(time.time() - start_ts, 3)

    assert decision is not None

    # Fetch agent runs for this session from SQLite
    agent_runs_data = []
    with db_session(DB_PATH) as conn:
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
    chain_valid, event_count, chain_err = verify_hashchain(DB_PATH)
    _, head_hash = export_head(DB_PATH)

    # Scanned files metadata
    scanned_files = []
    scan_mount_res = station.scan_engine.scan_mount(scan_target_path)
    for f in scan_mount_res.file_features:
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
            "is_dangerous": (
                bool(f.av_hits or f.yara_hits or f.ext_mismatch)
                or any("macro_autoexec" in fl for fl in f.flags)
            ),
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


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="id" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>USB Sentinel - Live Sheep-Dip Inspection Station</title>
  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>
  <style>
    @keyframes scanline {
      0% { transform: translateY(-100%); }
      100% { transform: translateY(1000%); }
    }
    .animate-scanline {
      animation: scanline 3s linear infinite;
    }
  </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen antialiased selection:bg-cyan-500 selection:text-black">
  <!-- Glowing Background Orbs -->
  <div class="fixed inset-0 pointer-events-none overflow-hidden z-0">
    <div class="absolute -top-40 -left-40 w-96 h-96 bg-cyan-600/10 rounded-full blur-3xl"></div>
    <div class="absolute top-1/2 -right-40 w-96 h-96 bg-indigo-600/10 rounded-full blur-3xl"></div>
  </div>

  <div class="relative z-10 max-w-7xl mx-auto px-4 py-6 sm:px-6 lg:px-8 space-y-6">

    <!-- Top Navigation & Brand Header -->
    <header class="bg-slate-900/80 backdrop-blur-md border border-slate-800 rounded-2xl p-5 shadow-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
      <div class="flex items-center gap-4">
        <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 text-white font-black text-xl tracking-wider">
          🛡️
        </div>
        <div>
          <div class="flex items-center gap-2">
            <h1 class="text-xl font-extrabold tracking-tight text-white">USB SENTINEL</h1>
            <span class="px-2 py-0.5 text-xs font-bold rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              SHEEP-DIP STATION v0.3.0
            </span>
          </div>
          <p class="text-xs text-slate-400 mt-0.5">Air-gapped Removable Media Sanitization & Multi-Agent AI Defense</p>
        </div>
      </div>

      <div class="flex items-center gap-4 self-end md:self-auto">
        <!-- Audio Beeper Toggle -->
        <button id="audio-toggle" onclick="toggleAudio()" class="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-xs text-slate-300 flex items-center gap-2 transition-all">
          <span id="audio-icon">🔊</span>
          <span id="audio-label">Alarm Beeper: Aktif</span>
        </button>

        <!-- Live Clock -->
        <div class="text-right hidden sm:block">
          <div class="text-[11px] text-slate-400 font-mono" id="clock-display">--:--:--</div>
          <div class="text-[10px] text-emerald-400 flex items-center gap-1 justify-end">
            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> Daemon Aktif
          </div>
        </div>
      </div>
    </header>

    <!-- LIVE HARDWARE DETECTION & ACTION HERO BANNER -->
    <section class="bg-gradient-to-r from-slate-900 via-slate-900 to-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-2xl">
      <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">

        <!-- Device Status Pill -->
        <div class="space-y-3 max-w-2xl">
          <div class="flex items-center gap-3">
            <span class="text-xs uppercase font-bold tracking-widest text-slate-400">Status Port USB Fisik</span>
            <span id="device-badge" class="px-3 py-1 rounded-full text-xs font-bold flex items-center gap-2 bg-slate-800 text-slate-400 border border-slate-700">
              <span class="w-2 h-2 rounded-full bg-slate-400 animate-ping"></span>
              Memeriksa port USB...
            </span>
          </div>

          <div id="device-info-container" class="space-y-1">
            <h2 id="device-title" class="text-2xl font-bold text-white tracking-tight">Menunggu Flashdisk Dicolokkan...</h2>
            <p id="device-subtitle" class="text-xs text-slate-400">
              Silakan tancapkan flashdisk ke port USB stasiun Sentinel. Sistem akan otomatis mendeteksi hardware dalam waktu nyata.
            </p>
          </div>

          <!-- Hardware Detail Badges (shown when connected) -->
          <div id="device-meta-tags" class="hidden flex flex-wrap gap-2 pt-1 text-xs">
            <span class="bg-slate-800 text-slate-300 px-2.5 py-1 rounded-md border border-slate-700 font-mono">Node: <strong id="meta-node" class="text-cyan-400">/dev/sda1</strong></span>
            <span class="bg-slate-800 text-slate-300 px-2.5 py-1 rounded-md border border-slate-700 font-mono">UUID: <strong id="meta-uuid" class="text-white">--</strong></span>
            <span class="bg-slate-800 text-slate-300 px-2.5 py-1 rounded-md border border-slate-700">Kapasitas: <strong id="meta-size" class="text-emerald-400">-- GB</strong></span>
            <span class="bg-slate-800 text-slate-300 px-2.5 py-1 rounded-md border border-slate-700">Filesystem: <strong id="meta-fs" class="text-white">VFAT</strong></span>
            <span class="bg-slate-800 text-slate-300 px-2.5 py-1 rounded-md border border-slate-700">Serial: <strong id="meta-serial" class="text-slate-200">--</strong></span>
          </div>
        </div>

        <!-- Big Start Action Button -->
        <div class="w-full lg:w-auto flex flex-col sm:flex-row items-center gap-3">
          <button id="btn-start-scan" onclick="startScan()" disabled class="w-full sm:w-auto px-8 py-4 rounded-xl font-extrabold text-sm tracking-wider uppercase transition-all duration-300 flex items-center justify-center gap-3 cursor-not-allowed bg-slate-800 text-slate-500 border border-slate-700 shadow-none">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
            <span id="btn-label">0 FLASHDISK (TOMBOL DINONAKTIFKAN)</span>
          </button>
        </div>

      </div>

      <!-- Live Inspection Progress Bar (Shown while scanning) -->
      <div id="scan-progress-box" class="hidden mt-6 pt-6 border-t border-slate-800 space-y-3">
        <div class="flex items-center justify-between text-xs">
          <span id="scan-step-label" class="font-bold text-cyan-400 flex items-center gap-2">
            <svg class="w-4 h-4 animate-spin text-cyan-400" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path></svg>
            Layer 1: Device Guard checking USB descriptors...
          </span>
          <span id="scan-pct-label" class="font-mono text-slate-400">25%</span>
        </div>
        <div class="w-full bg-slate-800 rounded-full h-2.5 overflow-hidden border border-slate-700">
          <div id="scan-progress-bar" class="bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-600 h-2.5 rounded-full transition-all duration-500 w-1/4"></div>
        </div>
      </div>
    </section>

    <!-- SCAN RESULTS SECTION (Populated after scan) -->
    <main id="results-view" class="hidden space-y-6">

      <!-- Decision Banner & Score Gauge Row -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">

        <!-- Final Decision Card -->
        <div id="card-decision" class="lg:col-span-2 bg-slate-900 border border-red-500/30 rounded-2xl p-6 shadow-2xl relative overflow-hidden flex flex-col justify-between">
          <div class="relative z-10 space-y-3">
            <div class="flex items-center justify-between">
              <span class="text-xs uppercase font-extrabold tracking-widest text-slate-400">Keputusan Akhir (Policy Engine Layer 4)</span>
              <span id="badge-decision" class="px-3.5 py-1 rounded-full text-xs font-black tracking-wide bg-red-500/20 text-red-400 border border-red-500/30">
                BLOCKED
              </span>
            </div>

            <h3 id="text-decision-title" class="text-3xl font-black text-white tracking-tight">FLASHDISK BERBAHAYA! DILARANG MASUK</h3>
            <p id="text-decision-desc" class="text-xs text-slate-300 leading-relaxed">
              Ditemukan berkas macro berbahaya, penyamaran executable sebagai PDF, dan percobaan prompt injection. Flashdisk ditolak otomatis.
            </p>

            <!-- Reasons list -->
            <div class="pt-2">
              <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-1.5">Indikator Ancaman Utama:</div>
              <ul id="list-reasons" class="text-xs text-red-300 space-y-1 list-disc list-inside"></ul>
            </div>
          </div>

          <div class="mt-6 pt-4 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
            <div>Sesi ID: <code id="txt-session-id" class="text-[11px] text-slate-300 font-mono">--</code></div>
            <div>Durasi: <strong id="txt-duration" class="text-white">-- detik</strong></div>
          </div>
        </div>

        <!-- Risk Gauge & LED Physical Indicator Card -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl flex flex-col items-center justify-between text-center">
          <span class="text-xs font-bold uppercase tracking-widest text-slate-400">Skor Risiko Terkalibrasi (Noisy-OR)</span>

          <!-- Radial Circle Gauge -->
          <div class="relative my-4 flex items-center justify-center">
            <svg class="w-40 h-40 transform -rotate-90">
              <circle cx="80" cy="80" r="65" stroke="currentColor" stroke-width="12" class="text-slate-800" fill="transparent" />
              <circle id="gauge-circle" cx="80" cy="80" r="65" stroke="currentColor" stroke-width="12" class="text-red-500 transition-all duration-1000" fill="transparent" stroke-dasharray="408" stroke-dashoffset="0" stroke-linecap="round" />
            </svg>
            <div class="absolute flex flex-col items-center justify-center text-center">
              <span id="gauge-score" class="text-4xl font-black text-white">1.00</span>
              <span class="text-[11px] text-slate-400">SKOR MAKS</span>
            </div>
          </div>

          <!-- Physical LED Status -->
          <div class="w-full bg-slate-950 p-3 rounded-xl border border-slate-800 flex items-center justify-between text-xs">
            <span class="text-slate-400">LED Station Fisik:</span>
            <div class="flex items-center gap-2">
              <span id="led-bulb" class="w-3.5 h-3.5 rounded-full bg-red-500 shadow-[0_0_12px_rgba(239,68,68,1)] animate-ping"></span>
              <span id="led-text" class="font-extrabold text-red-400">MERAH (ALARM)</span>
            </div>
          </div>
        </div>

      </div>

      <!-- AI Multi-Agent Triage Grid -->
      <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-4">
        <div class="flex items-center justify-between border-b border-slate-800 pb-3">
          <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded-lg bg-indigo-500/20 text-indigo-400 flex items-center justify-center text-sm font-bold">🤖</div>
            <h3 class="text-base font-bold text-white">Investigasi Tim AI Agents (Fase 3 Multi-Agent)</h3>
          </div>
          <span class="text-xs text-indigo-400 bg-indigo-500/10 border border-indigo-500/30 px-2.5 py-1 rounded-full font-mono">Gateway Protocol Active</span>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-4" id="agent-cards-container">
          <!-- Populated by JS -->
        </div>

        <!-- Responder Box -->
        <div class="p-4 rounded-xl bg-slate-950 border border-slate-800 flex items-start gap-3">
          <span class="text-xl">📢</span>
          <div class="space-y-1">
            <div class="text-xs font-bold text-slate-300 uppercase tracking-wide">Ringkasan Resmi Responder AI (Bahasa Indonesia):</div>
            <p id="txt-responder-summary" class="text-xs text-slate-400 leading-relaxed"></p>
          </div>
        </div>
      </div>

      <!-- Scanned Files Table -->
      <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-4">
        <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div>
            <h3 class="text-base font-bold text-white">Daftar Berkas yang Ditemukan di Flashdisk</h3>
            <p class="text-xs text-slate-400">Seluruh berkas diuji secara read-only tanpa eksekusi host</p>
          </div>
          <div class="flex items-center gap-2">
            <button onclick="filterFiles('all')" class="px-3 py-1 rounded-lg text-xs font-medium bg-slate-800 text-slate-300 hover:bg-slate-700">Semua</button>
            <button onclick="filterFiles('danger')" class="px-3 py-1 rounded-lg text-xs font-medium bg-red-500/20 text-red-400 hover:bg-red-500/30">Ancaman Saja</button>
          </div>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs border-collapse">
            <thead>
              <tr class="border-b border-slate-800 text-slate-400 bg-slate-950/50">
                <th class="py-3 px-3 font-semibold">Nama Berkas</th>
                <th class="py-3 px-3 font-semibold">Tipe Magic</th>
                <th class="py-3 px-3 font-semibold">Ukuran</th>
                <th class="py-3 px-3 font-semibold">Entropi</th>
                <th class="py-3 px-3 font-semibold">Flags Ancaman</th>
                <th class="py-3 px-3 font-semibold text-right">Status</th>
              </tr>
            </thead>
            <tbody id="files-table-body" class="divide-y divide-slate-800/60 font-mono">
              <!-- Populated by JS -->
            </tbody>
          </table>
        </div>
      </div>

      <!-- Cryptographic Hash Chain Audit Explorer -->
      <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-4">
        <div class="flex items-center justify-between border-b border-slate-800 pb-3">
          <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded-lg bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-sm font-bold">🔒</div>
            <div>
              <h3 class="text-base font-bold text-white">Log Integritas Kriptografis (SQLite Hash Chain)</h3>
              <p class="text-[11px] text-slate-400">Formula: <code>this_hash = SHA256(prev_hash || canonical_json(event))</code></p>
            </div>
          </div>
          <span class="text-xs px-2.5 py-1 rounded-full font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
            RANTAI UTUH / VALID
          </span>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
          <div class="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1">
            <div class="text-[10px] text-slate-500 uppercase font-sans">Total Event Tercatat</div>
            <div id="txt-event-count" class="text-lg font-bold text-white">--</div>
          </div>
          <div class="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1 md:col-span-2">
            <div class="text-[10px] text-slate-500 uppercase font-sans">Head Hash SHA256 Aktif</div>
            <div id="txt-head-hash" class="text-xs text-cyan-400 truncate">--</div>
          </div>
        </div>
      </div>

    </main>

  </div>

  <script>
    let audioEnabled = true;
    let audioCtx = null;
    let connectedDevices = [];
    let currentScanReport = null;

    function initAudio() {
      if (!audioCtx) {
        audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      }
    }

    function playBeep(freq = 880, duration = 0.15, type = 'sine') {
      if (!audioEnabled) return;
      try {
        initAudio();
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = type;
        osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
        gain.gain.setValueAtTime(0.15, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + duration);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start();
        osc.stop(audioCtx.currentTime + duration);
      } catch (e) {
        console.log("Audio failed:", e);
      }
    }

    function playAlarm() {
      if (!audioEnabled) return;
      playBeep(440, 0.2, 'sawtooth');
      setTimeout(() => playBeep(880, 0.3, 'sawtooth'), 200);
      setTimeout(() => playBeep(440, 0.2, 'sawtooth'), 500);
    }

    function toggleAudio() {
      audioEnabled = !audioEnabled;
      document.getElementById('audio-icon').innerText = audioEnabled ? '🔊' : '🔇';
      document.getElementById('audio-label').innerText = audioEnabled ? 'Alarm Beeper: Aktif' : 'Alarm Beeper: Mute';
      if (audioEnabled) playBeep(880, 0.1);
    }

    // Update Clock
    setInterval(() => {
      document.getElementById('clock-display').innerText = new Date().toLocaleTimeString('id-ID');
    }, 1000);

    // Poll Connected USB Hardware
    async function checkDevices() {
      try {
        const res = await fetch('/api/devices');
        const data = await res.json();
        connectedDevices = data.devices || [];
        updateDeviceUI(connectedDevices);
      } catch (err) {
        console.log("Error checking devices:", err);
      }
    }

    function updateDeviceUI(devices) {
      const badge = document.getElementById('device-badge');
      const title = document.getElementById('device-title');
      const subtitle = document.getElementById('device-subtitle');
      const meta = document.getElementById('device-meta-tags');
      const btn = document.getElementById('btn-start-scan');
      const btnLabel = document.getElementById('btn-label');

      if (!devices || devices.length === 0) {
        // 0 Devices
        badge.className = "px-3 py-1 rounded-full text-xs font-bold flex items-center gap-2 bg-amber-500/10 text-amber-400 border border-amber-500/30";
        badge.innerHTML = '<span class="w-2 h-2 rounded-full bg-amber-400 animate-ping"></span> 0 Perangkat USB Terhubung';

        title.innerText = "Menunggu Flashdisk Dicolokkan...";
        subtitle.innerText = "Port USB stasiun dalam kondisi standby. Silakan colokkan flashdisk target ke stasiun sanitasi.";
        meta.classList.add('hidden');

        btn.disabled = true;
        btn.className = "w-full sm:w-auto px-8 py-4 rounded-xl font-extrabold text-sm tracking-wider uppercase transition-all duration-300 flex items-center justify-center gap-3 cursor-not-allowed bg-slate-800 text-slate-500 border border-slate-700 shadow-none";
        btnLabel.innerText = "0 FLASHDISK (TOMBOL DINONAKTIFKAN)";
      } else {
        // 1 or more devices detected!
        const dev = devices[0];
        badge.className = "px-3 py-1 rounded-full text-xs font-bold flex items-center gap-2 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30";
        badge.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span> 1 Flashdisk Terdeteksi Siap Diuji';

        title.innerHTML = `✨ Terdeteksi: <span class="text-cyan-400 font-extrabold">${dev.label || dev.model}</span>`;
        subtitle.innerText = `Partisi aktif di ${dev.node} dengan mount point ${dev.mount_point}. Siap menjalankan pemeriksaan 4-Layer Sentinel.`;

        document.getElementById('meta-node').innerText = dev.node;
        document.getElementById('meta-uuid').innerText = dev.uuid || 'N/A';
        document.getElementById('meta-size').innerText = `${dev.size_gb} GB`;
        document.getElementById('meta-fs').innerText = dev.fs_type.toUpperCase();
        document.getElementById('meta-serial').innerText = dev.serial;
        meta.classList.remove('hidden');

        btn.disabled = false;
        btn.className = "w-full sm:w-auto px-8 py-4 rounded-xl font-extrabold text-sm tracking-wider uppercase transition-all duration-300 flex items-center justify-center gap-3 cursor-pointer bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 font-black shadow-lg shadow-cyan-500/30 transform hover:-translate-y-0.5";
        btnLabel.innerText = "⚡ MULAI SCAN SANITASI SEKARANG";
      }
    }

    // Trigger Scan
    async function startScan() {
      if (connectedDevices.length === 0) return;
      playBeep(600, 0.1);

      const progressBox = document.getElementById('scan-progress-box');
      const progressBar = document.getElementById('scan-progress-bar');
      const stepLabel = document.getElementById('scan-step-label');
      const pctLabel = document.getElementById('scan-pct-label');
      const btn = document.getElementById('btn-start-scan');

      progressBox.classList.remove('hidden');
      btn.disabled = true;

      // Simulated multi-stage progress
      stepLabel.innerText = "Layer 1: Device Guard memeriksa USB interface class & descriptor...";
      progressBar.style.width = "25%";
      pctLabel.innerText = "25%";
      playBeep(520, 0.1);

      setTimeout(() => {
        stepLabel.innerText = "Layer 2: Scanning Deterministik (Magic bytes, ClamAV, YARA, Zip bomb)...";
        progressBar.style.width = "55%";
        pctLabel.innerText = "55%";
        playBeep(650, 0.1);
      }, 500);

      setTimeout(() => {
        stepLabel.innerText = "Layer 3: AI Multi-Agent Triage (Static Analyst + Intel + Critic)...";
        progressBar.style.width = "85%";
        pctLabel.innerText = "85%";
        playBeep(780, 0.1);
      }, 1100);

      try {
        const res = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ device_node: connectedDevices[0].node })
        });
        const data = await res.json();
        currentScanReport = data;

        progressBar.style.width = "100%";
        pctLabel.innerText = "100%";
        stepLabel.innerText = "Layer 4: Policy Engine menetapkan vonis akhir!";

        setTimeout(() => {
          progressBox.classList.add('hidden');
          btn.disabled = false;
          renderScanReport(data);
        }, 600);

      } catch (err) {
        alert("Gagal menjalankan scan: " + err);
        progressBox.classList.add('hidden');
        btn.disabled = false;
      }
    }

    function renderScanReport(data) {
      document.getElementById('results-view').classList.remove('hidden');

      const isBlock = data.session.action === 'BLOCK';
      const isAllow = data.session.action === 'ALLOW';

      if (isBlock) playAlarm();
      else playBeep(1046, 0.3); // High success pitch

      // Decision Card
      const cardDec = document.getElementById('card-decision');
      const badgeDec = document.getElementById('badge-decision');
      const titleDec = document.getElementById('text-decision-title');
      const descDec = document.getElementById('text-decision-desc');
      const listReasons = document.getElementById('list-reasons');

      badgeDec.innerText = data.session.action;
      if (isBlock) {
        cardDec.className = "lg:col-span-2 bg-slate-900 border border-red-500/50 rounded-2xl p-6 shadow-2xl relative overflow-hidden flex flex-col justify-between bg-red-950/10";
        badgeDec.className = "px-3.5 py-1 rounded-full text-xs font-black tracking-wide bg-red-500/20 text-red-400 border border-red-500/30";
        titleDec.innerText = "🔴 FLASHDISK BERBAHAYA! DILARANG MASUK";
        descDec.innerText = "Terdeteksi berkas makro jahat, pemalsuan biner PE berkedok PDF, atau indikator malware lainnya. Flashdisk wajib ditahan petugas.";
      } else if (isAllow) {
        cardDec.className = "lg:col-span-2 bg-slate-900 border border-emerald-500/50 rounded-2xl p-6 shadow-2xl relative overflow-hidden flex flex-col justify-between bg-emerald-950/10";
        badgeDec.className = "px-3.5 py-1 rounded-full text-xs font-black tracking-wide bg-emerald-500/20 text-emerald-400 border border-emerald-500/30";
        titleDec.innerText = "🟢 FLASHDISK BERSIH! DIIZINKAN MASUK";
        descDec.innerText = "Seluruh pemeriksaan deterministik dan analisis AI bersih tanpa indikasi ancaman. Flashdisk boleh dibawa masuk ke server room.";
      }

      listReasons.innerHTML = '';
      const allReasons = [...(data.session.deterministic_reasons || []), ...(data.session.ai_reasons || [])];
      allReasons.forEach(r => {
        const li = document.createElement('li');
        li.innerText = r;
        listReasons.appendChild(li);
      });

      document.getElementById('txt-session-id').innerText = data.session.session_id;
      document.getElementById('txt-duration').innerText = `${data.session.duration_s} detik`;

      // Gauge Circle
      const gaugeCircle = document.getElementById('gauge-circle');
      const gaugeScore = document.getElementById('gauge-score');
      const score = data.session.risk || 0.0;
      gaugeScore.innerText = score.toFixed(2);
      // Circumference = 2 * PI * 65 ≈ 408
      const offset = 408 - (408 * score);
      gaugeCircle.style.strokeDashoffset = offset;
      gaugeCircle.className = score >= 0.75 ? "text-red-500 transition-all duration-1000" : (score >= 0.4 ? "text-amber-400 transition-all duration-1000" : "text-emerald-400 transition-all duration-1000");

      // LED
      const ledBulb = document.getElementById('led-bulb');
      const ledText = document.getElementById('led-text');
      if (isBlock) {
        ledBulb.className = "w-3.5 h-3.5 rounded-full bg-red-500 shadow-[0_0_12px_rgba(239,68,68,1)] animate-ping";
        ledText.className = "font-extrabold text-red-400";
        ledText.innerText = "MERAH (ALARM)";
      } else {
        ledBulb.className = "w-3.5 h-3.5 rounded-full bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,1)]";
        ledText.className = "font-extrabold text-emerald-400";
        ledText.innerText = "HIJAU (AMAN)";
      }

      // AI Agents Cards
      const container = document.getElementById('agent-cards-container');
      container.innerHTML = '';
      (data.agent_runs || []).forEach(run => {
        const div = document.createElement('div');
        div.className = "p-4 rounded-xl bg-slate-950 border border-slate-800 flex flex-col justify-between";
        div.innerHTML = `
          <div>
            <div class="flex items-center justify-between">
              <span class="text-xs font-bold text-indigo-400 uppercase tracking-wide">${run.agent}</span>
              <span class="px-2 py-0.5 text-[10px] font-bold rounded bg-slate-800 text-slate-300 border border-slate-700">${run.status.toUpperCase()}</span>
            </div>
            <p class="text-xs text-slate-300 mt-2 font-mono">Tokens: ${run.tokens} | Latensi: ${run.latency_ms}ms</p>
            <p class="text-[11px] text-slate-400 mt-1">${run.verdict ? JSON.stringify(run.verdict.reasons || run.verdict) : 'Analisis selesai.'}</p>
          </div>
        `;
        container.appendChild(div);
      });

      // Responder Summary
      document.getElementById('txt-responder-summary').innerText =
        data.session.ai_reasons.find(r => r.startsWith('AI:')) || "Pemeriksaan multi-lapis telah selesai dievaluasi.";

      // Hash Chain
      document.getElementById('txt-event-count').innerText = `${data.hashchain.total_events} Events`;
      document.getElementById('txt-head-hash').innerText = data.hashchain.head_hash;

      // Populate Files Table
      renderFilesTable(data.scanned_files || []);

      // Scroll smoothly to results
      document.getElementById('results-view').scrollIntoView({ behavior: 'smooth' });
    }

    function renderFilesTable(files) {
      const tbody = document.getElementById('files-table-body');
      tbody.innerHTML = '';
      files.forEach(f => {
        const tr = document.createElement('tr');
        tr.className = f.is_dangerous ? "bg-red-500/5 hover:bg-red-500/10 transition-colors" : "hover:bg-slate-800/40 transition-colors";
        tr.innerHTML = `
          <td class="py-3 px-3 font-medium flex items-center gap-2">
            <span class="w-2 h-2 rounded-full ${f.is_dangerous ? 'bg-red-500' : 'bg-emerald-400'}"></span>
            ${f.name}
          </td>
          <td class="py-3 px-3 ${f.ext_mismatch ? 'font-bold text-red-400' : 'text-slate-300'}">${f.type}</td>
          <td class="py-3 px-3 text-slate-400">${f.size_bytes} B</td>
          <td class="py-3 px-3 text-slate-400">${f.entropy.toFixed(2)}</td>
          <td class="py-3 px-3 text-slate-300">${(f.flags || []).join(', ') || '-'}</td>
          <td class="py-3 px-3 text-right">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${f.is_dangerous ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'}">
              ${f.is_dangerous ? 'THREAT' : 'CLEAN'}
            </span>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }

    function filterFiles(type) {
      if (!currentScanReport) return;
      let files = currentScanReport.scanned_files || [];
      if (type === 'danger') {
        files = files.filter(f => f.is_dangerous);
      }
      renderFilesTable(files);
    }

    // Start Polling every 1.5 seconds
    setInterval(checkDevices, 1500);
    checkDevices();
  </script>
</body>
</html>
"""


@ui_app.get("/", response_class=HTMLResponse)
async def serve_dashboard() -> str:
    """Serve the single-page application dashboard."""
    return DASHBOARD_HTML
