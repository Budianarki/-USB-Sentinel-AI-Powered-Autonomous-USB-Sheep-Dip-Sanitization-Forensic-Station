"""Main entrypoint and state machine orchestrator for USB Sentinel."""

import asyncio
import hashlib
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from sentinel.agents.schemas import SessionContext
from sentinel.guard.usb_class import evaluate_device_class
from sentinel.notify.telegram import TelegramNotifier
from sentinel.platform.base import (
    Display,
    DoorLock,
    Indicator,
    Tamper,
    UsbDeviceDescriptor,
    UsbEvent,
    UsbSource,
)
from sentinel.platform.display_console import ConsoleDisplay
from sentinel.platform.gpio import MockDoorLock, MockIndicator, MockTamper
from sentinel.platform.mock_usb import MockUsbSource
from sentinel.policy.engine import PolicyEngine
from sentinel.policy.schemas import Decision
from sentinel.scan.engine import ScanEngine
from sentinel.util.config import SentinelConfig, load_policy_config, load_sentinel_config

SentinelState = Literal[
    "IDLE",
    "DEVICE_DETECTED",
    "GUARD_CHECK",
    "MOUNTED",
    "SCANNING",
    "TRIAGE",
    "DECIDING",
    "ALLOWED",
    "QUARANTINED",
    "BLOCKED",
    "REVIEW",
    "REPORTING",
    "UNMOUNT",
    "ABORTED",
]


class SentinelStation:
    """Core state machine managing USB inspection lifecycle."""

    def __init__(
        self,
        config: SentinelConfig,
        usb_source: UsbSource,
        display: Display,
        indicator: Indicator,
        tamper: Tamper | None = None,
        door_lock: DoorLock | None = None,
        policy_engine: PolicyEngine | None = None,
        scan_engine: ScanEngine | None = None,
        db_path: Path | str | None = None,
        telegram_notifier: TelegramNotifier | None = None,
        orchestrator: Any | None = None,
    ) -> None:
        self.config = config
        self.usb_source = usb_source
        self.display = display
        self.indicator = indicator
        self.tamper = tamper or MockTamper()
        self.door_lock = door_lock or MockDoorLock()
        self.policy_engine = policy_engine or PolicyEngine(load_policy_config(config.policy.file))
        self.scan_engine = scan_engine or ScanEngine(
            config=self.config,
            policy_config=self.policy_engine.config,
        )
        self.telegram_notifier = telegram_notifier or TelegramNotifier(
            config=self.config.notify.telegram
        )

        self.db_path = Path(db_path) if db_path else None
        if self.db_path:
            from sentinel.store.db import init_database
            init_database(self.db_path)

        # AI Agent Layer Orchestrator (Fase 3)
        if orchestrator is not None:
            self.orchestrator = orchestrator
        else:
            try:
                from gateway.app import app as gateway_app
                from sentinel.agents.client import GatewayClient
                from sentinel.agents.orchestrator import AgentOrchestrator
                from sentinel.fusion.risk_fusion import RiskFusionEngine

                asgi_app = gateway_app if self.config.mode == "laptop_mock" else None
                client = GatewayClient(config=self.config.gateway, asgi_app=asgi_app)
                fusion = RiskFusionEngine(agent_caps=self.policy_engine.config.agent_caps)
                self.orchestrator = AgentOrchestrator(
                    config=self.config.agents,
                    gateway_client=client,
                    risk_fusion=fusion,
                    db_path=self.db_path,
                )
            except Exception as exc:  # noqa: BLE001
                import logging
                logging.getLogger(__name__).warning("Orchestrator initialization fallback: %s", exc)
                self.orchestrator = None

        self.state: SentinelState = "IDLE"
        self.active_session_id: str | None = None
        self.active_device: UsbDeviceDescriptor | None = None
        self.last_decision: Decision | None = None
        self._lock = asyncio.Lock()

        # Wire tamper callback
        self.tamper.on_tamper(self._handle_tamper_event)

    def _handle_tamper_event(self) -> None:
        """Immediate physical tamper response."""
        prefix = "[MOCK] " if self.config.mode == "laptop_mock" else ""
        self.indicator.set_state("red")
        self.indicator.beep("alarm")
        self.display.show(
            f"{prefix}SECURITY ALERT", [f"{prefix}Chassis tamper detected!", "Station locked down."]
        )

    def _calculate_fingerprint(self, dev: UsbDeviceDescriptor) -> str:
        """Calculate SHA256(vid || pid || serial)."""
        raw = f"{dev.vendor_id}:{dev.product_id}:{dev.serial_number}".encode()
        return hashlib.sha256(raw).hexdigest()

    async def handle_usb_event(self, event: UsbEvent) -> Decision | None:
        """Process incoming USB connect/disconnect event through state machine."""
        prefix = "[MOCK] " if self.config.mode == "laptop_mock" else ""
        async with self._lock:
            if event.event_type == "CONNECT":
                # Rule: Only one active USB session at a time. Reject second insertion with alarm.
                if self.state != "IDLE":
                    self.indicator.beep("alarm")
                    self.display.show(
                        f"{prefix}REJECTED",
                        [f"{prefix}Colokan kedua ditolak!", "Sesi lain sedang aktif."],
                    )
                    return None

                return await self._run_session(event.device)

            elif event.event_type == "DISCONNECT":
                if (
                    self.active_device
                    and self.active_device.device_id == event.device.device_id
                    and self.state in ("DEVICE_DETECTED", "GUARD_CHECK", "MOUNTED", "SCANNING")
                ):
                    # Forced unplug during scan -> ABORTED, no ALLOW.
                    self.state = "ABORTED"
                    self.indicator.set_state("red")
                    self.indicator.beep("alarm")
                    self.display.show(
                        f"{prefix}ABORTED",
                        [f"{prefix}Perangkat dicabut paksa!", "Pemeriksaan dibatalkan."],
                    )
                    await self.usb_source.unmount(event.device)
                    self.active_device = None
                    self.active_session_id = None
                    self.state = "IDLE"
                return None

        return None

    async def _run_session(self, device: UsbDeviceDescriptor) -> Decision:
        """Execute full inspection lifecycle for a single connected USB device."""
        session_id = str(uuid.uuid4())
        self.active_session_id = session_id
        self.active_device = device

        now_utc = datetime.now(UTC)
        fingerprint = self._calculate_fingerprint(device)
        _context = SessionContext(
            session_id=session_id,
            device_fingerprint=fingerprint,
            hour_of_day=now_utc.hour,
            recent_events=0,
        )

        # Initialize session in DB if persistence is active
        if self.db_path:
            try:
                from sentinel.store.db import db_session
                with db_session(self.db_path) as conn:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO devices (fingerprint, first_seen, last_seen, reputation)
                        VALUES (?, ?, ?, ?);
                        """,
                        (fingerprint, now_utc.isoformat(), now_utc.isoformat(), "unknown"),
                    )
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO sessions (id, device_fingerprint, started_at, decision, risk, policy_version, ai_available)
                        VALUES (?, ?, ?, ?, ?, ?, ?);
                        """,
                        (session_id, fingerprint, now_utc.isoformat(), "IN_PROGRESS", 0.0, self.policy_engine.config.version, 0),
                    )
            except Exception as db_init_err:  # noqa: BLE001
                import logging
                logging.getLogger(__name__).warning("Failed to initialize session in DB: %s", db_init_err)

        try:
            # 1. DEVICE_DETECTED
            self.state = "DEVICE_DETECTED"
            self.indicator.set_state("yellow")
            self.display.show(
                "DETECTED", [f"Serial: {device.serial_number[:16]}", "Checking class..."]
            )

            # 2. GUARD_CHECK (Layer 1)
            self.state = "GUARD_CHECK"
            guard_res = evaluate_device_class(
                device=device,
                allow_classes=self.config.usb.allow_classes,
                serial_whitelist_file=self.config.usb.serial_whitelist_file,
            )
            if not guard_res.allowed:
                decision = self.policy_engine.evaluate_guard_violation(
                    session_id=session_id,
                    disallowed_classes=guard_res.disallowed_classes,
                    reasons=guard_res.reasons,
                )
                await self._report_and_cleanup(device, decision)
                return decision

            # 3. MOUNTED (Hardened mount ro,noexec,nosuid,nodev)
            self.state = "MOUNTED"
            self.display.show("MOUNTING", ["Mounting read-only..."])
            mount_res = await self.usb_source.mount(device)
            if not mount_res.success or not mount_res.mount_point:
                # Fail closed on mount failure
                decision = self.policy_engine.evaluate_mount_failure(
                    session_id=session_id,
                    error_message=mount_res.error_message or "Unknown mount error",
                )
                await self._report_and_cleanup(device, decision)
                return decision

            # 4. SCANNING (Layer 2)
            self.state = "SCANNING"
            scan_header = "[MOCK] SCANNING" if self.config.mode == "laptop_mock" else "SCANNING"
            self.display.show(scan_header, ["Pemeriksaan file deterministik..."])
            mount_path = Path(mount_res.mount_point)

            scan_res = self.scan_engine.scan_mount(
                mount_point=mount_path,
                filesystem_type=getattr(mount_res, "filesystem_type", "vfat"),
            )

            # 5. TRIAGE (Layer 3 - AI Agent Layer)
            ai_risk: float = 0.0
            ai_reasons: list[str] = []
            critic_disagreement: bool = False
            ai_available: bool = True

            if (
                self.orchestrator
                and scan_res.file_features
                and (
                    self.config.agents.always_ai
                    or (
                        not scan_res.av_or_yara_hit
                        and any(self.orchestrator._is_file_gray(f) for f in scan_res.file_features)
                    )
                )
            ):
                self.state = "TRIAGE"
                triage_header = "[MOCK] TRIAGE" if self.config.mode == "laptop_mock" else "TRIAGE"
                self.display.show(triage_header, ["AI Agent triage & risk analysis..."])
                try:
                    triage_res = await self.orchestrator.triage_session(
                        session_id=session_id,
                        files=scan_res.file_features,
                        deterministic_risk=scan_res.deterministic_risk,
                        context=_context,
                    )
                    ai_risk = triage_res.ai_risk
                    ai_reasons = triage_res.ai_reasons
                    critic_disagreement = triage_res.critic_disagreement
                    ai_available = triage_res.ai_available
                except Exception as triage_err:  # noqa: BLE001
                    import logging
                    logging.getLogger(__name__).warning("AI triage failed (fail-closed): %s", triage_err)
                    ai_available = False

            # 6. DECIDING (Layer 4)
            self.state = "DECIDING"
            if (
                len(scan_res.file_features) == 0
                and scan_res.scan_complete
                and scan_res.scanners_ok
                and scan_res.filesystem_supported
                and scan_res.deterministic_risk == 0.0
            ):
                # Empty session clean allow
                decision = self.policy_engine.evaluate_empty_session(session_id=session_id)
            else:
                decision = self.policy_engine.decide(
                    session_id=session_id,
                    scan_complete=scan_res.scan_complete,
                    scanners_ok=scan_res.scanners_ok,
                    filesystem_supported=scan_res.filesystem_supported,
                    deterministic_risk=scan_res.deterministic_risk,
                    ai_risk=ai_risk,
                    critic_disagreement=critic_disagreement,
                    has_risky_type=scan_res.has_risky_type,
                    ai_available=ai_available,
                    av_or_yara_hit=scan_res.av_or_yara_hit,
                    deterministic_reasons=scan_res.deterministic_reasons,
                    ai_reasons=ai_reasons,
                )

            # Optional: Responder agent explanation
            if self.orchestrator and "responder" in self.config.agents.enabled and ai_available:
                try:
                    resp_out = await self.orchestrator.responder.generate_incident_report(
                        decision=decision,
                        context=_context,
                    )
                    if resp_out.status == "success" and resp_out.report_text:
                        decision.ai_reasons.append(f"AI: {resp_out.report_text}")
                except Exception as resp_err:  # noqa: BLE001
                    import logging
                    logging.getLogger(__name__).debug("Responder report skipped: %s", resp_err)

            await self._report_and_cleanup(device, decision)
            return decision

        except Exception as exc:  # noqa: BLE001 (Invariant 2: Fail closed on any unexpected exception)
            # Invariant 2: Fail closed on unexpected exception
            decision = self.policy_engine.evaluate_session_failure(
                session_id=session_id,
                error_message=str(exc),
            )
            await self._report_and_cleanup(device, decision)
            return decision

    async def _report_and_cleanup(
        self,
        device: UsbDeviceDescriptor,
        decision: Decision,
    ) -> None:
        """Transition through REPORTING and UNMOUNT back to IDLE."""
        self.state = "REPORTING"
        self.last_decision = decision
        prefix = "[MOCK] " if self.config.mode == "laptop_mock" else ""

        if decision.action == "ALLOW":
            self.indicator.set_state("green")
            self.indicator.beep("success")
            self.display.show(
                f"{prefix}ALLOWED",
                [f"{prefix}Pemeriksaan berhasil bersih.", "Silakan cabut flashdisk."],
            )
        elif decision.action == "BLOCK":
            self.indicator.set_state("red")
            self.indicator.beep("alarm")
            self.display.show(
                f"{prefix}BLOCKED",
                [f"{prefix}PERANGKAT BERBAHAYA!", "Jangan bawa masuk ke ruang server."],
            )
        elif decision.action == "QUARANTINE":
            self.indicator.set_state("yellow")
            self.indicator.beep("warning")
            self.display.show(
                f"{prefix}QUARANTINE",
                [f"{prefix}Flashdisk berisiko ditahan petugas.", "Menunggu verifikasi lanjutan."],
            )
        else:  # HUMAN_REVIEW
            self.indicator.set_state("yellow")
            self.indicator.beep("warning")
            self.display.show(
                f"{prefix}REVIEW",
                [f"{prefix}Menunggu persetujuan analis.", "Jangan cabut flashdisk."],
            )

        # Record event in tamper-evident hashchain if db_path is configured
        if self.db_path:
            try:
                from sentinel.store.db import db_session
                with db_session(self.db_path) as conn:
                    conn.execute(
                        """
                        UPDATE sessions
                        SET ended_at = ?, decision = ?, risk = ?, policy_version = ?, ai_available = ?
                        WHERE id = ?;
                        """,
                        (
                            datetime.now(UTC).isoformat(),
                            decision.action,
                            decision.risk,
                            decision.policy_version,
                            int(decision.ai_available),
                            decision.session_id,
                        ),
                    )
            except Exception as exc:  # noqa: BLE001
                import logging
                logging.getLogger(__name__).warning("Failed to update session in DB: %s", exc)

            try:
                from sentinel.store.hashchain import record_event
                record_event(
                    self.db_path,
                    event_type="SESSION_DECISION",
                    payload={
                        "session_id": decision.session_id,
                        "action": decision.action,
                        "risk": decision.risk,
                        "device_serial": device.serial_number,
                        "policy_version": decision.policy_version,
                        "deterministic_reasons": decision.deterministic_reasons,
                    },
                )
            except Exception as exc:  # noqa: BLE001
                import logging
                logging.getLogger(__name__).warning("Failed to record decision to hashchain: %s", exc)

        # Notify Telegram and broadcast hash chain anchor (fail-safe)
        try:
            self.telegram_notifier.notify_session(
                session_id=decision.session_id,
                decision=decision,
                device_fingerprint=self._calculate_fingerprint(device),
            )
            if self.db_path:
                from sentinel.store.hashchain import export_head
                count, head_hash = export_head(self.db_path)
                self.telegram_notifier.send_hashchain_anchor(count, head_hash)
        except Exception as exc:  # noqa: BLE001
            import logging
            logging.getLogger(__name__).warning("Telegram notification/anchor failed: %s", exc)

        # UNMOUNT
        self.state = "UNMOUNT"
        await self.usb_source.unmount(device)
        self.active_device = None
        self.active_session_id = None
        self.state = "IDLE"

    async def run_loop(self) -> None:
        """Run continuous listener loop."""
        self.display.show("READY", ["USB Sentinel Aktif", "Colokkan flashdisk..."])
        self.indicator.set_state("off")
        async for event in self.usb_source.events():
            await self.handle_usb_event(event)


def create_station(
    config_path: str | Path | None = None,
    db_path: Path | str | None = None,
    telegram_notifier: TelegramNotifier | None = None,
    orchestrator: Any | None = None,
) -> SentinelStation:
    """Factory creating SentinelStation based on configuration mode."""
    cfg = load_sentinel_config(config_path)
    usb_source: UsbSource
    if cfg.mode == "laptop_mock":
        usb_source = MockUsbSource()
        display = ConsoleDisplay()
        indicator = MockIndicator()
        tamper = MockTamper()
        door_lock = MockDoorLock()
    else:
        # IoT mode (Linux)
        from sentinel.platform.linux_udev import LinuxUdevSource

        usb_source = LinuxUdevSource()
        display = ConsoleDisplay()
        indicator = MockIndicator()
        tamper = MockTamper()
        door_lock = MockDoorLock()

    return SentinelStation(
        config=cfg,
        usb_source=usb_source,
        display=display,
        indicator=indicator,
        tamper=tamper,
        door_lock=door_lock,
        db_path=db_path,
        telegram_notifier=telegram_notifier,
        orchestrator=orchestrator,
    )
