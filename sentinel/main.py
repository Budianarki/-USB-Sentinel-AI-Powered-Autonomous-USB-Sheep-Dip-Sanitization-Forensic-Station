"""Main entrypoint and state machine orchestrator for USB Sentinel."""

import asyncio
import hashlib
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from sentinel.agents.schemas import SessionContext
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

        try:
            # 1. DEVICE_DETECTED
            self.state = "DEVICE_DETECTED"
            self.indicator.set_state("yellow")
            self.display.show(
                "DETECTED", [f"Serial: {device.serial_number[:16]}", "Checking class..."]
            )

            # 2. GUARD_CHECK (Layer 1)
            self.state = "GUARD_CHECK"
            # Rule: Only allowed classes permitted (default 0x08 Mass Storage).
            # If any HID (0x03) or unallowed class is found -> BLOCK immediately.
            disallowed = [
                cls_id
                for cls_id in device.interface_classes
                if cls_id not in self.config.usb.allow_classes
            ]
            if disallowed or (0x03 in device.interface_classes):
                decision = self.policy_engine.evaluate_guard_violation(
                    session_id=session_id,
                    disallowed_classes=disallowed or [0x03],
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

            # 5. DECIDING (Layer 4)
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
                    has_risky_type=scan_res.has_risky_type,
                    av_or_yara_hit=scan_res.av_or_yara_hit,
                    deterministic_reasons=scan_res.deterministic_reasons,
                )

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


def create_station(config_path: str | Path | None = None) -> SentinelStation:
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
    )
