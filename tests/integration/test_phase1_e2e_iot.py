"""Phase 1 End-to-End Acceptance Test (CLAUDE.md Section 18).

Enforces strictly IoT mode (mode="iot", NOT laptop_mock):
1. EICAR runtime constructed file = BLOCK
2. Benign clean file = ALLOW
3. Cryptographic hash chain audit log valid via verify-log
4. Three critical fault injection scenarios = NEVER ALLOW (Fail-closed to QUARANTINE):
   - Fault A: ClamAV daemon offline/unreachable
   - Fault B: Parser worker timeout / hung analysis
   - Fault C: Anti-TOCTOU tamper (bytes altered between stream and buffer)

Can run against a real mounted loop filesystem (when SENTINEL_TEST_MOUNT is set by
scripts/linux_root_checks.sh) or an unprivileged test directory.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from sentinel.main import SentinelStation
from sentinel.platform.base import UsbDeviceDescriptor, UsbEvent
from sentinel.platform.display_console import ConsoleDisplay
from sentinel.platform.gpio import MockDoorLock, MockIndicator, MockTamper
from sentinel.platform.mock_usb import MockUsbSource
from sentinel.policy.engine import PolicyEngine
from sentinel.scan.clamav import RUNTIME_EICAR_BYTES, ClamAvScanner, MockClamAvScanner
from sentinel.scan.engine import ScanEngine
from sentinel.scan.static_runner import IsolatedStaticRunner
from sentinel.scan.yara_scanner import MockYaraScanner
from sentinel.store.hashchain import verify_hashchain
from sentinel.util.config import PolicyConfig, PolicyThresholds, ScanConfig, SentinelConfig


@pytest.fixture
def iot_device() -> UsbDeviceDescriptor:
    return UsbDeviceDescriptor(
        device_id="/dev/sdb1",
        vendor_id="0951",
        product_id="1666",
        serial_number="IOT_KINGSTON_FLASH_001",
        interface_classes=[0x08],  # Mass storage
    )


def get_target_mount_dir(fallback_tmp_path: Path) -> Path:
    env_mount = os.environ.get("SENTINEL_TEST_MOUNT")
    if env_mount:
        p = Path(env_mount)
        if p.exists() and p.is_dir():
            return p
    return fallback_tmp_path


@pytest.mark.asyncio
async def test_phase1_e2e_iot_lifecycle_and_fault_scenarios(
    tmp_path: Path,
    iot_device: UsbDeviceDescriptor,
) -> None:
    """Execute complete Phase 1 End-to-End suite in IoT mode."""
    target_mount = get_target_mount_dir(tmp_path / "usb_mount")
    target_mount.mkdir(parents=True, exist_ok=True)
    db_dir = tmp_path / "db_store"
    db_dir.mkdir(parents=True, exist_ok=True)
    db_file = db_dir / "sentinel_audit.db"

    cfg = SentinelConfig(
        mode="iot",  # Strictly IoT mode, NOT laptop_mock
        scan=ScanConfig(
            max_file_mb=100,
            max_static_analysis_mb=50,
            allowed_filesystems=["vfat", "exfat"],
        ),
    )
    pol_cfg = PolicyConfig(
        version="1.0.0",
        thresholds=PolicyThresholds(allow=0.15, review=0.40, block=0.75),
    )
    policy_engine = PolicyEngine(pol_cfg)

    # Scanners configured for IoT testing
    clamav = MockClamAvScanner()  # Detects RUNTIME_EICAR_BYTES without real clamd dependency
    yara_sc = MockYaraScanner()
    static_runner = IsolatedStaticRunner(timeout_s=2.0)

    scan_engine = ScanEngine(
        config=cfg,
        policy_config=pol_cfg,
        clamav_scanner=clamav,
        yara_scanner=yara_sc,
        static_runner=static_runner,
    )

    # MockUsbSource pointing to our target mount directory
    usb_source = MockUsbSource(default_mount_dir=target_mount)
    display = ConsoleDisplay(silent=True)
    indicator = MockIndicator()
    tamper = MockTamper()
    door_lock = MockDoorLock()

    station = SentinelStation(
        config=cfg,
        usb_source=usb_source,
        display=display,
        indicator=indicator,
        tamper=tamper,
        door_lock=door_lock,
        policy_engine=policy_engine,
        scan_engine=scan_engine,
        db_path=db_file,
    )

    # --------------------------------------------------------------------------
    # Test 1: Benign File Session -> Must be ALLOW
    # --------------------------------------------------------------------------
    for f in target_mount.iterdir():
        if f.is_file():
            f.unlink()

    benign_file = target_mount / "notes.txt"
    benign_file.write_text("Security audit log entry: valid text payload.")

    import time
    def make_event() -> UsbEvent:
        return UsbEvent(event_type="CONNECT", device=iot_device, timestamp=time.time())

    decision_benign = await station.handle_usb_event(make_event())
    assert decision_benign is not None
    assert decision_benign.action == "ALLOW", f"Expected ALLOW for benign file, got {decision_benign.action}"
    assert indicator.current_state == "green"

    # --------------------------------------------------------------------------
    # Test 2: Runtime EICAR Signature -> Must be BLOCK
    # --------------------------------------------------------------------------
    eicar_file = target_mount / "malware_test.com"
    eicar_file.write_bytes(RUNTIME_EICAR_BYTES)

    decision_eicar = await station.handle_usb_event(make_event())
    assert decision_eicar is not None
    assert decision_eicar.action == "BLOCK", f"Expected BLOCK for EICAR, got {decision_eicar.action}"
    assert indicator.current_state == "red"
    eicar_file.unlink()

    # --------------------------------------------------------------------------
    # Test 3: Fault A - ClamAV Offline in IoT Mode -> Never ALLOW (Fail-Closed)
    # --------------------------------------------------------------------------
    station.scan_engine.clamav = MockClamAvScanner(simulate_daemon_down=True)
    decision_fault_a = await station.handle_usb_event(make_event())
    assert decision_fault_a is not None
    assert decision_fault_a.action != "ALLOW", f"Fault A (clamd down) emitted ALLOW! Got: {decision_fault_a.action}"
    assert decision_fault_a.action in ("QUARANTINE", "BLOCK")
    station.scan_engine.clamav = clamav  # restore

    # --------------------------------------------------------------------------
    # Test 4: Fault B - Parser Timeout -> Never ALLOW (Fail-Closed)
    # --------------------------------------------------------------------------
    station.scan_engine.static_runner = IsolatedStaticRunner(timeout_s=0.0001)
    decision_fault_b = await station.handle_usb_event(make_event())
    assert decision_fault_b is not None
    assert decision_fault_b.action != "ALLOW", f"Fault B (parser timeout) emitted ALLOW! Got: {decision_fault_b.action}"
    assert decision_fault_b.action in ("QUARANTINE", "BLOCK")
    station.scan_engine.static_runner = static_runner  # restore

    # --------------------------------------------------------------------------
    # Test 5: Fault C - TOCTOU Hash Tamper -> Never ALLOW (Fail-Closed)
    # --------------------------------------------------------------------------
    # Monkeypatch scan_mount to simulate TOCTOU stream tamper
    orig_scan_mount = station.scan_engine.scan_mount

    def tampered_scan_mount(*args, **kwargs):
        kwargs["_simulate_stream_tamper"] = True
        return orig_scan_mount(*args, **kwargs)

    station.scan_engine.scan_mount = tampered_scan_mount
    decision_fault_c = await station.handle_usb_event(make_event())
    assert decision_fault_c is not None
    assert decision_fault_c.action != "ALLOW", f"Fault C (TOCTOU tamper) emitted ALLOW! Got: {decision_fault_c.action}"
    assert decision_fault_c.action in ("QUARANTINE", "BLOCK")
    station.scan_engine.scan_mount = orig_scan_mount  # restore

    # --------------------------------------------------------------------------
    # Test 6: Verify Hash Chain Integrity via verify-log
    # --------------------------------------------------------------------------
    is_valid, count, err = verify_hashchain(db_file)
    assert is_valid is True, f"Hash chain verification failed: {err}"
    assert count == 5, f"Expected 5 recorded session events, got {count}"
    assert err is None

    # Run verify-log CLI subprocess to ensure CLI entrypoint succeeds
    cli_proc = subprocess.run(  # noqa: ASYNC221
        [sys.executable, "-m", "sentinel.store.hashchain", "--db", str(db_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cli_proc.returncode == 0, f"verify-log CLI failed: {cli_proc.stderr}"
    assert "SUCCESS" in cli_proc.stdout and "Hash chain intact" in cli_proc.stdout


def _is_real_clamd_available() -> tuple[bool, str | None, int | None]:
    """Check if real clamd daemon is accessible via unix socket or TCP port 3310."""
    sock_path = "/var/run/clamav/clamd.ctl"
    if Path(sock_path).exists():
        sc = ClamAvScanner(socket_path=sock_path, timeout_s=1.0)
        if sc.is_available():
            return True, sock_path, None
    sc_tcp = ClamAvScanner(host="127.0.0.1", port=3310, timeout_s=1.0)
    if sc_tcp.is_available():
        return True, None, 3310
    return False, None, None


@pytest.mark.asyncio
@pytest.mark.linux_only
@pytest.mark.needs_clamd
async def test_phase1_e2e_iot_with_real_clamd(
    tmp_path: Path,
    iot_device: UsbDeviceDescriptor,
) -> None:
    """Phase 1 E2E variant utilizing the REAL native ClamAV daemon via INSTREAM.

    Verifies with real antivirus:
    1. Benign clean file -> ALLOW
    2. Real EICAR constructed dynamically at runtime -> BLOCK (detected by native clamd)
    """
    if not sys.platform.startswith("linux"):
        pytest.skip("Test is Linux-only")

    clamd_ok, sock_path, tcp_port = _is_real_clamd_available()
    if not clamd_ok:
        pytest.skip(
            "Native clamd daemon is not reachable at /var/run/clamav/clamd.ctl or 127.0.0.1:3310. "
            "Requires clamav-daemon service running."
        )

    # Initialize real ClamAV scanner
    real_clamav = (
        ClamAvScanner(socket_path=sock_path)
        if sock_path
        else ClamAvScanner(host="127.0.0.1", port=tcp_port or 3310)
    )

    target_mount = get_target_mount_dir(tmp_path / "real_clamd_mount")
    target_mount.mkdir(parents=True, exist_ok=True)
    db_file = tmp_path / "real_clamd_audit.db"

    cfg = SentinelConfig(
        mode="iot",
        scan=ScanConfig(
            max_file_mb=100,
            max_static_analysis_mb=50,
            allowed_filesystems=["vfat", "exfat"],
        ),
    )
    pol_cfg = PolicyConfig(
        version="1.0.0",
        thresholds=PolicyThresholds(allow=0.15, review=0.40, block=0.75),
    )
    policy_engine = PolicyEngine(pol_cfg)
    yara_sc = MockYaraScanner()
    static_runner = IsolatedStaticRunner(timeout_s=2.0)

    scan_engine = ScanEngine(
        config=cfg,
        policy_config=pol_cfg,
        clamav_scanner=real_clamav,
        yara_scanner=yara_sc,
        static_runner=static_runner,
    )

    usb_source = MockUsbSource(default_mount_dir=target_mount)
    display = ConsoleDisplay(silent=True)
    indicator = MockIndicator()
    station = SentinelStation(
        config=cfg,
        usb_source=usb_source,
        display=display,
        indicator=indicator,
        policy_engine=policy_engine,
        scan_engine=scan_engine,
        db_path=db_file,
    )

    import time
    def make_event() -> UsbEvent:
        return UsbEvent(event_type="CONNECT", device=iot_device, timestamp=time.time())

    # 1. Benign file with REAL ClamAV -> ALLOW
    for f in target_mount.iterdir():
        if f.is_file():
            f.unlink()
    benign_file = target_mount / "readme.txt"
    benign_file.write_text("Hello, this is a completely clean test file.")

    decision_benign = await station.handle_usb_event(make_event())
    assert decision_benign is not None
    assert decision_benign.action == "ALLOW"
    assert indicator.current_state == "green"

    # 2. Dynamic EICAR with REAL ClamAV -> BLOCK
    eicar_file = target_mount / "eicar_sample.com"
    eicar_file.write_bytes(RUNTIME_EICAR_BYTES)

    decision_eicar = await station.handle_usb_event(make_event())
    assert decision_eicar is not None
    assert decision_eicar.action == "BLOCK"
    assert indicator.current_state == "red"
    assert any("Win.Test.EICAR_HDB-1" in r or "Eicar" in r or "clamav" in r.lower() for r in decision_eicar.deterministic_reasons)

