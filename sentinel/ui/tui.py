"""Interactive Terminal TUI for USB Sentinel Station using Rich.

Run via:
    ./.venv/bin/python -m sentinel.ui.tui
"""

import asyncio
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

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
from sentinel.ui.cleaner import sanitize_flashdisk
from sentinel.ui.device_scanner import list_connected_usb_devices
from sentinel.util.config import PolicyConfig, SentinelConfig

console = Console()
DB_PATH = Path("sentinel_audit.db")
init_database(DB_PATH)


async def execute_scan(target_device: dict) -> tuple[str, list[str]]:
    mount_dir = Path(target_device["mount_point"])
    console.print("\n[bold cyan]⚡ MEMULAI PEMERIKSAAN 4-LAYER SENTINEL...[/bold cyan]")

    with console.status("[bold green]Layer 1: Device Guard memeriksa USB Descriptor (0x08 Mass Storage)...", spinner="dots"):
        await asyncio.sleep(0.5)

    with console.status("[bold yellow]Layer 2: Scanning Deterministik (ClamAV, YARA, Macro, Zip Bomb)...", spinner="bouncingBar"):
        config = SentinelConfig(mode="laptop_mock")
        config.agents.always_ai = True
        policy_config = PolicyConfig()

        usb_source = MockUsbSource(default_mount_dir=mount_dir)
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
            device_id=target_device["node"],
            vendor_id="0781",
            product_id="5567",
            serial_number=target_device["serial"],
            device_class=0x00,
            interface_classes=[0x08],
            manufacturer=target_device["vendor"],
            product_name=target_device["model"],
        )

    with console.status("[bold magenta]Layer 3: AI Multi-Agent Triage (Static Analyst + Intel + Critic)...", spinner="aesthetic"):
        start_ts = time.time()
        event = UsbEvent(event_type="CONNECT", device=device_desc, timestamp=start_ts)
        decision = await station.handle_usb_event(event)
        duration_s = round(time.time() - start_ts, 2)

    assert decision is not None

    # Render Final Decision Panel
    is_blocked = decision.action == "BLOCK"
    panel_color = "red" if is_blocked else "green"
    icon = "🔴" if is_blocked else "🟢"

    body_text = Text()
    body_text.append(f"Keputusan Akhir : {decision.action}\n", style=f"bold {panel_color}")
    body_text.append(f"Total Skor Risiko: {decision.risk:.4f} / 1.00\n", style="bold white")
    body_text.append(f"Durasi Triage   : {duration_s} detik\n", style="dim")
    body_text.append(f"Sesi Audit ID   : {decision.session_id}\n\n", style="dim")

    body_text.append("Alasan Deterministik (Layer 2):\n", style="bold underline")
    for r in decision.deterministic_reasons:
        body_text.append(f"  • {r}\n", style="yellow")
    if not decision.deterministic_reasons:
        body_text.append("  • Tidak ada indikator lokal berbahaya.\n", style="dim")

    body_text.append("\nAnalisis AI Agents (Layer 3):\n", style="bold underline")
    for r in decision.ai_reasons:
        body_text.append(f"  • {r}\n", style="cyan")

    console.print(
        Panel(
            body_text,
            title=f"{icon} [bold {panel_color}]HASIL POLICY ENGINE: {decision.action}[/bold {panel_color}]",
            border_style=panel_color,
            padding=(1, 2),
        )
    )

    # Scanned Files Table
    files_table = Table(title="📁 Berkas yang Discan pada Flashdisk", border_style="dim")
    files_table.add_column("Nama Berkas", style="white")
    files_table.add_column("Tipe", style="cyan")
    files_table.add_column("Ukuran", justify="right", style="dim")
    files_table.add_column("Entropi", justify="right", style="dim")
    files_table.add_column("Flags / Deteksi", style="yellow")
    files_table.add_column("Status", justify="center")

    scan_res = station.scan_engine.scan_mount(mount_dir)
    bad_files: list[str] = []
    for f in scan_res.file_features:
        threat_keys = (
            "macro",
            "powershell",
            "autorun",
            "shortcut",
            "double",
            "disguised",
            "ransomware",
            "wscript",
            "reverse_shell",
            "high_entropy",
            "type_mismatch",
        )
        is_bad = bool(
            f.av_hits
            or f.yara_hits
            or f.ext_mismatch
            or any(any(k in fl for k in threat_keys) for fl in f.flags)
        )
        if is_bad and f.sanitized_name:
            bad_files.append(f.sanitized_name)
        status_text = "[bold red]THREAT[/bold red]" if is_bad else "[bold green]CLEAN[/bold green]"
        flags_str = ", ".join(f.flags + f.av_hits + f.yara_hits) or "-"
        files_table.add_row(
            f.sanitized_name,
            f.detected_type,
            f"{f.size} B",
            f"{f.entropy:.2f}",
            flags_str,
            status_text,
        )

    console.print(files_table)

    # AI Agent Triage Table (Layer 3)
    agent_table = Table(title="🤖 Tim AI Agent Triage (Layer 3)", border_style="dim")
    agent_table.add_column("Agent", style="bold magenta")
    agent_table.add_column("Model", style="dim")
    agent_table.add_column("Tokens", justify="right", style="cyan")
    agent_table.add_column("Latensi", justify="right", style="dim")
    agent_table.add_column("Biaya ($)", justify="right", style="green")
    agent_table.add_column("Status", justify="center")

    with db_session(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT agent, model, tokens_in, tokens_out, cost_est, latency_ms, status
            FROM agent_runs WHERE session_id = ?;
            """,
            (decision.session_id,),
        )
        agent_rows = cursor.fetchall()

    for row in agent_rows:
        total_tokens = row["tokens_in"] + row["tokens_out"]
        st = "[bold green]SUCCESS[/bold green]" if row["status"] == "success" else f"[bold red]{row['status']}[/bold red]"
        agent_table.add_row(
            row["agent"],
            row["model"],
            str(total_tokens),
            f"{row['latency_ms']} ms",
            f"${row['cost_est']:.6f}",
            st,
        )

    if agent_rows:
        console.print(agent_table)

    # Hash Chain Status
    valid, count, _ = verify_hashchain(DB_PATH)
    _, head_hash = export_head(DB_PATH)
    chain_status = "[bold green]VALID / UTUH[/bold green]" if valid else "[bold red]RUSAK[/bold red]"
    console.print(f"[dim]🔒 SQLite Hash Chain: {chain_status} | Events: {count} | Head: {head_hash[:24]}...[/dim]\n")

    return decision.action, bad_files


def run_tui() -> None:
    console.clear()
    console.print(
        Panel(
            "[bold white]USB SENTINEL - SHEEP-DIP AIR-GAPPED HARDWARE SANITIZATION[/bold white]\n"
            "[dim]Sistem Deteksi Flashdisk Otomatis & AI Multi-Agent Triage[/dim]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    while True:
        devices = list_connected_usb_devices()
        if not devices:
            console.print("[bold yellow]⚠️  0 Perangkat USB Terhubung.[/bold yellow] Menunggu flashdisk dicolokkan... (Ctrl+C untuk keluar)", end="\r")
            time.sleep(1.5)
            continue

        # Flashdisk detected
        dev = devices[0]
        console.print(f"\n[bold green]✨ FLASHDISK TERDETEKSI:[/bold green] [bold cyan]{dev['label']}[/bold cyan]")
        console.print(f"  • Node       : [bold white]{dev['node']}[/bold white]")
        console.print(f"  • Serial     : [dim]{dev['serial']}[/dim]")
        console.print(f"  • UUID       : [bold yellow]{dev['uuid']}[/bold yellow]")
        console.print(f"  • Kapasitas  : [bold green]{dev['size_gb']} GB[/bold green] ({dev['fs_type'].upper()})")
        console.print(f"  • Mount Point: [dim]{dev['mount_point']}[/dim]\n")

        try:
            choice = input("👉 Tekan [ENTER] untuk Mulai Scan Sanitasi (atau ketik 'q' untuk keluar): ").strip()
            if choice.lower() == "q":
                console.print("[yellow]Keluar dari stasiun Sentinel. Sampai jumpa![/yellow]")
                break

            action, threats = asyncio.run(execute_scan(dev))
            if action == "BLOCK" and threats:
                console.print(f"[bold red]⚠️  Terdeteksi {len(threats)} berkas berbahaya pada flashdisk![/bold red]")
                c_clean = input("👉 Ketik [C] untuk Bersihkan & Netralkan Flashdisk Sekarang (atau [ENTER] untuk Lewati): ").strip()
                if c_clean.lower() == "c":
                    with console.status("[bold green]Mengisolasi berkas jahat ke .sentinel_quarantine dan membersihkan flashdisk..."):
                        res = sanitize_flashdisk(
                            mount_point=Path(dev["mount_point"]),
                            dangerous_file_names=threats,
                            action="quarantine",
                            db_path=DB_PATH,
                        )
                    console.print(f"[bold green]✓ Selesai! {len(res['quarantined'])} berkas berhasil diisolasi ke karantina.[/bold green]")
                    console.print("[bold cyan]Memverifikasi ulang keamanan flashdisk...[/bold cyan]")
                    asyncio.run(execute_scan(dev))

            input("\nTekan [ENTER] untuk kembali ke pemantauan port USB...")
            console.clear()

        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Dihentikan oleh operator. Layanan dihentikan.[/yellow]")
            break


if __name__ == "__main__":
    run_tui()
