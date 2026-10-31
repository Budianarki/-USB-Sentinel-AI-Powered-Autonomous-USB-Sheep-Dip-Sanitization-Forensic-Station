"""USB Sentinel Daemon Entrypoint (python -m sentinel).

Provides:
- CLI argument parsing (--config, --db).
- Graceful shutdown handling on SIGINT / SIGTERM.
- Clean unmount and resource release during shutdown.
- Background periodic hash chain anchoring task.
"""

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

from sentinel.main import SentinelStation, create_station
from sentinel.store.hashchain import export_head

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinel.daemon")


async def run_periodic_anchoring(
    station: SentinelStation,
    interval_s: int,
    stop_event: asyncio.Event,
) -> None:
    """Periodically export and broadcast hash chain head to external anchor (Telegram)."""
    if interval_s <= 0 or not station.db_path:
        return

    logger.info("Started periodic hash chain anchor task (interval=%ds)", interval_s)
    try:
        while not stop_event.is_set():
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=float(interval_s))
                break  # Stop requested
            except TimeoutError:
                count, head_hash = export_head(station.db_path)
                logger.info("Broadcasting periodic hash chain anchor (count=%d)", count)
                station.telegram_notifier.send_hashchain_anchor(count, head_hash)
    except asyncio.CancelledError:
        pass


async def async_main(config_path: str | None, db_path: str | None) -> None:
    """Async daemon lifecycle orchestrator."""
    resolved_config = Path(config_path) if config_path else None
    resolved_db = Path(db_path) if db_path else Path("sentinel_audit.db")

    logger.info("Initializing USB Sentinel Daemon (config=%s, db=%s)", resolved_config, resolved_db)
    station = create_station(config_path=resolved_config, db_path=resolved_db)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _handle_shutdown_signal(sig_name: str) -> None:
        logger.info("Received shutdown signal %s, initiating graceful teardown...", sig_name)
        stop_event.set()

    # Register OS signals for graceful shutdown
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_shutdown_signal, sig.name)
        except (NotImplementedError, RuntimeError):
            # Fallback for environments lacking add_signal_handler
            pass

    # Start periodic anchor background task
    anchor_interval = station.config.notify.telegram.anchor_interval_s
    anchor_task = asyncio.create_task(
        run_periodic_anchoring(station, anchor_interval, stop_event)
    )

    # Start station event loop as a concurrent task
    station_task = asyncio.create_task(station.run_loop())

    # Wait for either shutdown signal or station loop failure
    _done, _pending = await asyncio.wait(
        [station_task, asyncio.create_task(stop_event.wait())],
        return_when=asyncio.FIRST_COMPLETED,
    )

    logger.info("Shutting down USB Sentinel Station...")

    # Stop background tasks
    anchor_task.cancel()
    station_task.cancel()
    await asyncio.gather(anchor_task, station_task, return_exceptions=True)

    # If a device is currently mounted or being scanned, cleanly unmount it
    if station.active_device:
        logger.warning("Unmounting active device %s during shutdown...", station.active_device.device_id)
        try:
            await station.usb_source.unmount(station.active_device)
        except Exception as err:  # noqa: BLE001
            logger.error("Failed to unmount device during shutdown: %s", err)

    # Display shutdown status and turn off LED
    station.display.show("OFFLINE", ["USB Sentinel", "Layanan dihentikan."])
    station.indicator.set_state("off")
    logger.info("USB Sentinel Daemon gracefully terminated.")


def cli_entrypoint() -> None:
    """CLI entrypoint for python -m sentinel."""
    parser = argparse.ArgumentParser(
        prog="python -m sentinel",
        description="USB Sentinel - Air-gapped Sheep-Dip Flashdisk Inspection Station",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        default=None,
        help="Path to sentinel configuration YAML (default: config/sentinel.yaml or fallback)",
    )
    parser.add_argument(
        "--db",
        type=str,
        default="sentinel_audit.db",
        help="Path to SQLite database for audit log and hash chain (default: sentinel_audit.db)",
    )

    args = parser.parse_args()

    try:
        asyncio.run(async_main(config_path=args.config, db_path=args.db))
    except KeyboardInterrupt:
        logger.info("Process interrupted by user (SIGINT). Exiting.")
        sys.exit(0)


if __name__ == "__main__":
    cli_entrypoint()
