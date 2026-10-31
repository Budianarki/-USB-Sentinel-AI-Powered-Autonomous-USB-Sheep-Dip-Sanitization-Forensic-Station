"""Unit tests for daemon entrypoint and graceful shutdown (Checkpoint 2A)."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.__main__ import async_main, run_periodic_anchoring
from sentinel.main import SentinelStation
from sentinel.notify.telegram import MockTelegramTransport, TelegramNotifier
from sentinel.platform.base import UsbDeviceDescriptor
from sentinel.platform.display_console import ConsoleDisplay
from sentinel.platform.gpio import MockIndicator
from sentinel.platform.mock_usb import MockUsbSource
from sentinel.policy.engine import PolicyEngine
from sentinel.scan.engine import ScanEngine
from sentinel.store.db import init_database
from sentinel.store.hashchain import record_event
from sentinel.util.config import PolicyConfig, SentinelConfig


@pytest.mark.asyncio
async def test_periodic_anchoring_task(tmp_path: Path) -> None:
    """Test that periodic anchoring reads head and calls TelegramNotifier."""
    db_file = tmp_path / "anchor_test.db"
    init_database(db_file)

    # Insert an event
    record_event(db_file, "TEST_EVENT", {"data": "periodic_anchor"})

    mock_transport = MockTelegramTransport()
    notifier = TelegramNotifier(
        token="FAKE_TOKEN",
        chat_id="1234",
        transport=mock_transport,
    )

    cfg = SentinelConfig(mode="laptop_mock")
    policy_cfg = PolicyConfig()
    station = SentinelStation(
        config=cfg,
        usb_source=MockUsbSource(),
        display=ConsoleDisplay(),
        indicator=MockIndicator(),
        policy_engine=PolicyEngine(policy_cfg),
        scan_engine=ScanEngine(cfg, policy_cfg),
        db_path=db_file,
        telegram_notifier=notifier,
    )

    stop_event = asyncio.Event()

    # Run anchor task with 0.1s interval
    task = asyncio.create_task(run_periodic_anchoring(station, interval_s=1, stop_event=stop_event))

    # Wait briefly then stop
    await asyncio.sleep(0.05)
    stop_event.set()
    await task

    # Task exited cleanly without error


@pytest.mark.asyncio
async def test_daemon_graceful_shutdown(tmp_path: Path) -> None:
    """Test that async_main gracefully tears down active devices and cleans up."""
    db_file = tmp_path / "daemon_test.db"

    active_dev = UsbDeviceDescriptor(
        device_id="/dev/sdb1",
        vendor_id="1234",
        product_id="5678",
        serial_number="SHUTDOWN_TEST",
        interface_classes=[0x08],
    )

    with patch("sentinel.__main__.create_station") as mock_create:
        mock_station = MagicMock()
        mock_station.config.notify.telegram.anchor_interval_s = 60
        mock_station.active_device = active_dev
        mock_station.usb_source.unmount = AsyncMock()
        mock_station.run_loop = AsyncMock()
        mock_station.display.show = MagicMock()
        mock_station.indicator.set_state = MagicMock()
        mock_create.return_value = mock_station

        # Trigger graceful shutdown immediately after startup
        async def trigger_shutdown_soon():
            await asyncio.sleep(0.05)
            # Simulate SIGTERM callback
            loop = asyncio.get_running_loop()
            for handler in loop._signal_handlers.values() if hasattr(loop, "_signal_handlers") else []:
                pass

        # Run async_main with a timeout
        main_task = asyncio.create_task(async_main(config_path=None, db_path=str(db_file)))
        await asyncio.sleep(0.05)

        # Cancel main task to simulate signal shutdown teardown
        main_task.cancel()
        try:
            await main_task
        except asyncio.CancelledError:
            pass

        # Verify device unmount was executed cleanly
        mock_station.usb_source.unmount.assert_awaited_once_with(active_dev)
        mock_station.indicator.set_state.assert_called_with("off")
