"""Tests for Linux-specific hardware and udev integration.

All real hardware Linux-specific tests are clearly marked with @pytest.mark.linux_only
and skipped automatically on non-Linux operating systems (Windows, macOS).
Subprocess and command-generation tests run across all platforms via mocks.
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.platform.base import UsbDeviceDescriptor
from sentinel.platform.linux_udev import LinuxUdevSource, PlatformNotSupportedError


def test_linux_udev_on_non_linux_raises_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """On non-Linux platforms (e.g. Windows), instantiating LinuxUdevSource must raise PlatformNotSupportedError."""
    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(PlatformNotSupportedError) as exc_info:
        LinuxUdevSource()

    assert "requires Linux" in str(exc_info.value)


def test_build_mount_command_contains_invariant_8_flags(tmp_path: Path) -> None:
    """Invariant 8: build_mount_command must enforce ro,noexec,nosuid,nodev."""
    # Use object.__new__ to bypass __init__ on non-Linux OS
    source = object.__new__(LinuxUdevSource)
    source._mount_base_dir = tmp_path

    device = UsbDeviceDescriptor(
        device_id="/dev/sdb1",
        serial_number="SECURE_DRIVE_001",
    )
    mount_point = tmp_path / "usb_SECURE_DRIVE_001"
    cmd = source.build_mount_command(device, mount_point)

    assert cmd[0] == "mount"
    assert "-o" in cmd
    opt_index = cmd.index("-o") + 1
    options = cmd[opt_index].split(",")
    assert "ro" in options
    assert "noexec" in options
    assert "nosuid" in options
    assert "nodev" in options
    assert cmd[-2] == "/dev/sdb1"
    assert cmd[-1] == str(mount_point)


@pytest.mark.asyncio
async def test_linux_mount_executes_hardened_flags_via_mock_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify mount() executes subprocess with exact ro,noexec,nosuid,nodev flags."""
    # Monkeypatch platform to simulate Linux
    monkeypatch.setattr(sys, "platform", "linux")

    source = object.__new__(LinuxUdevSource)
    source._mount_base_dir = tmp_path
    source._mounted_devices = {}

    device = UsbDeviceDescriptor(
        device_id="/dev/sdb1",
        serial_number="TEST_USB_888",
    )

    # Mock subprocess execution
    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.communicate = AsyncMock(return_value=(b"", b""))

    with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = mock_process

        res = await source.mount(device)

        assert res.success is True
        assert res.read_only is True
        assert mock_exec.called

        called_args = mock_exec.call_args[0]
        assert called_args[0] == "mount"
        assert called_args[1] == "-o"
        assert called_args[2] == "ro,noexec,nosuid,nodev"
        assert called_args[3] == "/dev/sdb1"
        assert "usb_TEST_USB_888" in called_args[4]


@pytest.mark.linux_only
@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="Linux-only test: requires udev and root mount"
)
def test_linux_udev_initialization_on_linux() -> None:
    """Verify LinuxUdevSource initialization on Linux."""
    source = LinuxUdevSource()
    assert source is not None
