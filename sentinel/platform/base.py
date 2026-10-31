"""Platform abstraction interfaces for USB Sentinel.

Defines abstract base classes for:
- UsbSource (USB insertion/removal events and hardened mount operations)
- Display (visual feedback to user)
- Indicator (LEDs and buzzers)
- Tamper (physical chassis tamper switch)
- DoorLock (access control integration - empty interface until Phase 5)
"""

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class UsbDeviceDescriptor(BaseModel):
    """Metadata describing a detected USB device."""

    device_id: str
    vendor_id: str = "0000"
    product_id: str = "0000"
    serial_number: str = "UNKNOWN"
    device_class: int = 0x00
    interface_classes: list[int] = Field(default_factory=lambda: [0x08])
    manufacturer: str | None = None
    product_name: str | None = None


class UsbEvent(BaseModel):
    """Event emitted when a USB device is plugged in or removed."""

    event_type: Literal["CONNECT", "DISCONNECT"]
    device: UsbDeviceDescriptor
    timestamp: float


class MountResult(BaseModel):
    """Result of mounting a USB device partition."""

    success: bool
    mount_point: Path | None = None
    error_message: str | None = None
    read_only: bool = True


class UsbSource(ABC):
    """Interface for detecting and mounting USB storage devices."""

    @abstractmethod
    def events(self) -> AsyncIterator[UsbEvent]:
        """Async stream of USB connect/disconnect events."""

    @abstractmethod
    async def mount(self, device: UsbDeviceDescriptor) -> MountResult:
        """Mount partition with hardened security flags (ro,noexec,nosuid,nodev)."""

    @abstractmethod
    async def unmount(self, device: UsbDeviceDescriptor) -> None:
        """Unmount and sync partition."""


class Display(ABC):
    """Interface for user-facing visual display."""

    @abstractmethod
    def show(self, status: str, lines: list[str]) -> None:
        """Display status header and detailed lines."""

    @abstractmethod
    def clear(self) -> None:
        """Clear display content."""


class Indicator(ABC):
    """Interface for visual (LED) and audible (Buzzer) signals."""

    @abstractmethod
    def set_state(self, color: Literal["off", "green", "yellow", "red"]) -> None:
        """Set LED indicator state."""

    @abstractmethod
    def beep(self, pattern: str) -> None:
        """Emit audible beep pattern (e.g., 'short', 'alarm', 'success')."""


class Tamper(ABC):
    """Interface for physical chassis intrusion detection."""

    @abstractmethod
    def on_tamper(self, callback: Callable[[], None]) -> None:
        """Register a callback to invoke when physical tamper is detected."""

    @abstractmethod
    def is_triggered(self) -> bool:
        """Return True if tamper condition currently exists."""


class DoorLock(ABC):
    """Interface for physical door lock integration (reserved for Phase 5)."""

    @abstractmethod
    def is_locked(self) -> bool:
        """Return True if door is locked (default: True, fail closed)."""

    @abstractmethod
    def unlock(self) -> None:
        """Temporarily unlock door."""

    @abstractmethod
    def lock(self) -> None:
        """Lock door."""
