"""GPIO and peripheral mock implementation (LEDs, Buzzer, Tamper switch, DoorLock)."""

from collections.abc import Callable
from typing import Literal

from sentinel.platform.base import DoorLock, Indicator, Tamper


class MockIndicator(Indicator):
    """Mock implementation of LED and Buzzer indicators."""

    def __init__(self) -> None:
        self.current_state: Literal["off", "green", "yellow", "red"] = "off"
        self.state_history: list[Literal["off", "green", "yellow", "red"]] = ["off"]
        self.beep_history: list[str] = []

    def set_state(self, color: Literal["off", "green", "yellow", "red"]) -> None:
        """Set LED indicator state."""
        self.current_state = color
        self.state_history.append(color)

    def beep(self, pattern: str) -> None:
        """Record audible beep pattern."""
        self.beep_history.append(pattern)


class MockTamper(Tamper):
    """Mock implementation of chassis intrusion tamper switch."""

    def __init__(self) -> None:
        self._triggered: bool = False
        self._callbacks: list[Callable[[], None]] = []

    def on_tamper(self, callback: Callable[[], None]) -> None:
        """Register a callback for tamper trigger."""
        self._callbacks.append(callback)

    def is_triggered(self) -> bool:
        """Check if tamper is currently triggered."""
        return self._triggered

    def trigger(self) -> None:
        """Simulate a physical chassis tamper event."""
        self._triggered = True
        for cb in self._callbacks:
            cb()

    def reset(self) -> None:
        """Reset tamper state to normal."""
        self._triggered = False


class MockDoorLock(DoorLock):
    """Mock implementation of physical door lock (fail closed: locked by default)."""

    def __init__(self) -> None:
        self._locked: bool = True
        self.unlock_count: int = 0

    def is_locked(self) -> bool:
        return self._locked

    def unlock(self) -> None:
        self._locked = False
        self.unlock_count += 1

    def lock(self) -> None:
        self._locked = True
