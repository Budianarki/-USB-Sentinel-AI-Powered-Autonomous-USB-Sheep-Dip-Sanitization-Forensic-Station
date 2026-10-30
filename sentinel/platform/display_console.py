"""Console and in-memory mock display implementation."""

from sentinel.platform.base import Display


class ConsoleDisplay(Display):
    """Display implementation that prints formatted status to console and stores history."""

    def __init__(self, silent: bool = False) -> None:
        self.silent = silent
        self.current_status: str = "IDLE"
        self.current_lines: list[str] = []
        self.history: list[tuple[str, list[str]]] = []

    def show(self, status: str, lines: list[str]) -> None:
        """Update display with status and text lines."""
        self.current_status = status
        self.current_lines = list(lines)
        self.history.append((status, list(lines)))

        if not self.silent:
            border = "=" * 40
            print(f"\n{border}")
            print(f"[USB SENTINEL DISPLAY] STATUS: {status}")
            print("-" * 40)
            for line in lines:
                print(f"  {line}")
            print(f"{border}\n")

    def clear(self) -> None:
        """Clear current display."""
        self.current_status = "IDLE"
        self.current_lines = []
        if not self.silent:
            print("[USB SENTINEL DISPLAY] CLEARED")
