"""Rate limiting and spending cap controls for USB Sentinel Gateway (Invariant 2 & 11).

Protects against:
- High API cost spikes via daily and monthly spending caps
- Request flooding via per-device token bucket rate limiting
- Fail-closed behavior: exceeding limits causes Gateway to return errors,
  prompting the Sentinel station to fail-closed to QUARANTINE.
"""

import time
from collections import defaultdict
from dataclasses import dataclass


class RateLimitExceededError(Exception):
    """Raised when a device exceeds maximum request frequency."""


class SpendingCapExceededError(Exception):
    """Raised when estimated token spend exceeds daily/monthly budget."""


@dataclass
class UsageStats:
    total_tokens_in: int = 0
    total_tokens_out: int = 0
    estimated_cost_usd: float = 0.0
    request_count: int = 0


class BudgetAndRateLimiter:
    """Enforces rate limits and cost controls across devices."""

    def __init__(
        self,
        max_requests_per_minute: int = 60,
        daily_spending_cap_usd: float = 5.0,
        cost_per_1k_input_tokens: float = 0.0015,
        cost_per_1k_output_tokens: float = 0.0075,
    ) -> None:
        self.max_requests_per_minute = max_requests_per_minute
        self.daily_spending_cap_usd = daily_spending_cap_usd
        self.cost_per_1k_in = cost_per_1k_input_tokens
        self.cost_per_1k_out = cost_per_1k_output_tokens

        self._request_timestamps: dict[str, list[float]] = defaultdict(list)
        self._daily_usage: dict[str, UsageStats] = defaultdict(UsageStats)
        self._today_str = self._get_today_str()

    def _get_today_str(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime())

    def check_limits(self, device_token: str) -> None:
        """Validate request frequency and current spending before LLM call."""
        now = time.time()
        today = self._get_today_str()

        # Reset daily stats if day changed
        if today != self._today_str:
            self._today_str = today
            self._daily_usage.clear()

        # 1. Check spending cap
        stats = self._daily_usage[device_token]
        if stats.estimated_cost_usd >= self.daily_spending_cap_usd:
            raise SpendingCapExceededError(
                f"Daily spending cap of ${self.daily_spending_cap_usd:.2f} exceeded for device "
                f"(current: ${stats.estimated_cost_usd:.4f})"
            )

        # 2. Check rate limit (sliding 60-second window)
        window_start = now - 60.0
        timestamps = self._request_timestamps[device_token]
        # Prune old timestamps
        timestamps = [ts for ts in timestamps if ts > window_start]
        self._request_timestamps[device_token] = timestamps

        if len(timestamps) >= self.max_requests_per_minute:
            raise RateLimitExceededError(
                f"Rate limit of {self.max_requests_per_minute} requests/minute exceeded for device."
            )

        timestamps.append(now)

    def record_usage(
        self,
        device_token: str,
        tokens_in: int,
        tokens_out: int,
    ) -> float:
        """Record token consumption and update estimated cost in USD. Returns cost for this call."""
        cost = (tokens_in / 1000.0 * self.cost_per_1k_in) + (
            tokens_out / 1000.0 * self.cost_per_1k_out
        )

        stats = self._daily_usage[device_token]
        stats.total_tokens_in += tokens_in
        stats.total_tokens_out += tokens_out
        stats.estimated_cost_usd += cost
        stats.request_count += 1

        return round(cost, 6)

    def get_device_usage(self, device_token: str) -> UsageStats:
        """Return usage statistics for device."""
        return self._daily_usage[device_token]

