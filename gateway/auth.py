"""Per-device authentication and token verification for USB Sentinel Gateway (Invariant 7)."""

import os

DEFAULT_DEV_TOKENS: set[str] = {
    "sentinel-dev-station-01",
    "sentinel-iot-test-token",
}


class TokenAuthenticator:
    """Validates device bearer tokens against registered credentials."""

    def __init__(self, registered_tokens: set[str] | None = None) -> None:
        self.tokens = set(registered_tokens or DEFAULT_DEV_TOKENS)
        # Also include token from environment if configured
        env_token = os.environ.get("SENTINEL_DEVICE_TOKEN")
        if env_token:
            self.tokens.add(env_token)

    def is_valid_token(self, token: str) -> bool:
        """Check whether token is registered and active."""
        if not token:
            return False
        clean = token.removeprefix("Bearer ").strip()
        return clean in self.tokens

    def register_token(self, token: str) -> None:
        """Register a new device token."""
        self.tokens.add(token.strip())

    def revoke_token(self, token: str) -> None:
        """Revoke an existing device token."""
        self.tokens.discard(token.strip())
