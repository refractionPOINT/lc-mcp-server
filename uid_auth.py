"""
UID Authentication data structure for LimaCharlie MCP Server.

This module provides a typed data class for storing UID authentication
information, replacing the previous tuple-based approach for better
type safety and clarity.
"""

from dataclasses import dataclass
from typing import Optional
import re


@dataclass(frozen=True)
class UIDAuth:
    """
    Stores authentication information for UID mode (multi-organization).

    Attributes:
        uid: User identifier (validated to ensure it's not a secret)
        api_key: API key for authentication (None in OAuth mode)
        mode: Authentication mode - either "oauth" or "api_key"
        oauth_creds: OAuth credentials dictionary (None in API key mode)
    """
    uid: str
    api_key: Optional[str]
    mode: str  # "oauth" or "api_key"
    oauth_creds: Optional[dict]

    def __post_init__(self):
        """Validate the UID to ensure it's not accidentally a secret."""
        # Validate mode
        if self.mode not in ("oauth", "api_key"):
            raise ValueError(f"Invalid auth mode: {self.mode}. Must be 'oauth' or 'api_key'")

        # Validate UID format - it should look like a Firebase UID or similar identifier
        # UIDs are typically alphanumeric with possible dashes/underscores, not long secret strings
        if not self._is_valid_uid(self.uid):
            raise ValueError(
                "UID validation failed: UID appears to be malformed or may be a secret. "
                "Expected a short alphanumeric identifier."
            )

    @staticmethod
    def _is_valid_uid(uid: str) -> bool:
        """
        Validate that a UID looks like a legitimate user identifier and not a secret.

        UIDs should be:
        - Reasonably short (< 256 characters)
        - Alphanumeric with common separators (-, _, @, .)
        - Not look like a JWT (no dots with long segments)
        - Not look like an API key (UUID format is OK, but not long hex strings)

        Args:
            uid: The UID string to validate

        Returns:
            True if the UID appears valid, False otherwise
        """
        if not uid or len(uid) > 255:
            return False

        # Check for patterns that indicate secrets
        # JWT tokens have format xxx.yyy.zzz with base64-like segments
        if uid.count('.') >= 2:
            parts = uid.split('.')
            # If all parts are long base64-like strings, likely a JWT
            if all(len(part) > 20 and re.match(r'^[A-Za-z0-9_-]+$', part) for part in parts):
                return False

        # Very long hex strings or base64 strings are likely secrets
        if len(uid) > 100:
            # Check if it's a long hex string
            if re.match(r'^[0-9a-fA-F]+$', uid):
                return False
            # Check if it's a long base64 string without typical UID separators
            if re.match(r'^[A-Za-z0-9+/]+=*$', uid) and '-' not in uid and '_' not in uid:
                return False

        # Should contain only safe characters (alphanumeric + common separators)
        # Allow: letters, numbers, -, _, @, .
        if not re.match(r'^[A-Za-z0-9._@-]+$', uid):
            return False

        return True

    @property
    def is_oauth_mode(self) -> bool:
        """Check if this is OAuth authentication mode."""
        return self.mode == "oauth"

    @property
    def is_api_key_mode(self) -> bool:
        """Check if this is API key authentication mode."""
        return self.mode == "api_key"

    def __str__(self) -> str:
        """String representation with sensitive data masked."""
        return f"UIDAuth(uid={self.uid}, mode={self.mode}, api_key={'***' if self.api_key else None})"

    def __repr__(self) -> str:
        """Developer representation with sensitive data masked."""
        return self.__str__()
