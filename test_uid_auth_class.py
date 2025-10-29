"""
Tests for the UIDAuth class to verify UID validation and class functionality.
"""

import pytest
from uid_auth import UIDAuth


class TestUIDAuthValidation:
    """Tests for UID validation to prevent secrets from being logged."""

    def test_valid_uid_formats(self):
        """Test that valid UID formats are accepted."""
        valid_uids = [
            "user123",
            "john.doe@example.com",
            "user-id-123",
            "test_user_456",
            "abc123def456",
            "a1b2c3d4e5f6",  # Short alphanumeric
        ]

        for uid in valid_uids:
            # Should not raise
            auth = UIDAuth(uid=uid, api_key="test-key", mode="api_key", oauth_creds=None)
            assert auth.uid == uid

    def test_rejects_jwt_tokens(self):
        """Test that JWT tokens are rejected as UIDs."""
        # JWT token format: header.payload.signature
        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        with pytest.raises(ValueError, match="UID validation failed"):
            UIDAuth(uid=jwt_token, api_key=None, mode="oauth", oauth_creds={})

    def test_rejects_long_hex_strings(self):
        """Test that long hex strings (likely API keys) are rejected."""
        long_hex = "a" * 150  # Long hex string

        with pytest.raises(ValueError, match="UID validation failed"):
            UIDAuth(uid=long_hex, api_key=None, mode="oauth", oauth_creds={})

    def test_rejects_long_base64_strings(self):
        """Test that long base64 strings are rejected."""
        long_base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" * 3

        with pytest.raises(ValueError, match="UID validation failed"):
            UIDAuth(uid=long_base64, api_key=None, mode="oauth", oauth_creds={})

    def test_rejects_too_long_uids(self):
        """Test that UIDs over 255 characters are rejected."""
        too_long_uid = "a" * 300

        with pytest.raises(ValueError, match="UID validation failed"):
            UIDAuth(uid=too_long_uid, api_key="test-key", mode="api_key", oauth_creds=None)

    def test_invalid_mode_rejected(self):
        """Test that invalid modes are rejected."""
        with pytest.raises(ValueError, match="Invalid auth mode"):
            UIDAuth(uid="test-uid", api_key=None, mode="invalid", oauth_creds=None)

    def test_mode_properties(self):
        """Test mode property helpers."""
        oauth_auth = UIDAuth(uid="test", api_key=None, mode="oauth", oauth_creds={})
        assert oauth_auth.is_oauth_mode
        assert not oauth_auth.is_api_key_mode

        api_key_auth = UIDAuth(uid="test", api_key="key", mode="api_key", oauth_creds=None)
        assert api_key_auth.is_api_key_mode
        assert not api_key_auth.is_oauth_mode

    def test_string_representation_masks_api_key(self):
        """Test that string representation masks the API key."""
        auth = UIDAuth(uid="test-uid", api_key="secret-key-123", mode="api_key", oauth_creds=None)

        str_repr = str(auth)
        repr_repr = repr(auth)

        # Should not contain the actual API key
        assert "secret-key-123" not in str_repr
        assert "secret-key-123" not in repr_repr

        # Should contain masked indicator
        assert "***" in str_repr
        assert "***" in repr_repr

    def test_immutability(self):
        """Test that UIDAuth is immutable (frozen dataclass)."""
        auth = UIDAuth(uid="test", api_key="key", mode="api_key", oauth_creds=None)

        with pytest.raises(Exception):  # FrozenInstanceError in Python 3.10+
            auth.uid = "modified"

    def test_oauth_mode_with_credentials(self):
        """Test OAuth mode with credentials."""
        oauth_creds = {
            'api_key': 'test-api-key',
            'id_token': 'test-id-token',
            'refresh_token': 'test-refresh-token',
            'provider': 'google'
        }

        auth = UIDAuth(uid="user@example.com", api_key=None, mode="oauth", oauth_creds=oauth_creds)

        assert auth.uid == "user@example.com"
        assert auth.api_key is None
        assert auth.mode == "oauth"
        assert auth.oauth_creds == oauth_creds
        assert auth.is_oauth_mode

    def test_api_key_mode_without_oauth(self):
        """Test API key mode without OAuth credentials."""
        auth = UIDAuth(uid="test-user", api_key="my-api-key", mode="api_key", oauth_creds=None)

        assert auth.uid == "test-user"
        assert auth.api_key == "my-api-key"
        assert auth.mode == "api_key"
        assert auth.oauth_creds is None
        assert auth.is_api_key_mode


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
