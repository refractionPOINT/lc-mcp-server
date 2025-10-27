"""
Security Fixes Test Suite

Tests for the critical security fixes:
1. OAuth credentials race condition
2. Token encryption in Redis
3. Atomic operations for TOCTOU prevention
"""

import pytest
import os
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

# Set test environment
os.environ["PUBLIC_MODE"] = "true"
os.environ["MCP_OAUTH_ENABLED"] = "true"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"  # Use test DB
os.environ["REDIS_ENCRYPTION_KEY"] = "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlc2Vh"  # Base64 test key


class TestOAuthCredentialsIsolation:
    """Test that OAuth credentials are passed explicitly per-request."""

    def test_uid_auth_context_includes_oauth_creds(self):
        """Test that OAuth credentials are stored in context."""
        from server import uid_auth_context_var

        # Simulate OAuth mode
        uid = "test-uid"
        oauth_creds = {
            'id_token': 'test-id-token',
            'refresh_token': 'test-refresh-token',
            'provider': 'google'
        }

        # Set context
        token = uid_auth_context_var.set((uid, None, "oauth", oauth_creds))

        try:
            # Retrieve and verify
            context = uid_auth_context_var.get()
            assert context is not None
            assert len(context) == 4
            assert context[0] == uid
            assert context[2] == "oauth"
            assert context[3] == oauth_creds
        finally:
            uid_auth_context_var.reset(token)

    @patch('server.limacharlie.Manager')
    def test_sdk_created_with_explicit_oauth_creds(self, mock_manager):
        """Test that SDK is created with explicit OAuth credentials."""
        from server import wrap_tool_for_multi_mode, uid_auth_context_var

        mock_sdk = Mock()
        mock_manager.return_value = mock_sdk

        def test_tool(ctx):
            return {"result": "ok"}

        wrapped = wrap_tool_for_multi_mode(test_tool, is_async=False)

        oauth_creds = {
            'id_token': 'test-id-token',
            'refresh_token': 'test-refresh-token',
            'provider': 'google'
        }

        token = uid_auth_context_var.set(("test-uid", None, "oauth", oauth_creds))

        try:
            result = wrapped(oid="test-oid", ctx=Mock())

            # Verify SDK was created with oauth_creds
            mock_manager.assert_called_once()
            call_kwargs = mock_manager.call_args[1]
            assert 'oauth_creds' in call_kwargs
            assert call_kwargs['oauth_creds'] == oauth_creds
        finally:
            uid_auth_context_var.reset(token)


class TestTokenEncryption:
    """Test token encryption/decryption in Redis."""

    def test_encryption_module_initialization(self):
        """Test that encryption module initializes correctly."""
        from token_encryption import TokenEncryption

        encryptor = TokenEncryption()
        assert encryptor is not None

    def test_token_encryption_decryption(self):
        """Test basic encryption and decryption."""
        from token_encryption import TokenEncryption

        encryptor = TokenEncryption()

        plaintext = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QifQ.eyJzdWIiOiJ0ZXN0LXVpZCJ9.signature"
        encrypted = encryptor.encrypt(plaintext)

        # Verify encrypted is different
        assert encrypted != plaintext
        assert len(encrypted) > len(plaintext)

        # Decrypt and verify
        decrypted = encryptor.decrypt(encrypted)
        assert decrypted == plaintext

    def test_encryption_fails_with_wrong_key(self):
        """Test that decryption fails with wrong key."""
        from token_encryption import TokenEncryption
        import base64

        # Encrypt with one key
        encryptor1 = TokenEncryption()
        plaintext = "test-token"
        encrypted = encryptor1.encrypt(plaintext)

        # Try to decrypt with different key
        wrong_key = base64.b64encode(b"different_32_byte_key_here!!" + b"a" * 5).decode()
        encryptor2 = TokenEncryption(master_key=wrong_key)

        with pytest.raises(ValueError):
            encryptor2.decrypt(encrypted)


class TestAtomicOperations:
    """Test atomic Redis operations for TOCTOU prevention."""

    @pytest.fixture
    def state_manager(self):
        """Create a state manager for testing."""
        from oauth_state_manager import OAuthStateManager
        manager = OAuthStateManager()
        # Clean up test DB
        for key in manager.redis_client.keys("oauth:*"):
            manager.redis_client.delete(key)
        yield manager
        # Cleanup after test
        for key in manager.redis_client.keys("oauth:*"):
            manager.redis_client.delete(key)

    def test_atomic_get_and_delete(self, state_manager):
        """Test atomic get-and-delete script."""
        # Store a value
        key = "oauth:test:atomic"
        value = "test-value"
        state_manager.redis_client.set(key, value)

        # Atomically get and delete
        # SECURITY: The Lua script returns the value directly (not a list)
        # With decode_responses=True, result is a string (or None if not found)
        result = state_manager.atomic_get_and_delete(keys=[key])

        # Verify result
        assert result == value

        # Verify key is deleted
        assert state_manager.redis_client.get(key) is None

    def test_authorization_code_single_use(self, state_manager):
        """Test that authorization codes can only be consumed once."""
        code = "test-auth-code"

        # Store authorization code
        state_manager.store_authorization_code(
            code=code,
            state="test-state",
            uid="test-uid",
            firebase_id_token="test-id-token",
            firebase_refresh_token="test-refresh-token",
            firebase_expires_at=int(time.time()) + 3600
        )

        # First consumption should succeed
        auth_code1 = state_manager.consume_authorization_code(code)
        assert auth_code1 is not None
        assert auth_code1.code == code

        # Second consumption should fail (code already consumed)
        auth_code2 = state_manager.consume_authorization_code(code)
        assert auth_code2 is None

    def test_concurrent_authorization_code_consumption(self, state_manager):
        """Test that concurrent requests cannot reuse authorization code."""
        code = "concurrent-test-code"

        # Store authorization code
        state_manager.store_authorization_code(
            code=code,
            state="test-state",
            uid="test-uid",
            firebase_id_token="test-id-token",
            firebase_refresh_token="test-refresh-token",
            firebase_expires_at=int(time.time()) + 3600
        )

        results = []

        def try_consume():
            result = state_manager.consume_authorization_code(code)
            results.append(result)

        # Try to consume concurrently from 10 threads
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(try_consume) for _ in range(10)]
            for future in futures:
                future.result()

        # Only one should succeed
        successful = [r for r in results if r is not None]
        failed = [r for r in results if r is None]

        assert len(successful) == 1, f"Expected 1 success, got {len(successful)}"
        assert len(failed) == 9, f"Expected 9 failures, got {len(failed)}"

    def test_oauth_state_encryption_in_storage(self, state_manager):
        """Test that tokens are encrypted when stored in Redis."""
        code = "encrypted-code-test"
        firebase_id_token = "plaintext-id-token-12345"
        firebase_refresh_token = "plaintext-refresh-token-67890"

        # Store authorization code
        state_manager.store_authorization_code(
            code=code,
            state="test-state",
            uid="test-uid",
            firebase_id_token=firebase_id_token,
            firebase_refresh_token=firebase_refresh_token,
            firebase_expires_at=int(time.time()) + 3600
        )

        # Directly read from Redis (bypass decryption)
        key = f"{state_manager.CODE_PREFIX}{code}"
        raw_data = state_manager.redis_client.get(key)
        assert raw_data is not None

        # If encryption is enabled, tokens should NOT be plaintext in Redis
        if state_manager.encryption_enabled:
            # Raw data should not contain plaintext tokens
            assert firebase_id_token not in raw_data
            assert firebase_refresh_token not in raw_data
        else:
            # If encryption disabled, tokens will be plaintext (security warning should be logged)
            pass

        # Consuming should still work (decryption happens automatically)
        auth_code = state_manager.consume_authorization_code(code)
        assert auth_code is not None
        assert auth_code.firebase_id_token == firebase_id_token
        assert auth_code.firebase_refresh_token == firebase_refresh_token


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
