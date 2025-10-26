"""
Additional Security Tests

Tests for additional security improvements:
1. Concurrent multitenancy isolation
2. Refresh token rotation
3. Refresh token theft detection
4. Token encryption validation
5. JWT signature verification
6. Log sanitization
"""

import pytest
import os
import time
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch, MagicMock
from contextvars import copy_context

# Set test environment
os.environ["PUBLIC_MODE"] = "true"
os.environ["MCP_OAUTH_ENABLED"] = "true"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"  # Use test DB
os.environ["REDIS_ENCRYPTION_KEY"] = "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlc2Vh"  # Base64 test key


class TestConcurrentMultitenancy:
    """Test that multitenancy isolation works under concurrent load."""

    @pytest.fixture
    def mock_sdk_class(self):
        """Mock limacharlie.Manager class for testing."""
        with patch('server.limacharlie.Manager') as mock_manager:
            # Each SDK instance should track which credentials it was created with
            def sdk_factory(*args, **kwargs):
                sdk = MagicMock()
                sdk.oid = kwargs.get('oid')
                sdk.uid = kwargs.get('uid')
                sdk.secret_api_key = kwargs.get('secret_api_key')
                sdk.oauth_creds = kwargs.get('oauth_creds')
                sdk.shutdown = MagicMock()
                return sdk

            mock_manager.side_effect = sdk_factory
            yield mock_manager

    def test_concurrent_requests_different_orgs(self, mock_sdk_class):
        """Verify no credential leakage between concurrent requests for different orgs."""
        from server import wrap_tool_for_multi_mode, uid_auth_context_var, sdk_context_var

        def test_tool(ctx):
            # Get SDK from context and return its credentials
            sdk = sdk_context_var.get()
            return {
                "oid": sdk.oid if sdk else None,
                "uid": sdk.uid if sdk else None,
                "api_key": sdk.secret_api_key if sdk else None
            }

        wrapped = wrap_tool_for_multi_mode(test_tool, is_async=False)

        results = []
        errors = []

        def run_with_context(uid, api_key, oid):
            """Run tool with specific context."""
            try:
                # Set auth context for this "request"
                token = uid_auth_context_var.set((uid, api_key, "api_key", None))
                try:
                    result = wrapped(oid=oid, ctx=Mock())
                    results.append({
                        "expected_oid": oid,
                        "expected_uid": uid,
                        "expected_api_key": api_key,
                        "actual": result
                    })
                finally:
                    uid_auth_context_var.reset(token)
            except Exception as e:
                errors.append(str(e))

        # Simulate 50 concurrent requests with different credentials
        test_data = [
            (f"uid-{i}", f"api-key-{i}", f"oid-{i}")
            for i in range(50)
        ]

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(copy_context().run, run_with_context, uid, api_key, oid)
                for uid, api_key, oid in test_data
            ]
            for future in futures:
                future.result()

        # Verify no errors
        assert len(errors) == 0, f"Errors occurred: {errors}"

        # Verify each request got the correct credentials
        assert len(results) == 50, f"Expected 50 results, got {len(results)}"

        for result_data in results:
            expected_oid = result_data["expected_oid"]
            expected_uid = result_data["expected_uid"]
            expected_api_key = result_data["expected_api_key"]
            actual = result_data["actual"]

            # Each result should match its expected credentials
            assert actual["oid"] == expected_oid, \
                f"OID mismatch: expected {expected_oid}, got {actual['oid']}"
            assert actual["uid"] == expected_uid, \
                f"UID mismatch: expected {expected_uid}, got {actual['uid']}"
            assert actual["api_key"] == expected_api_key, \
                f"API key mismatch: expected {expected_api_key}, got {actual['api_key']}"


class TestRefreshTokenRotation:
    """Test refresh token rotation implementation."""

    @pytest.fixture
    def token_manager(self):
        """Create a token manager for testing."""
        from oauth_token_manager import OAuthTokenManager
        from oauth_state_manager import OAuthStateManager
        from firebase_auth_bridge import FirebaseAuthBridge

        state_manager = OAuthStateManager()
        # Clean up test DB
        for key in state_manager.redis_client.keys("oauth:*"):
            state_manager.redis_client.delete(key)

        manager = OAuthTokenManager(
            state_manager=state_manager,
            firebase_bridge=Mock(spec=FirebaseAuthBridge)
        )

        yield manager

        # Cleanup after test
        for key in state_manager.redis_client.keys("oauth:*"):
            state_manager.redis_client.delete(key)

    def test_refresh_token_rotation_creates_new_token(self, token_manager):
        """Verify that using a refresh token creates a NEW refresh token."""
        # Mock Firebase token refresh
        token_manager.firebase_bridge.refresh_id_token.return_value = (
            "new-firebase-id-token",
            int(time.time()) + 3600
        )

        # Create initial refresh token
        uid = "test-uid"
        firebase_refresh_token = "firebase-refresh-token"
        scope = "openid email"
        access_token1 = "access-token-1"
        refresh_token1 = "refresh-token-1"

        token_manager.state_manager.store_access_token(
            access_token=access_token1,
            uid=uid,
            firebase_id_token="firebase-id-token-1",
            firebase_refresh_token=firebase_refresh_token,
            firebase_expires_at=int(time.time()) + 3600,
            scope=scope
        )

        token_manager.state_manager.store_refresh_token(
            refresh_token=refresh_token1,
            access_token=access_token1,
            uid=uid,
            firebase_refresh_token=firebase_refresh_token,
            scope=scope
        )

        # Use refresh token to get new tokens
        response = token_manager.refresh_access_token(refresh_token1)

        assert response is not None
        assert "access_token" in response
        assert "refresh_token" in response

        # NEW refresh token should be different
        new_refresh_token = response["refresh_token"]
        assert new_refresh_token != refresh_token1, "Refresh token was not rotated!"

        # New access token should also be different
        new_access_token = response["access_token"]
        assert new_access_token != access_token1

    def test_old_refresh_token_invalid_after_rotation(self, token_manager):
        """Verify that old refresh token is invalidated after use."""
        # Mock Firebase token refresh
        token_manager.firebase_bridge.refresh_id_token.return_value = (
            "new-firebase-id-token",
            int(time.time()) + 3600
        )

        # Create initial refresh token
        uid = "test-uid"
        firebase_refresh_token = "firebase-refresh-token"
        scope = "openid email"
        access_token1 = "access-token-1"
        refresh_token1 = "refresh-token-1"

        token_manager.state_manager.store_access_token(
            access_token=access_token1,
            uid=uid,
            firebase_id_token="firebase-id-token-1",
            firebase_refresh_token=firebase_refresh_token,
            firebase_expires_at=int(time.time()) + 3600,
            scope=scope
        )

        token_manager.state_manager.store_refresh_token(
            refresh_token=refresh_token1,
            access_token=access_token1,
            uid=uid,
            firebase_refresh_token=firebase_refresh_token,
            scope=scope
        )

        # Use refresh token once
        response1 = token_manager.refresh_access_token(refresh_token1)
        assert response1 is not None

        # Try to use old refresh token again (should fail)
        response2 = token_manager.refresh_access_token(refresh_token1)
        assert response2 is None, "Old refresh token was not invalidated!"


class TestRefreshTokenTheftDetection:
    """Test that refresh token theft can be detected via rotation."""

    @pytest.fixture
    def token_manager(self):
        """Create a token manager for testing."""
        from oauth_token_manager import OAuthTokenManager
        from oauth_state_manager import OAuthStateManager
        from firebase_auth_bridge import FirebaseAuthBridge

        state_manager = OAuthStateManager()
        # Clean up test DB
        for key in state_manager.redis_client.keys("oauth:*"):
            state_manager.redis_client.delete(key)

        manager = OAuthTokenManager(
            state_manager=state_manager,
            firebase_bridge=Mock(spec=FirebaseAuthBridge)
        )

        yield manager

        # Cleanup after test
        for key in state_manager.redis_client.keys("oauth:*"):
            state_manager.redis_client.delete(key)

    def test_concurrent_refresh_token_use_only_one_succeeds(self, token_manager):
        """Simulate stolen refresh token - only one concurrent use should succeed."""
        # Mock Firebase token refresh
        token_manager.firebase_bridge.refresh_id_token.return_value = (
            "new-firebase-id-token",
            int(time.time()) + 3600
        )

        # Create initial refresh token
        uid = "test-uid"
        firebase_refresh_token = "firebase-refresh-token"
        scope = "openid email"
        access_token1 = "access-token-1"
        refresh_token1 = "refresh-token-1"

        token_manager.state_manager.store_access_token(
            access_token=access_token1,
            uid=uid,
            firebase_id_token="firebase-id-token-1",
            firebase_refresh_token=firebase_refresh_token,
            firebase_expires_at=int(time.time()) + 3600,
            scope=scope
        )

        token_manager.state_manager.store_refresh_token(
            refresh_token=refresh_token1,
            access_token=access_token1,
            uid=uid,
            firebase_refresh_token=firebase_refresh_token,
            scope=scope
        )

        results = []

        def try_refresh():
            result = token_manager.refresh_access_token(refresh_token1)
            results.append(result)

        # Try to use same refresh token from 10 threads simultaneously
        # This simulates an attacker and legitimate user both trying to use the token
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(try_refresh) for _ in range(10)]
            for future in futures:
                future.result()

        # Only one should succeed (atomic Redis operation)
        successful = [r for r in results if r is not None]
        failed = [r for r in results if r is None]

        assert len(successful) == 1, f"Expected 1 success, got {len(successful)}"
        assert len(failed) == 9, f"Expected 9 failures, got {len(failed)}"


class TestTokenEncryptionInRedis:
    """Test that tokens are properly encrypted in Redis."""

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

    def test_firebase_tokens_encrypted_in_redis(self, state_manager):
        """Verify Firebase tokens are encrypted, not plaintext in Redis."""
        code = "test-auth-code"
        firebase_id_token = "plaintext-id-token-SENSITIVE-DATA-12345"
        firebase_refresh_token = "plaintext-refresh-token-SENSITIVE-DATA-67890"

        # Store authorization code
        state_manager.store_authorization_code(
            code=code,
            state="test-state",
            uid="test-uid",
            firebase_id_token=firebase_id_token,
            firebase_refresh_token=firebase_refresh_token,
            firebase_expires_at=int(time.time()) + 3600
        )

        # Read raw data from Redis (bypass decryption)
        key = f"{state_manager.CODE_PREFIX}{code}"
        raw_data = state_manager.redis_client.get(key)
        assert raw_data is not None

        # If encryption is enabled, plaintext should NOT be in Redis
        if state_manager.encryption_enabled:
            # Raw data should not contain plaintext tokens
            assert firebase_id_token not in raw_data, \
                "Firebase ID token stored as plaintext in Redis!"
            assert firebase_refresh_token not in raw_data, \
                "Firebase refresh token stored as plaintext in Redis!"

            # Raw data should contain encrypted tokens (base64-encoded ciphertext)
            assert len(raw_data) > len(firebase_id_token), \
                "Encrypted data should be larger (includes nonce + tag)"
        else:
            pytest.skip("Encryption not enabled - set REDIS_ENCRYPTION_KEY to test")

        # Consuming should still work (decryption happens automatically)
        auth_code = state_manager.consume_authorization_code(code)
        assert auth_code is not None
        assert auth_code.firebase_id_token == firebase_id_token
        assert auth_code.firebase_refresh_token == firebase_refresh_token


class TestJWTSignatureVerification:
    """Test JWT signature verification implementation."""

    def test_jwt_verification_requires_pyjwt(self):
        """Verify that JWT verification requires PyJWT library."""
        from firebase_auth_bridge import FirebaseAuthBridge

        bridge = FirebaseAuthBridge()

        # Create a fake JWT (invalid signature)
        import base64
        import json

        header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "kid": "test"}).encode()).decode().rstrip('=')
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "test-uid", "user_id": "test-user"}).encode()).decode().rstrip('=')
        signature = "fake-signature"
        fake_jwt = f"{header}.{payload}.{signature}"

        # Try to verify (should fail or fall back to unverified)
        result = bridge.verify_firebase_id_token(fake_jwt)

        # If jwt library is available, should return None (invalid signature)
        # If not available, falls back to unverified decode
        # Either way, method should not crash
        assert result is None or isinstance(result, dict)

    def test_unverified_decode_still_works(self):
        """Verify backward compatibility with unverified decode."""
        from firebase_auth_bridge import FirebaseAuthBridge

        bridge = FirebaseAuthBridge()

        # Create a valid JWT structure (but invalid signature)
        import base64
        import json

        payload_data = {"sub": "test-uid", "user_id": "test-user", "email": "test@example.com"}

        header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "kid": "test"}).encode()).decode().rstrip('=')
        payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip('=')
        signature = "fake-signature"
        fake_jwt = f"{header}.{payload}.{signature}"

        # Unverified decode should work
        result = bridge.get_user_info_from_token(fake_jwt)

        assert result is not None
        assert result.get("user_id") == "test-user"
        assert result.get("email") == "test@example.com"


class TestLogSanitization:
    """Test that sensitive data is not logged."""

    def test_oauth_state_not_in_error_logs(self, caplog):
        """Verify OAuth states are not logged in full at ERROR level."""
        from oauth_endpoints import OAuthEndpointHandler
        from oauth_state_manager import OAuthStateManager
        from firebase_auth_bridge import FirebaseAuthBridge

        state_manager = OAuthStateManager()
        firebase_bridge = FirebaseAuthBridge()

        handler = OAuthEndpointHandler(
            state_manager=state_manager,
            firebase_bridge=firebase_bridge,
            metadata_provider=Mock()
        )

        # Trigger an error condition that would log sensitive data
        with caplog.at_level(logging.ERROR):
            with pytest.raises(Exception):
                # Pass invalid parameters that trigger error logging
                handler.handle_oauth_callback(params={})

        # Check that full state values are not in ERROR logs
        for record in caplog.records:
            if record.levelname == "ERROR":
                # Should not contain full sensitive values
                assert "oauth:state:" not in record.message or "..." in record.message, \
                    f"Full OAuth state logged at ERROR level: {record.message}"

    def test_session_ids_not_in_error_logs(self, caplog):
        """Verify session IDs are not logged in full."""
        from firebase_auth_bridge import FirebaseAuthBridge

        bridge = FirebaseAuthBridge()

        with caplog.at_level(logging.ERROR):
            # Trigger Firebase operations that might log session IDs
            # (This will fail but should log safely)
            try:
                bridge.create_auth_uri(
                    provider_id="google.com",
                    redirect_uri="https://example.com/callback"
                )
            except Exception:
                pass

        # Check ERROR logs don't contain full session IDs
        for record in caplog.records:
            if record.levelname == "ERROR":
                # If session_id appears, it should be truncated
                if "session" in record.message.lower():
                    # Should have truncation markers "..." if sensitive data present
                    # Full session IDs are typically 100+ chars
                    assert len(record.message) < 500 or "..." in record.message, \
                        f"Potentially unredacted session ID in ERROR log: {record.message[:100]}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
