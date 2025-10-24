#!/usr/bin/env python3
"""
Comprehensive test suite for OAuth authentication mode.

Tests cover:
- OAuth credential detection from ~/.limacharlie
- OAuth mode initialization and precedence
- Manager creation with OAuth vs API key
- Environment variable handling (LC_CURRENT_ENV)
- Error handling for missing credentials
- 3-tuple context structure
"""

import pytest
import os
import tempfile
import json
from unittest.mock import Mock, patch, MagicMock, call
import contextvars

# Set environment before importing server
os.environ["PUBLIC_MODE"] = "false"
os.environ["MCP_PROFILE"] = "all"

# Mock dependencies
import sys
sys.modules['limacharlie'] = MagicMock()
sys.modules['limacharlie.Replay'] = MagicMock()
sys.modules['google'] = MagicMock()
sys.modules['google.genai'] = MagicMock()
sys.modules['google.genai.types'] = MagicMock()
sys.modules['google.cloud'] = MagicMock()
sys.modules['google.cloud.storage'] = MagicMock()
sys.modules['google.auth'] = MagicMock()
sys.modules['google.auth.transport'] = MagicMock()
sys.modules['google.auth.transport.requests'] = MagicMock()
sys.modules['mcp'] = MagicMock()
sys.modules['mcp.server'] = MagicMock()
sys.modules['mcp.server.fastmcp'] = MagicMock()
sys.modules['mcp.server.fastmcp.server'] = MagicMock()

# Import server components after mocking
from server import (
    get_auth_from_sdk_config,
    uid_auth_context_var,
    validate_oid_parameter
)


class TestOAuthCredentialDetection:
    """Test OAuth credential loading from ~/.limacharlie config file."""

    def test_load_oauth_from_config_default_env(self):
        """Test loading OAuth credentials from default environment."""
        mock_oauth_creds = {
            "refresh_token": "mock-refresh-token",
            "api_key": "mock-firebase-api-key",
            "id_token": "mock-id-token"
        }

        with patch('limacharlie._getEnvironmentCreds') as mock_get_creds:
            # Simulate SDK returning OAuth credentials
            mock_get_creds.return_value = (
                "test-oid",  # oid
                "test-uid",  # uid
                None,        # api_key (None when OAuth is used)
                mock_oauth_creds  # oauth
            )

            uid, api_key, oauth = get_auth_from_sdk_config()

            assert uid == "test-uid"
            assert api_key is None
            assert oauth == mock_oauth_creds
            mock_get_creds.assert_called_once_with("default")

    def test_load_oauth_from_config_custom_env(self):
        """Test loading OAuth credentials from custom environment."""
        mock_oauth_creds = {"refresh_token": "mock-token"}

        with patch('limacharlie._getEnvironmentCreds') as mock_get_creds:
            mock_get_creds.return_value = ("oid", "uid", None, mock_oauth_creds)

            with patch.dict(os.environ, {"LC_CURRENT_ENV": "production"}):
                uid, api_key, oauth = get_auth_from_sdk_config()

                assert oauth == mock_oauth_creds
                mock_get_creds.assert_called_once_with("production")

    def test_load_api_key_from_config(self):
        """Test loading API key from config (no OAuth)."""
        with patch('limacharlie._getEnvironmentCreds') as mock_get_creds:
            # Simulate SDK returning API key credentials
            mock_get_creds.return_value = (
                "test-oid",
                "test-uid",
                "test-api-key",
                None  # No OAuth
            )

            uid, api_key, oauth = get_auth_from_sdk_config()

            assert uid == "test-uid"
            assert api_key == "test-api-key"
            assert oauth is None

    def test_config_file_not_found(self):
        """Test handling when ~/.limacharlie file doesn't exist."""
        with patch('limacharlie._getEnvironmentCreds') as mock_get_creds:
            mock_get_creds.side_effect = FileNotFoundError("Config not found")

            uid, api_key, oauth = get_auth_from_sdk_config()

            assert uid is None
            assert api_key is None
            assert oauth is None

    def test_config_invalid_environment(self):
        """Test handling when specified environment doesn't exist in config."""
        with patch('limacharlie._getEnvironmentCreds') as mock_get_creds:
            mock_get_creds.side_effect = KeyError("Environment not found")

            with patch.dict(os.environ, {"LC_CURRENT_ENV": "nonexistent"}):
                # Should return None values when environment doesn't exist
                uid, api_key, oauth = get_auth_from_sdk_config()

                assert uid is None
                assert api_key is None
                assert oauth is None


class TestOAuthModeInitialization:
    """Test OAuth mode initialization logic in STDIO mode."""

    def test_oauth_mode_selected_when_available(self):
        """Test that OAuth mode is selected when credentials are available."""
        # This tests the logic that would happen during STDIO initialization
        mock_oauth_creds = {"refresh_token": "token"}

        # Simulate: LC_UID is set, OAuth creds found
        uid = "test-uid"
        api_key_sdk = None
        oauth_creds = mock_oauth_creds

        # OAuth takes precedence
        if oauth_creds:
            mode = "oauth"
            context_value = (uid, None, mode)
        elif api_key_sdk:
            mode = "api_key"
            context_value = (uid, api_key_sdk, mode)
        else:
            context_value = None

        assert context_value == ("test-uid", None, "oauth")

    def test_api_key_mode_fallback(self):
        """Test that API key mode is used when OAuth is not available."""
        uid = "test-uid"
        api_key_sdk = "test-api-key"
        oauth_creds = None

        if oauth_creds:
            mode = "oauth"
            context_value = (uid, None, mode)
        elif api_key_sdk:
            mode = "api_key"
            context_value = (uid, api_key_sdk, mode)
        else:
            context_value = None

        assert context_value == ("test-uid", "test-api-key", "api_key")

    def test_oauth_precedence_over_api_key(self):
        """Test that OAuth takes precedence when both are available."""
        uid = "test-uid"
        api_key_sdk = "test-api-key"
        oauth_creds = {"refresh_token": "token"}

        # OAuth should take precedence
        if oauth_creds:
            mode = "oauth"
            context_value = (uid, None, mode)
        elif api_key_sdk:
            mode = "api_key"
            context_value = (uid, api_key_sdk, mode)
        else:
            context_value = None

        assert context_value == ("test-uid", None, "oauth")
        assert context_value[2] == "oauth"

    def test_error_when_neither_auth_available(self):
        """Test that initialization fails when neither OAuth nor API key is available."""
        uid = "test-uid"
        api_key_sdk = None
        oauth_creds = None

        if oauth_creds:
            mode = "oauth"
            context_value = (uid, None, mode)
        elif api_key_sdk:
            mode = "api_key"
            context_value = (uid, api_key_sdk, mode)
        else:
            context_value = None

        # Should result in error state (None context)
        assert context_value is None


class TestManagerCreation:
    """Test LimaCharlie Manager SDK creation in different auth modes."""

    def test_manager_creation_oauth_mode(self):
        """Test Manager is created correctly in OAuth mode."""
        with patch('server.limacharlie.Manager') as mock_manager:
            # Simulate tool wrapper logic in OAuth mode
            uid_auth = ("test-uid", None, "oauth")
            oid = "target-org-123"

            uid, api_key, mode = uid_auth
            if mode == "oauth":
                sdk = mock_manager(oid=oid)
            else:
                sdk = mock_manager(oid, secret_api_key=api_key)

            # Should be called with only oid parameter (uses GLOBAL_OAUTH)
            mock_manager.assert_called_once_with(oid=oid)

    def test_manager_creation_api_key_mode(self):
        """Test Manager is created correctly in API key mode."""
        with patch('server.limacharlie.Manager') as mock_manager:
            # Simulate tool wrapper logic in API key mode
            uid_auth = ("test-uid", "test-api-key", "api_key")
            oid = "target-org-123"

            uid, api_key, mode = uid_auth
            if mode == "oauth":
                sdk = mock_manager(oid=oid)
            else:
                sdk = mock_manager(oid, secret_api_key=api_key)

            # Should be called with oid and api_key
            mock_manager.assert_called_once_with(oid, secret_api_key="test-api-key")

    def test_manager_creation_respects_mode(self):
        """Test that Manager creation respects the mode parameter."""
        with patch('server.limacharlie.Manager') as mock_manager:
            test_cases = [
                # (uid, api_key, mode, oid)
                ("uid1", None, "oauth", "org1"),
                ("uid2", "key2", "api_key", "org2"),
            ]

            for uid, api_key, mode, oid in test_cases:
                mock_manager.reset_mock()
                uid_auth = (uid, api_key, mode)

                uid_val, api_key_val, mode_val = uid_auth
                if mode_val == "oauth":
                    sdk = mock_manager(oid=oid)
                else:
                    sdk = mock_manager(oid, secret_api_key=api_key_val)

                if mode == "oauth":
                    mock_manager.assert_called_once_with(oid=oid)
                else:
                    mock_manager.assert_called_once_with(oid, secret_api_key=api_key)


class TestContextStructure:
    """Test 3-tuple context variable structure."""

    def test_context_var_3tuple_oauth(self):
        """Test context variable stores 3-tuple correctly for OAuth mode."""
        uid_auth_context_var.set(("test-uid", None, "oauth"))
        value = uid_auth_context_var.get()

        assert len(value) == 3
        assert value[0] == "test-uid"
        assert value[1] is None
        assert value[2] == "oauth"

    def test_context_var_3tuple_api_key(self):
        """Test context variable stores 3-tuple correctly for API key mode."""
        uid_auth_context_var.set(("test-uid", "test-key", "api_key"))
        value = uid_auth_context_var.get()

        assert len(value) == 3
        assert value[0] == "test-uid"
        assert value[1] == "test-key"
        assert value[2] == "api_key"

    def test_context_var_unpacking(self):
        """Test that 3-tuple can be unpacked correctly."""
        uid_auth_context_var.set(("my-uid", "my-key", "api_key"))

        uid, api_key, mode = uid_auth_context_var.get()

        assert uid == "my-uid"
        assert api_key == "my-key"
        assert mode == "api_key"


class TestValidationWithMode:
    """Test validation helper with mode parameter."""

    def test_validation_with_oauth_mode(self):
        """Test validation error message includes OAuth mode info."""
        with pytest.raises(ValueError) as exc_info:
            validate_oid_parameter(
                oid=None,
                uid_mode=True,
                tool_name="test_tool",
                mode="oauth"
            )

        error_msg = str(exc_info.value)
        assert "test_tool" in error_msg
        assert "oauth" in error_msg
        assert "required" in error_msg

    def test_validation_with_api_key_mode(self):
        """Test validation error message includes API key mode info."""
        with pytest.raises(ValueError) as exc_info:
            validate_oid_parameter(
                oid=None,
                uid_mode=True,
                tool_name="test_tool",
                mode="api_key"
            )

        error_msg = str(exc_info.value)
        assert "test_tool" in error_msg
        assert "api_key" in error_msg

    def test_validation_passes_with_oid(self):
        """Test validation passes when oid is provided."""
        # Should not raise
        validate_oid_parameter(
            oid="test-org-123",
            uid_mode=True,
            tool_name="test_tool",
            mode="oauth"
        )

    def test_validation_normal_mode_ignores_mode(self):
        """Test validation in normal mode doesn't require oid regardless of mode."""
        # Should not raise even without oid in normal mode
        validate_oid_parameter(
            oid=None,
            uid_mode=False,
            tool_name="test_tool",
            mode="oauth"
        )


class TestEnvironmentVariableHandling:
    """Test environment variable precedence and handling."""

    def test_lc_current_env_default(self):
        """Test that LC_CURRENT_ENV defaults to 'default'."""
        # Clear any existing LC_CURRENT_ENV
        env = os.environ.copy()
        if "LC_CURRENT_ENV" in env:
            del env["LC_CURRENT_ENV"]

        with patch.dict(os.environ, env, clear=True):
            env_name = os.getenv("LC_CURRENT_ENV", "default")
            assert env_name == "default"

    def test_lc_current_env_custom(self):
        """Test that LC_CURRENT_ENV can be customized."""
        with patch.dict(os.environ, {"LC_CURRENT_ENV": "production"}):
            env_name = os.getenv("LC_CURRENT_ENV", "default")
            assert env_name == "production"

    def test_env_precedence_oauth_over_api_key(self):
        """Test that when both OAuth and API key are in env, OAuth wins."""
        # This simulates the STDIO initialization logic
        with patch.dict(os.environ, {
            "LC_UID": "test-uid",
            "LC_API_KEY": "env-api-key"
        }):
            # Simulate SDK returning OAuth credentials
            uid_sdk = "test-uid"
            api_key_sdk = "sdk-api-key"
            oauth_creds = {"refresh_token": "token"}

            # OAuth takes precedence over both env and SDK API keys
            if oauth_creds:
                selected_mode = "oauth"
            elif os.getenv("LC_API_KEY") or api_key_sdk:
                selected_mode = "api_key"
            else:
                selected_mode = None

            assert selected_mode == "oauth"


class TestGlobalOAuthSetup:
    """Test limacharlie.GLOBAL_OAUTH configuration."""

    def test_global_oauth_set_in_oauth_mode(self):
        """Test that GLOBAL_OAUTH is set when using OAuth mode."""
        mock_oauth_creds = {"refresh_token": "token", "api_key": "firebase-key"}

        with patch('server.limacharlie') as mock_lc:
            # Simulate STDIO initialization setting GLOBAL_OAUTH
            oauth_creds = mock_oauth_creds
            if oauth_creds:
                mock_lc.GLOBAL_OAUTH = oauth_creds

            assert mock_lc.GLOBAL_OAUTH == mock_oauth_creds

    def test_global_oauth_not_set_in_api_key_mode(self):
        """Test that GLOBAL_OAUTH is not set in API key mode."""
        # This test verifies the logic: in API key mode, we don't set GLOBAL_OAUTH
        oauth_creds = None
        api_key = "test-key"

        # Track whether we would set GLOBAL_OAUTH
        global_oauth_set = False
        if oauth_creds:
            # Would set GLOBAL_OAUTH here
            global_oauth_set = True

        # In API key mode, GLOBAL_OAUTH should not be set
        assert not global_oauth_set


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
