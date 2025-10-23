#!/usr/bin/env python3
"""
Comprehensive test suite for UID mode (multi-organization) functionality.

Tests cover:
- Tool wrapper signature modification
- Mode detection and validation
- SDK creation in both modes
- HTTP and STDIO mode support
- Context isolation
- Backward compatibility
"""

import pytest
import os
import inspect
from unittest.mock import Mock, patch, MagicMock, call
import asyncio
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
    wrap_tool_for_multi_mode,
    uid_auth_context_var,
    sdk_context_var,
    get_uid_from_environment,
    validate_oid_parameter
)


class TestToolWrapperSignature:
    """Test that the wrapper correctly modifies tool signatures"""

    def test_wrapper_adds_oid_parameter_sync(self):
        """Test that oid parameter is added to sync function signature"""
        # Create a simple sync tool
        def sample_tool(param1: str, param2: int, ctx) -> dict:
            return {"result": "ok"}

        # Wrap it
        wrapped = wrap_tool_for_multi_mode(sample_tool, is_async=False)

        # Check signature
        sig = inspect.signature(wrapped)
        params = list(sig.parameters.keys())

        # Should have: param1, param2, oid, ctx
        assert 'oid' in params
        assert params.index('oid') == len(params) - 2  # Before ctx
        assert params[-1] == 'ctx'  # ctx is last

        # Check oid parameter details
        oid_param = sig.parameters['oid']
        assert oid_param.default is None
        assert oid_param.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD

    def test_wrapper_adds_oid_parameter_async(self):
        """Test that oid parameter is added to async function signature"""
        # Create a simple async tool
        async def sample_tool_async(param1: str, ctx) -> dict:
            return {"result": "ok"}

        # Wrap it
        wrapped = wrap_tool_for_multi_mode(sample_tool_async, is_async=True)

        # Check signature
        sig = inspect.signature(wrapped)
        params = list(sig.parameters.keys())

        assert 'oid' in params
        assert params[-2] == 'oid'  # Before ctx
        assert params[-1] == 'ctx'

    def test_wrapper_preserves_original_parameters(self):
        """Test that original parameters are preserved"""
        def complex_tool(a: str, b: int = 5, c: list = None, ctx=None):
            return {}

        wrapped = wrap_tool_for_multi_mode(complex_tool, is_async=False)
        sig = inspect.signature(wrapped)

        # Original params should be there
        assert 'a' in sig.parameters
        assert 'b' in sig.parameters
        assert 'c' in sig.parameters
        assert 'ctx' in sig.parameters
        assert 'oid' in sig.parameters


class TestUIDModeValidation:
    """Test UID mode detection and validation"""

    def test_uid_mode_requires_oid_sync(self):
        """Test that UID mode requires oid parameter (sync)"""
        def test_tool(ctx):
            return {"result": "ok"}

        wrapped = wrap_tool_for_multi_mode(test_tool, is_async=False)

        # Set UID mode
        uid_auth_context_var.set(("test-uid", "test-api-key", "api_key"))

        try:
            # Call without oid should fail
            with pytest.raises(ValueError) as exc_info:
                wrapped(ctx=Mock())

            assert "required in UID mode" in str(exc_info.value)
        finally:
            uid_auth_context_var.set(None)

    @pytest.mark.asyncio
    async def test_uid_mode_requires_oid_async(self):
        """Test that UID mode requires oid parameter (async)"""
        async def test_tool(ctx):
            return {"result": "ok"}

        wrapped = wrap_tool_for_multi_mode(test_tool, is_async=True)

        # Set UID mode
        uid_auth_context_var.set(("test-uid", "test-api-key", "api_key"))

        try:
            # Call without oid should fail
            with pytest.raises(ValueError) as exc_info:
                await wrapped(ctx=Mock())

            assert "required in UID mode" in str(exc_info.value)
        finally:
            uid_auth_context_var.set(None)

    def test_normal_mode_rejects_oid(self):
        """Test that normal mode rejects oid parameter"""
        def test_tool(ctx):
            return {"result": "ok"}

        wrapped = wrap_tool_for_multi_mode(test_tool, is_async=False)

        # Normal mode (no UID auth set)
        uid_auth_context_var.set(None)
        sdk_context_var.set(Mock())  # Mock SDK for normal mode

        try:
            # Call with oid should fail
            with pytest.raises(ValueError) as exc_info:
                wrapped(oid="test-oid", ctx=Mock())

            assert "not allowed in normal mode" in str(exc_info.value)
        finally:
            sdk_context_var.set(None)


class TestSDKCreation:
    """Test SDK creation in different modes"""

    @patch('server.limacharlie.Manager')
    def test_uid_mode_creates_sdk_with_correct_params(self, mock_manager):
        """Test that UID mode creates SDK with oid, uid, and api_key"""
        mock_sdk = Mock()
        mock_manager.return_value = mock_sdk

        def test_tool(ctx):
            # This should have SDK available
            sdk = sdk_context_var.get()
            return {"has_sdk": sdk is not None}

        wrapped = wrap_tool_for_multi_mode(test_tool, is_async=False)

        # Set UID mode
        uid_auth_context_var.set(("my-uid", "my-api-key", "api_key"))

        try:
            result = wrapped(oid="my-oid", ctx=Mock())

            # Verify SDK was created with correct parameters
            mock_manager.assert_called_once_with("my-oid", secret_api_key="my-api-key")

            # Verify SDK was cleaned up
            mock_sdk.shutdown.assert_called_once()
        finally:
            uid_auth_context_var.set(None)

    @pytest.mark.asyncio
    @patch('server.limacharlie.Manager')
    async def test_uid_mode_creates_sdk_async(self, mock_manager):
        """Test SDK creation in UID mode for async tools"""
        mock_sdk = Mock()
        mock_manager.return_value = mock_sdk

        async def test_tool(ctx):
            sdk = sdk_context_var.get()
            return {"has_sdk": sdk is not None}

        wrapped = wrap_tool_for_multi_mode(test_tool, is_async=True)

        uid_auth_context_var.set(("uid-async", "api-key-async", "api_key"))

        try:
            result = await wrapped(oid="oid-async", ctx=Mock())

            mock_manager.assert_called_once_with("oid-async", secret_api_key="api-key-async")
            mock_sdk.shutdown.assert_called_once()
        finally:
            uid_auth_context_var.set(None)

    def test_normal_mode_uses_existing_sdk(self):
        """Test that normal mode uses SDK from context"""
        mock_sdk = Mock()
        sdk_context_var.set(mock_sdk)

        def test_tool(ctx):
            sdk = sdk_context_var.get()
            return {"sdk": sdk}

        wrapped = wrap_tool_for_multi_mode(test_tool, is_async=False)

        # Normal mode
        uid_auth_context_var.set(None)

        try:
            result = wrapped(ctx=Mock())

            # Should return the existing SDK
            assert result["sdk"] == mock_sdk
        finally:
            sdk_context_var.set(None)


class TestContextIsolation:
    """Test that SDK instances are properly isolated between tool calls"""

    @patch('server.limacharlie.Manager')
    def test_different_oids_create_separate_sdks(self, mock_manager):
        """Test that different OIDs result in separate SDK instances"""
        # Track all SDK instances created
        sdk_instances = []

        def create_mock_sdk(*args, **kwargs):
            sdk = Mock()
            sdk_instances.append((args, kwargs, sdk))
            return sdk

        mock_manager.side_effect = create_mock_sdk

        def test_tool(ctx):
            return {"result": "ok"}

        wrapped = wrap_tool_for_multi_mode(test_tool, is_async=False)

        uid_auth_context_var.set(("test-uid", "test-api-key", "api_key"))

        try:
            # Call with first OID
            wrapped(oid="org-1", ctx=Mock())

            # Call with second OID
            wrapped(oid="org-2", ctx=Mock())

            # Should have created two separate SDKs
            assert len(sdk_instances) == 2
            assert sdk_instances[0][0][0] == "org-1"
            assert sdk_instances[1][0][0] == "org-2"

            # Both should be shut down
            assert sdk_instances[0][2].shutdown.called
            assert sdk_instances[1][2].shutdown.called
        finally:
            uid_auth_context_var.set(None)


class TestHelperFunctions:
    """Test helper functions"""

    @patch.dict(os.environ, {'LC_UID': 'env-uid'})
    def test_get_uid_from_environment_env_var(self):
        """Test getting UID from LC_UID environment variable"""
        uid = get_uid_from_environment()
        assert uid == 'env-uid'

    @patch.dict(os.environ, {}, clear=True)
    @patch('server.limacharlie.Manager')
    def test_get_uid_from_sdk_defaults(self, mock_manager):
        """Test getting UID from SDK defaults"""
        # Make sure LC_UID is not set
        if 'LC_UID' in os.environ:
            del os.environ['LC_UID']

        mock_sdk = Mock()
        mock_sdk._uid = 'sdk-uid'
        mock_manager.return_value = mock_sdk

        uid = get_uid_from_environment()
        assert uid == 'sdk-uid'

    @patch.dict(os.environ, {}, clear=True)
    @patch('server.limacharlie.Manager')
    def test_get_uid_returns_none_when_not_found(self, mock_manager):
        """Test that get_uid_from_environment returns None when UID not found"""
        if 'LC_UID' in os.environ:
            del os.environ['LC_UID']

        mock_sdk = Mock()
        del mock_sdk._uid  # No UID attribute
        mock_sdk.getDefaultUserId.return_value = None  # Mock method returns None
        mock_manager.return_value = mock_sdk

        uid = get_uid_from_environment()
        assert uid is None

    def test_validate_oid_parameter_uid_mode_missing(self):
        """Test validation fails when oid missing in UID mode"""
        with pytest.raises(ValueError) as exc_info:
            validate_oid_parameter(None, uid_mode=True, tool_name="test_tool")

        assert "required in UID mode" in str(exc_info.value)

    def test_validate_oid_parameter_uid_mode_present(self):
        """Test validation passes when oid present in UID mode"""
        # Should not raise
        validate_oid_parameter("test-oid", uid_mode=True, tool_name="test_tool")

    def test_validate_oid_parameter_normal_mode_present(self):
        """Test validation fails when oid present in normal mode"""
        with pytest.raises(ValueError) as exc_info:
            validate_oid_parameter("test-oid", uid_mode=False, tool_name="test_tool")

        assert "not allowed in normal mode" in str(exc_info.value)

    def test_validate_oid_parameter_normal_mode_missing(self):
        """Test validation passes when oid missing in normal mode"""
        # Should not raise
        validate_oid_parameter(None, uid_mode=False, tool_name="test_tool")


class TestBackwardCompatibility:
    """Test that normal mode still works as before"""

    def test_normal_mode_unchanged(self):
        """Test that tools work in normal mode without oid parameter"""
        mock_sdk = Mock()
        sdk_context_var.set(mock_sdk)

        def legacy_tool(param1: str, ctx):
            sdk = sdk_context_var.get()
            return {"param1": param1, "has_sdk": sdk is not None}

        wrapped = wrap_tool_for_multi_mode(legacy_tool, is_async=False)

        # Normal mode
        uid_auth_context_var.set(None)

        try:
            # Call without oid (normal mode)
            result = wrapped(param1="test", ctx=Mock())

            assert result["param1"] == "test"
            assert result["has_sdk"] is True
        finally:
            sdk_context_var.set(None)

    @pytest.mark.asyncio
    async def test_normal_mode_unchanged_async(self):
        """Test that async tools work in normal mode"""
        mock_sdk = Mock()
        sdk_context_var.set(mock_sdk)

        async def legacy_tool_async(param1: str, ctx):
            sdk = sdk_context_var.get()
            return {"param1": param1, "has_sdk": sdk is not None}

        wrapped = wrap_tool_for_multi_mode(legacy_tool_async, is_async=True)

        uid_auth_context_var.set(None)

        try:
            result = await wrapped(param1="test", ctx=Mock())

            assert result["param1"] == "test"
            assert result["has_sdk"] is True
        finally:
            sdk_context_var.set(None)


class TestToolExecution:
    """Test actual tool execution in both modes"""

    @patch('server.limacharlie.Manager')
    def test_tool_executes_correctly_uid_mode(self, mock_manager):
        """Test that tools execute correctly in UID mode"""
        mock_sdk = Mock()
        mock_manager.return_value = mock_sdk

        # Simulate a tool that uses the SDK
        def get_sensors(ctx):
            sdk = sdk_context_var.get()
            if not sdk:
                return {"error": "No SDK"}

            # Simulate SDK call
            return {"sensors": ["sensor1", "sensor2"]}

        wrapped = wrap_tool_for_multi_mode(get_sensors, is_async=False)

        uid_auth_context_var.set(("test-uid", "test-api-key", "api_key"))

        try:
            result = wrapped(oid="test-oid", ctx=Mock())

            # Tool should execute successfully
            assert "sensors" in result
            assert len(result["sensors"]) == 2

            # SDK should be created and cleaned up
            mock_manager.assert_called_once()
            mock_sdk.shutdown.assert_called_once()
        finally:
            uid_auth_context_var.set(None)

    def test_tool_executes_correctly_normal_mode(self):
        """Test that tools execute correctly in normal mode"""
        mock_sdk = Mock()
        sdk_context_var.set(mock_sdk)

        def get_sensors(ctx):
            sdk = sdk_context_var.get()
            if not sdk:
                return {"error": "No SDK"}

            return {"sensors": ["sensor1", "sensor2"]}

        wrapped = wrap_tool_for_multi_mode(get_sensors, is_async=False)

        uid_auth_context_var.set(None)

        try:
            result = wrapped(ctx=Mock())

            assert "sensors" in result
            assert len(result["sensors"]) == 2
        finally:
            sdk_context_var.set(None)


class TestErrorHandling:
    """Test error handling in various scenarios"""

    @patch('server.limacharlie.Manager')
    def test_sdk_creation_failure_handled(self, mock_manager):
        """Test that SDK creation failures are handled gracefully"""
        # Simulate SDK creation failure
        mock_manager.side_effect = Exception("SDK creation failed")

        def test_tool(ctx):
            return {"result": "ok"}

        wrapped = wrap_tool_for_multi_mode(test_tool, is_async=False)

        uid_auth_context_var.set(("test-uid", "test-api-key", "api_key"))

        try:
            # Should raise the exception from SDK creation
            with pytest.raises(Exception) as exc_info:
                wrapped(oid="test-oid", ctx=Mock())

            assert "SDK creation failed" in str(exc_info.value)
        finally:
            uid_auth_context_var.set(None)

    @patch('server.limacharlie.Manager')
    def test_sdk_shutdown_failure_ignored(self, mock_manager):
        """Test that SDK shutdown failures don't prevent tool execution"""
        mock_sdk = Mock()
        mock_sdk.shutdown.side_effect = Exception("Shutdown failed")
        mock_manager.return_value = mock_sdk

        def test_tool(ctx):
            return {"result": "ok"}

        wrapped = wrap_tool_for_multi_mode(test_tool, is_async=False)

        uid_auth_context_var.set(("test-uid", "test-api-key", "api_key"))

        try:
            # Should complete successfully despite shutdown failure
            result = wrapped(oid="test-oid", ctx=Mock())
            assert result["result"] == "ok"
        finally:
            uid_auth_context_var.set(None)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
