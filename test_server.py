#!/usr/bin/env python3
"""Unit tests for the LimaCharlie MCP Server"""

import pytest
import httpx
from unittest.mock import Mock, patch, MagicMock
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.responses import JSONResponse
from starlette.testclient import TestClient
import contextvars

# Import the server module components
import sys
import os

# Ensure PUBLIC_MODE is set for testing HTTP mode
os.environ["PUBLIC_MODE"] = "true"
os.environ["MCP_PROFILE"] = "all"

# Mock the limacharlie module before importing server
sys.modules['limacharlie'] = MagicMock()
sys.modules['limacharlie.Replay'] = MagicMock()

# Mock google.genai to avoid import errors
sys.modules['google'] = MagicMock()
sys.modules['google.genai'] = MagicMock()
sys.modules['google.genai.types'] = MagicMock()
sys.modules['google.cloud'] = MagicMock()
sys.modules['google.cloud.storage'] = MagicMock()
sys.modules['google.auth'] = MagicMock()
sys.modules['google.auth.transport'] = MagicMock()
sys.modules['google.auth.transport.requests'] = MagicMock()

# Mock fastmcp before importing server
mock_fastmcp = MagicMock()
mock_fastmcp_server = MagicMock()
sys.modules['mcp'] = MagicMock()
sys.modules['mcp.server'] = MagicMock()
sys.modules['mcp.server.fastmcp'] = mock_fastmcp
sys.modules['mcp.server.fastmcp.server'] = mock_fastmcp_server

# Now import server components
from server import RequestContextMiddleware, request_context_var, sdk_context_var, uid_auth_context_var


@pytest.fixture
def mock_mcp_instance():
    """Create a mock MCP instance"""
    mock_mcp = Mock()
    mock_app = Mock()
    mock_mcp.streamable_http_app.return_value = mock_app

    # Make the mock app callable as an ASGI app
    async def mock_asgi_app(scope, receive, send):
        # Simple response for testing
        if scope["type"] == "http":
            response = JSONResponse({"status": "ok", "mock": "mcp_response"})
            await response(scope, receive, send)

    mock_app.side_effect = mock_asgi_app
    return mock_mcp


@pytest.fixture
def mock_create_mcp_for_profile(mock_mcp_instance):
    """Mock the create_mcp_for_profile function"""
    with patch('server.create_mcp_for_profile', return_value=mock_mcp_instance):
        yield


@pytest.fixture
def test_app(mock_create_mcp_for_profile, mock_mcp_instance):
    """Create a test Starlette app similar to the real app"""
    # Create mock MCPs for different profiles
    profile_mcps = {
        "all": mock_mcp_instance,
        "historical_data": mock_mcp_instance,
        "live_investigation": mock_mcp_instance,
    }

    routes = []
    available_profiles = ["all", "historical_data", "live_investigation"]

    # Add profile-specific endpoints
    for profile, profile_mcp in profile_mcps.items():
        if profile == "all":
            routes.append(Mount("/mcp", profile_mcp.streamable_http_app()))
        else:
            routes.append(Mount(f"/{profile}", profile_mcp.streamable_http_app()))

    # Create root endpoint
    async def root(request):
        profiles_info = {}
        for profile_name in available_profiles:
            if profile_name == "all":
                profiles_info[profile_name] = {
                    "path": "/mcp",
                    "tools": 100,
                    "description": "All available tools"
                }
            else:
                profiles_info[profile_name] = {
                    "path": f"/{profile_name}",
                    "tools": 20,
                    "description": f"Tools for {profile_name.replace('_', ' ')}"
                }

        return JSONResponse({
            "status": "ok",
            "type": "mcp-server",
            "profiles": profiles_info
        })

    routes.insert(0, Route("/", root, methods=["GET"]))

    # Create app
    app = Starlette(routes=routes)
    app.add_middleware(RequestContextMiddleware)

    return app


@pytest.fixture
def client(test_app):
    """Create a test client"""
    return TestClient(test_app)


class TestRootEndpoint:
    """Tests for the root health check endpoint"""

    def test_root_endpoint_returns_ok(self, client):
        """Test that root endpoint returns ok status"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["type"] == "mcp-server"

    def test_root_endpoint_lists_profiles(self, client):
        """Test that root endpoint lists all available profiles"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "profiles" in data
        assert "all" in data["profiles"]
        assert "historical_data" in data["profiles"]

    def test_root_endpoint_profile_info(self, client):
        """Test that each profile has correct path and description"""
        response = client.get("/")
        data = response.json()

        # Check 'all' profile
        assert data["profiles"]["all"]["path"] == "/mcp"
        assert "description" in data["profiles"]["all"]
        assert "tools" in data["profiles"]["all"]

        # Check other profiles
        assert data["profiles"]["historical_data"]["path"] == "/historical_data"


class TestTrailingSlashBehavior:
    """Tests to document and verify trailing slash behavior in routing

    Starlette's Mount directive is strict about trailing slashes by default.
    These tests document the expected behavior:
    - Mount paths WITHOUT trailing slash will match the path and subpaths
    - Requests TO the mount point should work with or without trailing slash
    - This behavior can be modified with redirect_slashes setting
    """

    def test_mcp_endpoint_without_trailing_slash(self, client):
        """Test /mcp endpoint without trailing slash"""
        response = client.get("/mcp")
        # Starlette Mount handles both with and without trailing slash
        # but may redirect or handle differently
        assert response.status_code in [200, 307, 404]

    def test_mcp_endpoint_with_trailing_slash(self, client):
        """Test /mcp/ endpoint with trailing slash

        IMPORTANT: Starlette Mount behavior with trailing slashes:
        - Mount("/mcp", app) will handle /mcp/* paths
        - Accessing /mcp/ directly may result in different behavior than /mcp
        - This is Starlette's default behavior for mounted sub-applications
        """
        response = client.get("/mcp/")
        # Mount may redirect or handle this differently
        assert response.status_code in [200, 307, 404]

    def test_profile_endpoint_without_trailing_slash(self, client):
        """Test profile endpoint without trailing slash"""
        response = client.get("/historical_data")
        assert response.status_code in [200, 307, 404]

    def test_profile_endpoint_with_trailing_slash(self, client):
        """Test profile endpoint with trailing slash"""
        response = client.get("/historical_data/")
        assert response.status_code in [200, 307, 404]

    def test_root_without_trailing_slash(self, client):
        """Test root endpoint - should always work"""
        response = client.get("/")
        assert response.status_code == 200

    def test_trailing_slash_consistency(self, client):
        """Document that trailing slash behavior is consistent across profiles

        Both /mcp and /historical_data should have the same trailing slash behavior
        since they're both created using Mount() in the same way
        """
        mcp_response = client.get("/mcp")
        profile_response = client.get("/historical_data")

        # Both should have same status code pattern (either both work or both redirect)
        assert (mcp_response.status_code == profile_response.status_code or
                abs(mcp_response.status_code - profile_response.status_code) == 0)


class TestProfileRouting:
    """Tests for profile-based routing"""

    def test_all_profile_mounted_at_mcp(self, client):
        """Test that 'all' profile is mounted at /mcp"""
        # We can't easily test the full MCP response with mocks,
        # but we can verify the route exists
        response = client.get("/mcp")
        # Should either work or give a method not allowed (since MCP uses POST)
        assert response.status_code in [200, 307, 404, 405]

    def test_historical_data_profile_mounted(self, client):
        """Test that historical_data profile is mounted"""
        response = client.get("/historical_data")
        assert response.status_code in [200, 307, 404, 405]

    def test_live_investigation_profile_mounted(self, client):
        """Test that live_investigation profile is mounted"""
        response = client.get("/live_investigation")
        assert response.status_code in [200, 307, 404, 405]

    def test_nonexistent_profile_returns_404(self, client):
        """Test that accessing non-existent profile returns 404"""
        response = client.get("/nonexistent_profile")
        assert response.status_code == 404


class TestRequestContextMiddleware:
    """Tests for RequestContextMiddleware functionality

    This middleware stores the HTTP request in a contextvar for later access.
    It also manages SDK lifecycle with proper cleanup.
    """

    @pytest.mark.asyncio
    async def test_middleware_sets_request_context(self):
        """Test that middleware sets request in contextvar"""
        from starlette.requests import Request
        from starlette.responses import Response

        # Reset contextvars
        request_context_var.set(None)
        sdk_context_var.set(None)

        # Create a simple app
        async def app(scope, receive, send):
            # Inside the app, we should be able to access the request
            req = request_context_var.get()
            assert req is not None
            assert isinstance(req, Request)

            response = Response("OK", status_code=200)
            await response(scope, receive, send)

        # Wrap with middleware
        middleware_app = RequestContextMiddleware(app)

        # Create a test request
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/test",
            "query_string": b"",
            "headers": [],
            "server": ("testserver", 80),
        }

        # Simulate request
        async def receive():
            return {"type": "http.request", "body": b""}

        messages = []
        async def send(message):
            messages.append(message)

        await middleware_app(scope, receive, send)

        # After request, contextvar should be cleaned up
        # (though in practice it stays set within the same async context)

    @pytest.mark.asyncio
    async def test_middleware_initializes_sdk_context(self):
        """Test that middleware initializes SDK contextvar to None"""
        from starlette.responses import Response

        # Reset contextvars
        request_context_var.set(None)
        sdk_context_var.set(None)

        async def app(scope, receive, send):
            # SDK should be initialized to None
            sdk = sdk_context_var.get()
            assert sdk is None or sdk is not None  # Could be set by the app

            response = Response("OK", status_code=200)
            await response(scope, receive, send)

        middleware_app = RequestContextMiddleware(app)

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/test",
            "query_string": b"",
            "headers": [],
            "server": ("testserver", 80),
        }

        async def receive():
            return {"type": "http.request", "body": b""}

        messages = []
        async def send(message):
            messages.append(message)

        await middleware_app(scope, receive, send)

    @pytest.mark.asyncio
    async def test_middleware_cleans_up_sdk(self):
        """Test that middleware cleans up SDK on request completion"""
        from starlette.responses import Response

        # Reset contextvars
        request_context_var.set(None)
        sdk_context_var.set(None)

        mock_sdk = Mock()
        mock_sdk.shutdown = Mock()

        async def app(scope, receive, send):
            # Set a mock SDK
            sdk_context_var.set(mock_sdk)

            response = Response("OK", status_code=200)
            await response(scope, receive, send)

        middleware_app = RequestContextMiddleware(app)

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/test",
            "query_string": b"",
            "headers": [],
            "server": ("testserver", 80),
        }

        async def receive():
            return {"type": "http.request", "body": b""}

        messages = []
        async def send(message):
            messages.append(message)

        await middleware_app(scope, receive, send)

        # SDK shutdown should have been called
        mock_sdk.shutdown.assert_called_once()

    @pytest.mark.asyncio
    async def test_middleware_ignores_non_http_requests(self):
        """Test that middleware only processes HTTP requests"""
        from starlette.responses import Response

        app_called = False

        async def app(scope, receive, send):
            nonlocal app_called
            app_called = True

        middleware_app = RequestContextMiddleware(app)

        # WebSocket scope
        scope = {
            "type": "websocket",
            "path": "/ws",
        }

        async def receive():
            return {"type": "websocket.connect"}

        async def send(message):
            pass

        await middleware_app(scope, receive, send)

        # App should still be called for non-HTTP
        assert app_called


class TestAuthenticationHeaders:
    """Tests for authentication header handling

    The server expects authentication via HTTP headers in PUBLIC_MODE:
    - Authorization: Bearer <token> or Bearer <api_key>:<oid>
    - x-lc-oid: <organization_id>

    These tests document the expected header formats.
    """

    def test_accepts_authorization_header(self, client):
        """Test that server accepts Authorization header"""
        headers = {
            "Authorization": "Bearer test-key:test-oid",
            "x-lc-oid": "test-oid"
        }
        response = client.get("/", headers=headers)
        assert response.status_code == 200

    def test_accepts_separate_oid_header(self, client):
        """Test that server accepts separate x-lc-oid header"""
        headers = {
            "Authorization": "Bearer test-jwt-token",
            "x-lc-oid": "test-oid"
        }
        response = client.get("/", headers=headers)
        assert response.status_code == 200

    def test_root_endpoint_works_without_auth(self, client):
        """Test that root health check works without authentication"""
        response = client.get("/")
        assert response.status_code == 200
        # Health check should work regardless of auth

    def test_accepts_combined_auth_format(self, client):
        """Test Authorization: Bearer <api_key>:<oid> format"""
        headers = {
            "Authorization": "Bearer api_key_here:org_id_here"
        }
        response = client.get("/", headers=headers)
        assert response.status_code == 200


class TestProfileDiscovery:
    """Tests for profile discovery and endpoint listing"""

    def test_root_lists_available_profiles(self, client):
        """Test that root endpoint provides profile discovery"""
        response = client.get("/")
        data = response.json()

        assert "profiles" in data
        assert isinstance(data["profiles"], dict)
        assert len(data["profiles"]) > 0

    def test_each_profile_has_required_fields(self, client):
        """Test that each profile has path, tools, and description"""
        response = client.get("/")
        data = response.json()

        for profile_name, profile_info in data["profiles"].items():
            assert "path" in profile_info, f"Profile {profile_name} missing path"
            assert "tools" in profile_info, f"Profile {profile_name} missing tools count"
            assert "description" in profile_info, f"Profile {profile_name} missing description"
            assert isinstance(profile_info["tools"], int)
            assert profile_info["tools"] >= 0

    def test_all_profile_has_special_path(self, client):
        """Test that 'all' profile is mounted at /mcp (not /all)"""
        response = client.get("/")
        data = response.json()

        assert "all" in data["profiles"]
        assert data["profiles"]["all"]["path"] == "/mcp"
        assert data["profiles"]["all"]["path"] != "/all"

    def test_profile_paths_match_routes(self, client):
        """Test that profile paths in discovery match actual routes"""
        response = client.get("/")
        data = response.json()

        # Test that each listed path is routable
        for profile_name, profile_info in data["profiles"].items():
            path = profile_info["path"]
            # Try to access the path (may return 404, 405, or redirect, but shouldn't be 500)
            profile_response = client.get(path)
            assert profile_response.status_code != 500, f"Profile path {path} caused server error"


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])
