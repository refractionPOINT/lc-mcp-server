"""
Test suite for MCP OAuth 2.1 flow

Tests the complete OAuth integration including:
- OAuth endpoint handlers
- Token management
- Firebase auth bridge
- State management
- PKCE validation
"""

import pytest
import hashlib
import base64
import secrets
from unittest.mock import Mock, patch, MagicMock
import json

# Mock Redis before importing OAuth modules
@pytest.fixture(autouse=True)
def mock_redis():
    with patch('redis.from_url') as mock_from_url:
        mock_client = MagicMock()
        mock_client.ping.return_value = True
        mock_client.get.return_value = None
        mock_client.setex.return_value = True
        mock_client.set.return_value = True
        mock_client.delete.return_value = 1
        mock_from_url.return_value = mock_client
        yield mock_client


from oauth_state_manager import OAuthStateManager, OAuthState, AuthorizationCode, AccessTokenData
from oauth_token_manager import OAuthTokenManager, TokenValidationResult
from oauth_endpoints import OAuthEndpoints, OAuthError, AuthorizeRequest
from oauth_metadata import OAuthMetadataProvider
from firebase_auth_bridge import FirebaseAuthBridge, FirebaseAuthError


class TestOAuthStateManager:
    """Test OAuth state management in Redis."""

    @pytest.fixture
    def state_manager(self, mock_redis):
        return OAuthStateManager(redis_url="redis://localhost:6379")

    def test_ping(self, state_manager, mock_redis):
        """Test Redis connectivity check."""
        assert state_manager.ping() is True
        mock_redis.ping.assert_called_once()

    def test_generate_state(self, state_manager):
        """Test state generation."""
        state = state_manager.generate_state()
        assert isinstance(state, str)
        assert len(state) > 40  # Base64 encoded 32 bytes

    def test_store_and_get_oauth_state(self, state_manager, mock_redis):
        """Test storing and retrieving OAuth state."""
        state = "test_state_123"
        state_manager.store_oauth_state(
            state=state,
            code_challenge="challenge123",
            code_challenge_method="S256",
            redirect_uri="http://localhost:8080/callback",
            client_id="test_client",
            scope="limacharlie:read",
            resource="http://localhost:8080"
        )

        # Verify setex was called
        assert mock_redis.setex.called

    def test_generate_authorization_code(self, state_manager):
        """Test authorization code generation."""
        code = state_manager.generate_authorization_code()
        assert isinstance(code, str)
        assert len(code) > 40

    def test_generate_access_token(self, state_manager):
        """Test access token generation."""
        token = state_manager.generate_access_token()
        assert isinstance(token, str)
        assert len(token) > 40


class TestOAuthMetadataProvider:
    """Test OAuth metadata endpoints."""

    @pytest.fixture
    def metadata_provider(self):
        return OAuthMetadataProvider(server_url="http://localhost:8080")

    def test_get_protected_resource_metadata(self, metadata_provider):
        """Test protected resource metadata."""
        metadata = metadata_provider.get_protected_resource_metadata()

        assert metadata['resource'] == "http://localhost:8080"
        assert "http://localhost:8080" in metadata['authorization_servers']
        assert "limacharlie:read" in metadata['scopes_supported']
        assert "header" in metadata['bearer_methods_supported']

    def test_get_authorization_server_metadata(self, metadata_provider):
        """Test authorization server metadata."""
        metadata = metadata_provider.get_authorization_server_metadata()

        assert metadata['issuer'] == "http://localhost:8080"
        assert metadata['authorization_endpoint'] == "http://localhost:8080/authorize"
        assert metadata['token_endpoint'] == "http://localhost:8080/token"
        assert "S256" in metadata['code_challenge_methods_supported']
        assert "code" in metadata['response_types_supported']

    def test_www_authenticate_header(self, metadata_provider):
        """Test WWW-Authenticate header generation."""
        header = metadata_provider.generate_www_authenticate_header(
            error="invalid_token",
            error_description="Token expired"
        )

        assert "Bearer" in header
        assert "resource_metadata=" in header
        assert "error=" in header
        assert "invalid_token" in header


class TestFirebaseAuthBridge:
    """Test Firebase authentication bridge."""

    @pytest.fixture
    def firebase_bridge(self):
        return FirebaseAuthBridge()

    @patch('firebase_auth_bridge.requests.post')
    def test_create_auth_uri(self, mock_post, firebase_bridge):
        """Test Firebase createAuthUri call."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "sessionId": "session123",
            "authUri": "https://accounts.google.com/o/oauth2/v2/auth?..."
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        session_id, auth_uri = firebase_bridge.create_auth_uri(
            provider_id="google.com",
            redirect_uri="http://localhost:8080/callback"
        )

        assert session_id == "session123"
        assert auth_uri.startswith("https://accounts.google.com")
        mock_post.assert_called_once()

    @patch('firebase_auth_bridge.requests.post')
    def test_sign_in_with_idp(self, mock_post, firebase_bridge):
        """Test Firebase signInWithIdp call."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "idToken": "firebase_id_token_123",
            "refreshToken": "firebase_refresh_token_456",
            "expiresIn": "3600",
            "localId": "firebase_uid_789"
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        result = firebase_bridge.sign_in_with_idp(
            request_uri="http://localhost:8080/callback",
            query_string="code=abc123&state=xyz",
            session_id="session123"
        )

        assert result['id_token'] == "firebase_id_token_123"
        assert result['refresh_token'] == "firebase_refresh_token_456"
        assert result['uid'] == "firebase_uid_789"
        assert 'expires_at' in result

    def test_validate_provider_callback_with_error(self, firebase_bridge):
        """Test callback validation with OAuth error."""
        callback = "?error=access_denied&error_description=User+denied"

        with pytest.raises(FirebaseAuthError) as exc_info:
            firebase_bridge.validate_provider_callback(callback)

        assert "access_denied" in str(exc_info.value)


class TestOAuthEndpoints:
    """Test OAuth endpoint handlers."""

    @pytest.fixture
    def oauth_endpoints(self, mock_redis):
        return OAuthEndpoints()

    def test_validate_authorize_request_success(self, oauth_endpoints):
        """Test successful authorization request validation."""
        params = {
            'response_type': 'code',
            'client_id': 'test_client',
            'redirect_uri': 'http://localhost:8080/callback',
            'state': 'random_state_123',
            'code_challenge': 'challenge123',
            'code_challenge_method': 'S256',
            'scope': 'limacharlie:read'
        }

        result = oauth_endpoints.validate_authorize_request(params)

        assert isinstance(result, AuthorizeRequest)
        assert result.client_id == 'test_client'
        assert result.code_challenge_method == 'S256'

    def test_validate_authorize_request_missing_pkce(self, oauth_endpoints):
        """Test authorization request validation without PKCE."""
        params = {
            'response_type': 'code',
            'client_id': 'test_client',
            'redirect_uri': 'http://localhost:8080/callback',
            'state': 'random_state_123',
            # Missing code_challenge
        }

        with pytest.raises(OAuthError) as exc_info:
            oauth_endpoints.validate_authorize_request(params)

        assert exc_info.value.error == 'invalid_request'
        assert "code_challenge" in exc_info.value.error_description.lower()

    def test_validate_authorize_request_wrong_challenge_method(self, oauth_endpoints):
        """Test authorization request with unsupported challenge method."""
        params = {
            'response_type': 'code',
            'client_id': 'test_client',
            'redirect_uri': 'http://localhost:8080/callback',
            'state': 'random_state_123',
            'code_challenge': 'challenge123',
            'code_challenge_method': 'plain',  # Only S256 supported
        }

        with pytest.raises(OAuthError) as exc_info:
            oauth_endpoints.validate_authorize_request(params)

        assert "S256" in exc_info.value.error_description

    def test_verify_pkce_success(self, oauth_endpoints):
        """Test successful PKCE verification."""
        # Generate verifier and challenge
        verifier = secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).decode().rstrip('=')

        result = oauth_endpoints.verify_pkce(challenge, verifier)
        assert result is True

    def test_verify_pkce_failure(self, oauth_endpoints):
        """Test failed PKCE verification."""
        challenge = "valid_challenge"
        verifier = "wrong_verifier"

        result = oauth_endpoints.verify_pkce(challenge, verifier)
        assert result is False


class TestOAuthTokenManager:
    """Test OAuth token management."""

    @pytest.fixture
    def token_manager(self, mock_redis):
        return OAuthTokenManager()

    @patch('oauth_token_manager.OAuthStateManager')
    def test_validate_access_token_not_found(self, mock_state_mgr, token_manager):
        """Test validation of non-existent token."""
        token_manager.state_manager.get_access_token_data = Mock(return_value=None)

        result = token_manager.validate_access_token("invalid_token")

        assert result.valid is False
        assert result.error is not None

    @patch('oauth_token_manager.OAuthStateManager')
    @patch('oauth_token_manager.FirebaseAuthBridge')
    def test_create_token_response(self, mock_firebase, mock_state_mgr, token_manager):
        """Test creating OAuth token response."""
        token_manager.state_manager.generate_access_token = Mock(return_value="access_123")
        token_manager.state_manager.generate_refresh_token = Mock(return_value="refresh_456")
        token_manager.state_manager.store_access_token = Mock()
        token_manager.state_manager.store_refresh_token = Mock()

        response = token_manager.create_token_response(
            uid="test_uid",
            firebase_id_token="fb_id_token",
            firebase_refresh_token="fb_refresh_token",
            firebase_expires_at=1234567890,
            scope="limacharlie:read limacharlie:write"
        )

        assert response['access_token'] == "access_123"
        assert response['refresh_token'] == "refresh_456"
        assert response['token_type'] == "Bearer"
        assert response['scope'] == "limacharlie:read limacharlie:write"


class TestIntegration:
    """Integration tests for complete OAuth flow."""

    @pytest.mark.asyncio
    async def test_metadata_discovery(self):
        """Test OAuth metadata discovery endpoints."""
        metadata_provider = OAuthMetadataProvider(server_url="http://localhost:8080")

        # Test protected resource metadata
        resource_meta = metadata_provider.get_protected_resource_metadata()
        assert 'authorization_servers' in resource_meta
        assert 'scopes_supported' in resource_meta

        # Test authorization server metadata
        authz_meta = metadata_provider.get_authorization_server_metadata()
        assert authz_meta['authorization_endpoint'].endswith('/authorize')
        assert authz_meta['token_endpoint'].endswith('/token')
        assert 'S256' in authz_meta['code_challenge_methods_supported']

    def test_pkce_end_to_end(self):
        """Test complete PKCE flow."""
        endpoints = OAuthEndpoints()

        # 1. Client generates verifier
        verifier = secrets.token_urlsafe(32)

        # 2. Client generates challenge
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).decode().rstrip('=')

        # 3. Server validates PKCE
        assert endpoints.verify_pkce(challenge, verifier) is True
        assert endpoints.verify_pkce(challenge, "wrong_verifier") is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
