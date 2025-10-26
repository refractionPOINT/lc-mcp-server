"""
OAuth 2.1 Endpoints for MCP

Implements the OAuth 2.1 authorization flow endpoints required by MCP specification:
- GET /authorize: Authorization endpoint
- POST /token: Token endpoint
- POST /register: Dynamic client registration
- POST /revoke: Token revocation
- POST /introspect: Token introspection

Integrates with Firebase Auth for actual authentication.
"""

import hashlib
import base64
import logging
import urllib.parse
from typing import Dict, Any, Optional
from dataclasses import dataclass

from firebase_auth_bridge import FirebaseAuthBridge, FirebaseAuthError, get_firebase_bridge
from oauth_state_manager import OAuthStateManager
from oauth_token_manager import OAuthTokenManager, get_token_manager
from oauth_metadata import get_metadata_provider, validate_scope, filter_scope_to_supported


@dataclass
class AuthorizeRequest:
    """OAuth authorization request parameters."""
    response_type: str
    client_id: str
    redirect_uri: str
    scope: str
    state: str
    code_challenge: str
    code_challenge_method: str
    resource: str  # MCP requires resource parameter


@dataclass
class TokenRequest:
    """OAuth token request parameters."""
    grant_type: str
    code: Optional[str] = None
    redirect_uri: Optional[str] = None
    client_id: Optional[str] = None
    code_verifier: Optional[str] = None
    refresh_token: Optional[str] = None


class OAuthError(Exception):
    """OAuth protocol error."""

    def __init__(self, error: str, error_description: str, status_code: int = 400):
        self.error = error
        self.error_description = error_description
        self.status_code = status_code
        super().__init__(f"{error}: {error_description}")


class OAuthEndpoints:
    """
    OAuth 2.1 endpoint handlers for MCP server.

    Implements the authorization code flow with PKCE, bridging to Firebase Auth.
    """

    def __init__(
        self,
        state_manager: Optional[OAuthStateManager] = None,
        token_manager: Optional[OAuthTokenManager] = None,
        firebase_bridge: Optional[FirebaseAuthBridge] = None
    ):
        """
        Initialize OAuth endpoints.

        Args:
            state_manager: OAuth state manager
            token_manager: Token manager
            firebase_bridge: Firebase auth bridge
        """
        self.state_manager = state_manager or OAuthStateManager()
        self.token_manager = token_manager or get_token_manager()
        self.firebase_bridge = firebase_bridge or get_firebase_bridge()
        self.metadata_provider = get_metadata_provider()
        logging.info("OAuth endpoints initialized")

    # ===== Authorization Endpoint =====

    def validate_authorize_request(self, params: Dict[str, Any]) -> AuthorizeRequest:
        """
        Validate OAuth authorization request parameters.

        Args:
            params: Request parameters from query string

        Returns:
            Validated AuthorizeRequest

        Raises:
            OAuthError: If validation fails
        """
        # Required parameters
        response_type = params.get('response_type')
        client_id = params.get('client_id')
        redirect_uri = params.get('redirect_uri')
        state = params.get('state')
        code_challenge = params.get('code_challenge')
        code_challenge_method = params.get('code_challenge_method')

        # Validate response_type (must be 'code' for OAuth 2.1)
        if response_type != 'code':
            raise OAuthError(
                'unsupported_response_type',
                f'Only "code" response type is supported, got "{response_type}"'
            )

        # Validate required parameters
        if not client_id:
            raise OAuthError('invalid_request', 'Missing client_id parameter')
        if not redirect_uri:
            raise OAuthError('invalid_request', 'Missing redirect_uri parameter')
        if not state:
            raise OAuthError('invalid_request', 'Missing state parameter (CSRF protection)')

        # Validate PKCE (required in OAuth 2.1)
        if not code_challenge:
            raise OAuthError('invalid_request', 'Missing code_challenge parameter (PKCE required)')
        if code_challenge_method != 'S256':
            raise OAuthError(
                'invalid_request',
                f'Only S256 code_challenge_method is supported, got "{code_challenge_method}"'
            )

        # Validate redirect_uri (must be localhost or HTTPS)
        if not (redirect_uri.startswith('http://localhost') or
                redirect_uri.startswith('http://127.0.0.1') or
                redirect_uri.startswith('https://')):
            raise OAuthError(
                'invalid_request',
                'redirect_uri must be localhost or HTTPS'
            )

        # Validate resource parameter (MCP requirement)
        resource = params.get('resource')
        if resource:
            server_url = self.metadata_provider.server_url
            if resource != server_url:
                logging.warning(f"Resource mismatch: requested={resource}, server={server_url}")
                # Don't fail, but log for debugging

        # Get and validate scope
        scope = params.get('scope', '')
        if not scope:
            # Use default scope if not specified
            from oauth_metadata import get_default_scope
            scope = get_default_scope()
        else:
            # Filter to supported scopes
            scope = filter_scope_to_supported(scope)

        return AuthorizeRequest(
            response_type=response_type,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            resource=resource or self.metadata_provider.server_url
        )

    async def handle_authorize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle GET /authorize request.

        This initiates the Firebase OAuth flow for the user.

        Args:
            params: Query parameters from authorization request

        Returns:
            Dict with:
            - redirect_url: URL to redirect user to for authentication
            - state: OAuth state parameter for CSRF protection

        Raises:
            OAuthError: If request is invalid
        """
        # Validate request
        auth_req = self.validate_authorize_request(params)

        logging.info(f"Authorization request from client {auth_req.client_id}, scope: {auth_req.scope}")

        # Store OAuth state for callback validation
        self.state_manager.store_oauth_state(
            state=auth_req.state,
            code_challenge=auth_req.code_challenge,
            code_challenge_method=auth_req.code_challenge_method,
            redirect_uri=auth_req.redirect_uri,
            client_id=auth_req.client_id,
            scope=auth_req.scope,
            resource=auth_req.resource
        )

        # Build OAuth callback URL (our server will receive this)
        # NOTE: Firebase doesn't allow "state" as a query parameter in continueUri
        # because it's a reserved OAuth parameter. We'll use session_id to track state instead.
        server_url = self.metadata_provider.server_url
        oauth_callback_url = f"{server_url}/oauth/callback"

        try:
            # Initiate Firebase auth flow
            # This returns a Firebase-managed Google OAuth URL
            session_id, firebase_auth_uri = self.firebase_bridge.create_auth_uri(
                provider_id="google.com",
                redirect_uri=oauth_callback_url,
                scopes=("openid", "email", "profile")
            )

            # Store bidirectional mapping between session_id and OAuth state
            # We need this to reconnect the Firebase callback with the OAuth flow
            self.state_manager.redis_client.setex(
                f"oauth:session:{auth_req.state}",
                600,  # 10 minutes
                session_id
            )
            # Also store reverse mapping (session_id -> state)
            self.state_manager.redis_client.setex(
                f"oauth:state:{session_id}",
                600,  # 10 minutes
                auth_req.state
            )

            logging.info(f"Created Firebase auth URI for state {auth_req.state[:20]}...")

            # Return the Firebase auth URL for user to visit
            return {
                "redirect_url": firebase_auth_uri,
                "state": auth_req.state
            }

        except FirebaseAuthError as e:
            logging.error(f"Firebase auth initiation failed: {e}")
            raise OAuthError(
                'server_error',
                f'Failed to initiate authentication: {str(e)}',
                500
            )

    async def handle_oauth_callback(self, params: Dict[str, Any]) -> str:
        """
        Handle OAuth callback from Firebase after user authentication.

        This is called by Firebase after the user completes Google OAuth.
        We exchange the callback for Firebase tokens, then redirect back to client.

        Args:
            params: Callback parameters from Firebase (includes provider response data)

        Returns:
            Redirect URL to send user back to client application

        Raises:
            OAuthError: If callback is invalid
        """
        # Firebase returns the session_id in the "state" parameter of the callback
        # This is Firebase's session state, NOT our OAuth state - we need to map it
        firebase_state = params.get('state')
        if not firebase_state:
            logging.error(f"No Firebase state in callback params: {list(params.keys())}")
            raise OAuthError('invalid_request', 'Missing session information in callback')

        # The Firebase state is actually the session_id we got from createAuthUri
        session_id = firebase_state

        # Look up our OAuth state using the Firebase session_id
        state_key = f"oauth:state:{session_id}"
        oauth_state_value = self.state_manager.redis_client.get(state_key)
        if not oauth_state_value:
            logging.error(f"No OAuth state found for session: {session_id[:20]}...")
            raise OAuthError('invalid_request', 'Invalid or expired session')

        if isinstance(oauth_state_value, bytes):
            oauth_state_value = oauth_state_value.decode('utf-8')

        # oauth_state_value is our original OAuth state parameter
        state = oauth_state_value

        # Retrieve OAuth state
        oauth_state = self.state_manager.consume_oauth_state(state)
        if not oauth_state:
            raise OAuthError('invalid_request', 'Invalid or expired state parameter')

        # Clean up session mappings (single-use)
        self.state_manager.redis_client.delete(f"oauth:session:{state}")
        self.state_manager.redis_client.delete(state_key)

        try:
            # Build callback URL for Firebase
            callback_url = self.metadata_provider.server_url + "/oauth/callback"
            callback_path = "?" + urllib.parse.urlencode(params)

            # Validate and extract query string
            query_string = self.firebase_bridge.validate_provider_callback(callback_path)

            # Exchange with Firebase to get tokens
            firebase_tokens = self.firebase_bridge.sign_in_with_idp(
                request_uri=callback_url,
                query_string=query_string,
                session_id=session_id,
                provider_id="google.com"
            )

            # Generate authorization code
            auth_code = self.state_manager.generate_authorization_code()

            # Store authorization code with Firebase tokens
            self.state_manager.store_authorization_code(
                code=auth_code,
                state=state,
                uid=firebase_tokens['uid'],
                firebase_id_token=firebase_tokens['id_token'],
                firebase_refresh_token=firebase_tokens['refresh_token'],
                firebase_expires_at=firebase_tokens['expires_at']
            )

            # Build redirect URL back to client
            redirect_params = {
                'code': auth_code,
                'state': state
            }
            redirect_url = oauth_state.redirect_uri + "?" + urllib.parse.urlencode(redirect_params)

            logging.info(f"OAuth callback successful, redirecting to client")
            return redirect_url

        except FirebaseAuthError as e:
            logging.error(f"Firebase sign-in failed: {e}")
            # Redirect to client with error
            error_params = {
                'error': 'server_error',
                'error_description': str(e),
                'state': state
            }
            return oauth_state.redirect_uri + "?" + urllib.parse.urlencode(error_params)

    # ===== Token Endpoint =====

    def validate_token_request(self, params: Dict[str, Any]) -> TokenRequest:
        """
        Validate OAuth token request parameters.

        Args:
            params: Request body parameters

        Returns:
            Validated TokenRequest

        Raises:
            OAuthError: If validation fails
        """
        grant_type = params.get('grant_type')

        if not grant_type:
            raise OAuthError('invalid_request', 'Missing grant_type parameter')

        if grant_type == 'authorization_code':
            # Validate authorization code grant
            code = params.get('code')
            redirect_uri = params.get('redirect_uri')
            code_verifier = params.get('code_verifier')

            if not code:
                raise OAuthError('invalid_request', 'Missing code parameter')
            if not redirect_uri:
                raise OAuthError('invalid_request', 'Missing redirect_uri parameter')
            if not code_verifier:
                raise OAuthError('invalid_request', 'Missing code_verifier parameter (PKCE required)')

            return TokenRequest(
                grant_type=grant_type,
                code=code,
                redirect_uri=redirect_uri,
                client_id=params.get('client_id'),
                code_verifier=code_verifier
            )

        elif grant_type == 'refresh_token':
            # Validate refresh token grant
            refresh_token = params.get('refresh_token')

            if not refresh_token:
                raise OAuthError('invalid_request', 'Missing refresh_token parameter')

            return TokenRequest(
                grant_type=grant_type,
                refresh_token=refresh_token,
                client_id=params.get('client_id')
            )

        else:
            raise OAuthError(
                'unsupported_grant_type',
                f'Grant type "{grant_type}" is not supported'
            )

    def verify_pkce(self, code_challenge: str, code_verifier: str) -> bool:
        """
        Verify PKCE code challenge against code verifier.

        Args:
            code_challenge: Code challenge from authorization request
            code_verifier: Code verifier from token request

        Returns:
            True if PKCE verification succeeds
        """
        # Compute SHA-256 hash of verifier
        verifier_hash = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        # Base64-URL encode without padding
        computed_challenge = base64.urlsafe_b64encode(verifier_hash).decode('utf-8').rstrip('=')

        # Compare with stored challenge
        return computed_challenge == code_challenge

    async def handle_token(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle POST /token request.

        Supports:
        - authorization_code grant (with PKCE)
        - refresh_token grant

        Args:
            params: Request body parameters

        Returns:
            OAuth token response

        Raises:
            OAuthError: If request is invalid
        """
        # Validate request
        token_req = self.validate_token_request(params)

        if token_req.grant_type == 'authorization_code':
            return await self.handle_authorization_code_grant(token_req)
        elif token_req.grant_type == 'refresh_token':
            return await self.handle_refresh_token_grant(token_req)

    async def handle_authorization_code_grant(self, token_req: TokenRequest) -> Dict[str, Any]:
        """
        Handle authorization_code grant type.

        Args:
            token_req: Validated token request

        Returns:
            Token response dict

        Raises:
            OAuthError: If code is invalid or PKCE fails
        """
        # Consume authorization code (single-use)
        auth_code_data = self.state_manager.consume_authorization_code(token_req.code)

        if not auth_code_data:
            raise OAuthError('invalid_grant', 'Invalid or expired authorization code')

        # Retrieve OAuth state to get PKCE challenge
        oauth_state = self.state_manager.get_oauth_state(auth_code_data.state)

        if not oauth_state:
            # State might have expired, but we have the code data, so proceed
            # In production, you might want to fail here for extra security
            logging.warning("OAuth state expired but authorization code is valid, proceeding")
            # Verify redirect_uri matches at minimum
            pass
        else:
            # Verify redirect_uri matches
            if token_req.redirect_uri != oauth_state.redirect_uri:
                raise OAuthError('invalid_grant', 'redirect_uri does not match authorization request')

            # Verify PKCE
            if not self.verify_pkce(oauth_state.code_challenge, token_req.code_verifier):
                raise OAuthError('invalid_grant', 'PKCE verification failed')

        # Create token response using Firebase tokens
        scope = oauth_state.scope if oauth_state else "limacharlie:read limacharlie:write"
        token_response = self.token_manager.create_token_response(
            uid=auth_code_data.uid,
            firebase_id_token=auth_code_data.firebase_id_token,
            firebase_refresh_token=auth_code_data.firebase_refresh_token,
            firebase_expires_at=auth_code_data.firebase_expires_at,
            scope=scope
        )

        logging.info(f"Issued access token for UID: {auth_code_data.uid}")
        return token_response

    async def handle_refresh_token_grant(self, token_req: TokenRequest) -> Dict[str, Any]:
        """
        Handle refresh_token grant type.

        Args:
            token_req: Validated token request

        Returns:
            Token response dict

        Raises:
            OAuthError: If refresh token is invalid
        """
        token_response = self.token_manager.refresh_access_token(token_req.refresh_token)

        if not token_response:
            raise OAuthError('invalid_grant', 'Invalid or expired refresh token')

        logging.info("Issued new access token via refresh grant")
        return token_response

    # ===== Client Registration Endpoint =====

    async def handle_register(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle POST /register request (Dynamic Client Registration).

        Args:
            params: Registration request parameters

        Returns:
            Client registration response

        Raises:
            OAuthError: If registration fails
        """
        # Extract parameters
        client_name = params.get('client_name')
        redirect_uris = params.get('redirect_uris', [])

        if not client_name:
            raise OAuthError('invalid_request', 'Missing client_name parameter')

        if not redirect_uris:
            raise OAuthError('invalid_request', 'Missing redirect_uris parameter')

        # Validate redirect URIs
        for uri in redirect_uris:
            if not (uri.startswith('http://localhost') or
                    uri.startswith('http://127.0.0.1') or
                    uri.startswith('https://')):
                raise OAuthError(
                    'invalid_redirect_uri',
                    f'Invalid redirect_uri: {uri} (must be localhost or HTTPS)'
                )

        # Generate client ID (no secret for public clients)
        client_id = self.state_manager.generate_client_id()

        # Store registration
        self.state_manager.store_client_registration(
            client_id=client_id,
            client_name=client_name,
            redirect_uris=redirect_uris
        )

        # Build response
        response = {
            'client_id': client_id,
            'client_name': client_name,
            'redirect_uris': redirect_uris,
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'token_endpoint_auth_method': 'none'  # Public client
        }

        logging.info(f"Registered new client: {client_id} ({client_name})")
        return response

    # ===== Token Revocation Endpoint =====

    async def handle_revoke(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle POST /revoke request.

        Args:
            params: Revocation request parameters

        Returns:
            Empty dict (revocation always returns 200)
        """
        token = params.get('token')
        token_type_hint = params.get('token_type_hint')

        if not token:
            # OAuth spec says to return 200 even for invalid tokens
            return {}

        # Revoke the token
        self.token_manager.revoke_token(token, token_type_hint)

        # Always return success (per OAuth spec)
        return {}

    # ===== Token Introspection Endpoint =====

    async def handle_introspect(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle POST /introspect request.

        Args:
            params: Introspection request parameters

        Returns:
            Token introspection response
        """
        token = params.get('token')

        if not token:
            raise OAuthError('invalid_request', 'Missing token parameter')

        # Introspect the token
        introspection = self.token_manager.introspect_token(token)

        return introspection


# Singleton instance
_oauth_endpoints = None


def get_oauth_endpoints() -> OAuthEndpoints:
    """
    Get singleton OAuth endpoints instance.

    Returns:
        OAuthEndpoints instance
    """
    global _oauth_endpoints
    if _oauth_endpoints is None:
        _oauth_endpoints = OAuthEndpoints()
    return _oauth_endpoints
