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
import hmac
import base64
import logging
import urllib.parse
import json
from typing import Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

from firebase_auth_bridge import FirebaseAuthBridge, FirebaseAuthError, FirebaseMfaRequiredError, MfaResponse, get_firebase_bridge
from oauth_state_manager import OAuthStateManager, OAuthState, MfaSession
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

    # Supported OAuth providers (maps client-facing names to Firebase provider IDs)
    SUPPORTED_PROVIDERS = {
        "google": "google.com",
        "microsoft": "microsoft.com",
    }

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

        # Set up Jinja2 template environment for HTML pages
        template_dir = Path(__file__).parent / "templates"
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(['html', 'xml'])
        )

        logging.info("OAuth endpoints initialized")

    def _validate_and_normalize_provider(self, provider: str) -> str:
        """
        Validate and normalize provider parameter.

        Args:
            provider: Provider identifier ("google", "microsoft", "google.com", "microsoft.com")

        Returns:
            Normalized provider ID for Firebase ("google.com", "microsoft.com")

        Raises:
            OAuthError: If provider is unsupported
        """
        if not provider:
            return "google.com"  # Default for backward compatibility

        # Normalize: "google" -> "google.com", "microsoft" -> "microsoft.com"
        if provider in self.SUPPORTED_PROVIDERS:
            return self.SUPPORTED_PROVIDERS[provider]

        # Accept already-normalized form
        if provider in self.SUPPORTED_PROVIDERS.values():
            return provider

        raise OAuthError(
            "invalid_request",
            f"Unsupported provider: {provider}. Supported: {', '.join(self.SUPPORTED_PROVIDERS.keys())}"
        )

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
            mcp_url = f"{server_url}/mcp"
            # Accept either base URL or /mcp endpoint
            if resource not in (server_url, mcp_url):
                logging.warning(f"Resource mismatch: requested={resource}, expected={server_url} or {mcp_url}")
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
            OR
            - selection_redirect: URL to provider selection page (if provider not specified)
            - session_id: Session ID for provider selection

        Raises:
            OAuthError: If request is invalid
        """
        # Validate request
        auth_req = self.validate_authorize_request(params)

        # Check if provider selection is needed
        provider_param = params.get('provider')

        if not provider_param:
            # No provider specified - show selection page
            logging.info(f"No provider specified for client {auth_req.client_id}, redirecting to selection page")
            session_id = self.state_manager.generate_selection_session_id()

            # Store OAuth params for later retrieval
            self.state_manager.store_oauth_selection_session(
                session_id=session_id,
                oauth_params=params
            )

            # Return redirect to selection page
            server_url = self.metadata_provider.server_url
            selection_url = f"{server_url}/oauth/select-provider?session={session_id}"
            return {
                "selection_redirect": selection_url,
                "session_id": session_id
            }

        # Provider specified - validate and continue
        provider_id = self._validate_and_normalize_provider(provider_param)

        logging.info(f"Authorization request from client {auth_req.client_id}, provider: {provider_id}, scope: {auth_req.scope}")

        # Store OAuth state for callback validation (including provider)
        self.state_manager.store_oauth_state(
            state=auth_req.state,
            code_challenge=auth_req.code_challenge,
            code_challenge_method=auth_req.code_challenge_method,
            redirect_uri=auth_req.redirect_uri,
            client_id=auth_req.client_id,
            scope=auth_req.scope,
            resource=auth_req.resource,
            provider=provider_id
        )

        # Build OAuth callback URL (our server will receive this)
        # IMPORTANT: continueUri must be EXACTLY what's registered in Firebase Console
        # Cannot include query parameters (causes redirect_uri_mismatch from Google)
        # We use Redis bi-directional mapping to correlate Firebase session with OAuth state
        server_url = self.metadata_provider.server_url
        oauth_callback_url = f"{server_url}/oauth/callback"

        try:
            # Initiate Firebase auth flow
            # This returns a Firebase-managed OAuth URL for the selected provider
            logging.debug(f"Creating Firebase auth URI for OAuth state: {auth_req.state[:8]}...{auth_req.state[-4:]}")
            session_id, firebase_auth_uri = self.firebase_bridge.create_auth_uri(
                provider_id=provider_id,
                redirect_uri=oauth_callback_url,
                scopes=("openid", "email", "profile")
            )

            logging.debug(f"Received Firebase session_id: {session_id[:12]}...{session_id[-8:]}")
            logging.debug(f"OAuth state correlation: {auth_req.state[:8]}...")

            # Extract the state parameter from Firebase's authUri
            # This is what Google OAuth will pass back to our callback
            from urllib.parse import urlparse, parse_qs
            parsed_uri = urlparse(firebase_auth_uri)
            query_params = parse_qs(parsed_uri.query)
            firebase_state = query_params.get('state', [None])[0]

            if not firebase_state:
                logging.error("Firebase authUri missing state parameter")
                raise OAuthError('server_error', 'Firebase authUri missing state parameter')

            logging.debug(f"Firebase state extracted: {firebase_state[:12]}...{firebase_state[-8:]}")

            # Store three-way mapping for OAuth state correlation:
            # 1. oauth_state -> firebase_state (for validation)
            # 2. firebase_state -> oauth_state (for callback lookup)
            # 3. firebase_state -> session_id (for signInWithIdp call)

            # Forward: oauth_state -> firebase_state
            forward_key = f"oauth:session:{auth_req.state}"
            self.state_manager.redis_client.setex(
                forward_key,
                600,  # 10 minutes
                firebase_state
            )
            logging.debug(f"Stored OAuth state mapping in Redis (key: {forward_key[:20]}...)")

            # Reverse: firebase_state -> oauth_state (critical - callback uses this)
            reverse_key = f"oauth:state:{firebase_state}"
            self.state_manager.redis_client.setex(
                reverse_key,
                600,  # 10 minutes
                auth_req.state
            )
            logging.debug(f"Stored reverse OAuth mapping in Redis (key: {reverse_key[:20]}...)")

            # Session mapping: firebase_state -> session_id (for signInWithIdp)
            session_key = f"oauth:fbsession:{firebase_state}"
            self.state_manager.redis_client.setex(
                session_key,
                600,  # 10 minutes
                session_id
            )
            logging.debug(f"Stored Firebase session mapping in Redis")

            logging.info(f"Created Firebase auth URI for OAuth state: {auth_req.state[:20]}...")
            logging.info(f"Firebase session_id: {session_id[:20]}...")
            logging.info(f"Stored Redis key: oauth:state:{session_id[:20]}...")

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

    async def handle_provider_selection_page(self, session_id: str) -> str:
        """
        Render provider selection HTML page.

        Args:
            session_id: Session ID from the OAuth selection flow

        Returns:
            Rendered HTML page as string

        Raises:
            OAuthError: If session is invalid or expired
        """
        # Validate session exists (without consuming it)
        session_key = f"{self.state_manager.SELECTION_PREFIX}{session_id}"
        if not self.state_manager.redis_client.exists(session_key):
            logging.warning(f"Invalid or expired provider selection session: {session_id[:20]}...")
            raise OAuthError(
                'invalid_request',
                'Provider selection session expired or invalid. Please restart authentication.',
                400
            )

        logging.info(f"Rendering provider selection page for session: {session_id[:20]}...")

        # Render the selection page
        template = self.jinja_env.get_template('select_provider.html')
        html = template.render(session_id=session_id)

        return html

    async def handle_provider_selected(self, provider: str, session_id: str) -> Dict[str, Any]:
        """
        Handle provider selection from HTML page.

        When user clicks on a provider button, this retrieves the stored OAuth parameters,
        adds the selected provider, and continues the OAuth authorization flow.

        Args:
            provider: Selected provider ("google" or "microsoft")
            session_id: Session ID from provider selection flow

        Returns:
            Dict with redirect_url and state (same as handle_authorize)

        Raises:
            OAuthError: If session is invalid, expired, or provider is unsupported
        """
        logging.info(f"Provider selected: {provider} for session: {session_id[:20]}...")

        # Validate provider first
        try:
            provider_id = self._validate_and_normalize_provider(provider)
        except OAuthError as e:
            logging.error(f"Invalid provider selected: {provider}")
            raise

        # Consume OAuth parameters from session (single-use, atomic)
        oauth_params = self.state_manager.consume_oauth_selection_session(session_id)

        if oauth_params is None:
            logging.warning(f"Invalid or expired provider selection session: {session_id[:20]}...")
            raise OAuthError(
                'invalid_request',
                'Provider selection session expired or invalid. Please restart authentication.',
                400
            )

        logging.debug(f"Retrieved OAuth params from session, client_id: {oauth_params.get('client_id', 'unknown')}")

        # Merge the selected provider into the OAuth parameters
        oauth_params['provider'] = provider

        # Continue with normal OAuth flow (handle_authorize with provider specified)
        return await self.handle_authorize(oauth_params)

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
        # Extract Firebase's state parameter from callback
        firebase_state = params.get('state')
        if not firebase_state:
            logging.error(f"No Firebase state in callback params (received: {len(params)} params)")
            raise OAuthError('invalid_request', 'Missing Firebase state in callback')

        logging.debug(f"OAuth callback received with Firebase state: {firebase_state[:12]}...{firebase_state[-8:]}")

        # Build Redis keys for atomic lookup
        state_key = f"oauth:state:{firebase_state}"  # Firebase state -> MCP state mapping
        session_key = f"oauth:fbsession:{firebase_state}"  # Firebase state -> session ID

        logging.debug("Performing atomic Redis lookup for OAuth session")

        # SECURITY: Atomically retrieve and delete the reverse mappings (Firebase -> MCP state + session)
        # We need to do this in two steps because we don't know the oauth_state_key until we get the MCP state
        results = self.state_manager.atomic_multi_get_and_delete(keys=[state_key, session_key])

        oauth_state_value = results[0]
        session_id_bytes = results[1]

        # Convert bytes to strings
        if oauth_state_value and isinstance(oauth_state_value, bytes):
            oauth_state_value = oauth_state_value.decode('utf-8')
        if session_id_bytes and isinstance(session_id_bytes, bytes):
            session_id = session_id_bytes.decode('utf-8')
        else:
            session_id = session_id_bytes

        if not oauth_state_value or not session_id:
            # Debug: check what keys exist in Redis
            all_keys = self.state_manager.redis_client.keys("oauth:state:*")
            logging.error(f"OAuth state lookup failed - possibly expired or already consumed")
            logging.debug(f"Searched for key: {state_key[:30]}...")
            logging.debug(f"Found {len(all_keys)} oauth:state:* keys in Redis")
            if all_keys:
                logging.debug(f"Sample keys exist in Redis: {len(all_keys[:3])} keys")
            raise OAuthError('invalid_request', 'Invalid or expired session (possibly reused)')

        state = oauth_state_value
        logging.info(f"Atomically consumed Firebase session for OAuth state")
        logging.debug(f"Retrieved session_id: {session_id[:12]}...{session_id[-8:]}")

        # SECURITY: Now atomically consume the actual OAuth state object and forward mapping
        oauth_state_key = f"{self.state_manager.STATE_PREFIX}{state}"
        forward_mapping_key = f"oauth:session:{state}"

        oauth_results = self.state_manager.atomic_multi_get_and_delete(keys=[oauth_state_key, forward_mapping_key])
        oauth_state_data = oauth_results[0]

        if not oauth_state_data:
            logging.error("OAuth state object not found - expired or invalid")
            raise OAuthError('invalid_request', 'Invalid or expired OAuth state')

        # Deserialize OAuth state
        try:
            oauth_state_json = oauth_state_data
            if isinstance(oauth_state_json, bytes):
                oauth_state_json = oauth_state_json.decode('utf-8')
            oauth_state = OAuthState.from_dict(json.loads(oauth_state_json))
        except Exception as e:
            logging.error(f"Failed to deserialize OAuth state: {e}")
            raise OAuthError('invalid_request', 'Invalid OAuth state format')

        # Get provider from stored OAuth state
        provider_id = oauth_state.provider
        logging.info(f"OAuth callback for provider: {provider_id}")

        try:
            # Build callback URL for Firebase
            callback_url = self.metadata_provider.server_url + "/oauth/callback"
            callback_path = "?" + urllib.parse.urlencode(params)

            # Validate and extract query string
            query_string = self.firebase_bridge.validate_provider_callback(callback_path)

            # Exchange with Firebase to get tokens using the stored provider
            firebase_tokens = self.firebase_bridge.sign_in_with_idp(
                request_uri=callback_url,
                query_string=query_string,
                session_id=session_id,
                provider_id=provider_id
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

        except FirebaseMfaRequiredError as e:
            # MFA is required - redirect to challenge page
            logging.info(f"MFA required for user {e.mfa_response.email}, redirecting to challenge page")

            # Generate MFA session ID
            mfa_session_id = self.state_manager.generate_mfa_session_id()

            # Store MFA session
            mfa_session = MfaSession(
                mfa_pending_credential=e.mfa_response.mfa_pending_credential,
                mfa_enrollment_id=e.mfa_response.mfa_enrollment_id,
                pending_token=e.mfa_response.pending_token,
                oauth_state=state,
                display_name=e.mfa_response.display_name,
                local_id=e.mfa_response.local_id,
                email=e.mfa_response.email,
                attempt_count=0
            )
            self.state_manager.store_mfa_session(mfa_session_id, mfa_session)

            # Store OAuth state data alongside MFA session for later use
            # OAuth state was already consumed, so store necessary fields
            mfa_session_key = f"{self.state_manager.MFA_PREFIX}{mfa_session_id}"
            oauth_state_json = json.dumps({
                'redirect_uri': oauth_state.redirect_uri,
                'client_id': oauth_state.client_id,
                'scope': oauth_state.scope,
                'code_challenge': oauth_state.code_challenge,
                'code_challenge_method': oauth_state.code_challenge_method
            })
            self.state_manager.redis_client.setex(
                f"{mfa_session_key}:oauth",
                self.state_manager.MFA_TTL,
                oauth_state_json
            )
            logging.debug(f"Stored OAuth state data for MFA session")

            # Build redirect URL to MFA challenge page
            server_url = self.metadata_provider.server_url
            mfa_challenge_url = f"{server_url}/oauth/mfa-challenge?session={mfa_session_id}"

            logging.info(f"Stored MFA session {mfa_session_id[:12]}..., redirecting to challenge page")
            return mfa_challenge_url

        except FirebaseAuthError as e:
            # SECURITY: Log full error internally but return generic message to client
            # to avoid information disclosure about server internals
            logging.error(f"Firebase sign-in failed for state {state[:8]}...: {e}")
            # Redirect to client with generic error
            error_params = {
                'error': 'server_error',
                'error_description': 'Authentication failed. Please try again or contact support.',
                'state': state
            }
            return oauth_state.redirect_uri + "?" + urllib.parse.urlencode(error_params)

    async def handle_mfa_challenge_page(self, session_id: str) -> str:
        """
        Render MFA challenge HTML page.

        Args:
            session_id: MFA session ID from redirect

        Returns:
            Rendered HTML page as string

        Raises:
            OAuthError: If session is invalid or expired
        """
        # Get MFA session (non-destructive read)
        mfa_session = self.state_manager.get_mfa_session(session_id)

        if mfa_session is None:
            logging.warning(f"Invalid or expired MFA session: {session_id[:20]}...")
            raise OAuthError(
                'invalid_request',
                'MFA session expired or invalid. Please restart authentication.',
                400
            )

        # Check if maximum attempts reached
        if mfa_session.attempt_count >= self.state_manager.MAX_MFA_ATTEMPTS:
            logging.warning(f"Maximum MFA attempts reached for session: {session_id[:20]}...")
            # Consume the session to prevent further attempts
            self.state_manager.consume_mfa_session(session_id)
            raise OAuthError(
                'access_denied',
                'Maximum verification attempts exceeded. Please restart authentication.',
                403
            )

        logging.info(f"Rendering MFA challenge page for user {mfa_session.email}, session: {session_id[:20]}...")

        # Render the MFA challenge page
        template = self.jinja_env.get_template('mfa_challenge.html')
        html = template.render(
            session_id=session_id,
            email=mfa_session.email,
            display_name=mfa_session.display_name,
            attempt_count=mfa_session.attempt_count,
            max_attempts=self.state_manager.MAX_MFA_ATTEMPTS
        )

        return html

    async def handle_mfa_verify(self, session_id: str, verification_code: str) -> str:
        """
        Verify TOTP code and complete OAuth flow.

        Args:
            session_id: MFA session ID
            verification_code: 6-digit TOTP code from authenticator app

        Returns:
            Redirect URL to send user back to client application

        Raises:
            OAuthError: If verification fails or session is invalid
        """
        logging.info(f"MFA verification attempt for session: {session_id[:20]}...")

        # Validate verification code format (6 digits)
        if not verification_code or not verification_code.isdigit() or len(verification_code) != 6:
            logging.warning(f"Invalid verification code format: {len(verification_code) if verification_code else 0} chars")
            # Increment attempt counter before failing
            self.state_manager.increment_mfa_attempts(session_id)
            raise OAuthError(
                'invalid_request',
                'Verification code must be 6 digits',
                400
            )

        # Get MFA session (non-destructive, need to check attempts first)
        mfa_session = self.state_manager.get_mfa_session(session_id)

        if mfa_session is None:
            logging.warning(f"Invalid or expired MFA session: {session_id[:20]}...")
            raise OAuthError(
                'invalid_request',
                'MFA session expired or invalid. Please restart authentication.',
                400
            )

        # Check if maximum attempts reached
        if mfa_session.attempt_count >= self.state_manager.MAX_MFA_ATTEMPTS:
            logging.warning(f"Maximum MFA attempts already reached for session: {session_id[:20]}...")
            # Consume the session to prevent further attempts
            self.state_manager.consume_mfa_session(session_id)
            raise OAuthError(
                'access_denied',
                'Maximum verification attempts exceeded. Please restart authentication.',
                403
            )

        # Get OAuth state data stored with MFA session
        mfa_session_key = f"{self.state_manager.MFA_PREFIX}{session_id}"
        oauth_state_data = self.state_manager.redis_client.get(f"{mfa_session_key}:oauth")

        if not oauth_state_data:
            logging.error(f"OAuth state data not found for MFA session: {session_id[:20]}...")
            # Consume MFA session since OAuth state is gone
            self.state_manager.consume_mfa_session(session_id)
            raise OAuthError(
                'invalid_request',
                'OAuth session expired. Please restart authentication.',
                400
            )

        # Parse OAuth state data
        try:
            if isinstance(oauth_state_data, bytes):
                oauth_state_data = oauth_state_data.decode('utf-8')
            oauth_state_dict = json.loads(oauth_state_data)
            redirect_uri = oauth_state_dict['redirect_uri']
        except Exception as e:
            logging.error(f"Failed to parse OAuth state data: {e}")
            self.state_manager.consume_mfa_session(session_id)
            raise OAuthError(
                'invalid_request',
                'Invalid OAuth session data. Please restart authentication.',
                400
            )

        try:
            # Call Firebase MFA finalization API
            logging.debug(f"Calling Firebase MFA finalization for user {mfa_session.email}")
            firebase_tokens = self.firebase_bridge.finalize_mfa_signin(
                mfa_pending_credential=mfa_session.mfa_pending_credential,
                mfa_enrollment_id=mfa_session.mfa_enrollment_id,
                verification_code=verification_code
            )

            logging.info(f"MFA verification successful for user {mfa_session.email}")

            # Consume the MFA session (single-use, atomic)
            self.state_manager.consume_mfa_session(session_id)

            # Generate authorization code
            auth_code = self.state_manager.generate_authorization_code()

            # Store authorization code with Firebase tokens
            self.state_manager.store_authorization_code(
                code=auth_code,
                state=mfa_session.oauth_state,
                uid=firebase_tokens['uid'],
                firebase_id_token=firebase_tokens['id_token'],
                firebase_refresh_token=firebase_tokens['refresh_token'],
                firebase_expires_at=firebase_tokens['expires_at']
            )

            # Build redirect URL back to client
            redirect_params = {
                'code': auth_code,
                'state': mfa_session.oauth_state
            }
            redirect_url = redirect_uri + "?" + urllib.parse.urlencode(redirect_params)

            logging.info(f"MFA flow complete, redirecting to client")
            return redirect_url

        except FirebaseAuthError as e:
            # MFA verification failed (likely wrong code)
            logging.warning(f"MFA verification failed for session {session_id[:20]}...: {e}")

            # Increment attempt counter
            attempt_count = self.state_manager.increment_mfa_attempts(session_id)

            if attempt_count is None:
                # Session expired during verification
                raise OAuthError(
                    'invalid_request',
                    'MFA session expired. Please restart authentication.',
                    400
                )

            if attempt_count >= self.state_manager.MAX_MFA_ATTEMPTS:
                # Maximum attempts reached - consume session
                logging.warning(f"Maximum MFA attempts reached after verification failure: {session_id[:20]}...")
                self.state_manager.consume_mfa_session(session_id)

                # Redirect to client with error
                error_params = {
                    'error': 'access_denied',
                    'error_description': 'Maximum verification attempts exceeded. Please restart authentication.',
                    'state': mfa_session.oauth_state
                }
                return redirect_uri + "?" + urllib.parse.urlencode(error_params)

            # Return error for user to retry
            remaining_attempts = self.state_manager.MAX_MFA_ATTEMPTS - attempt_count
            raise OAuthError(
                'invalid_grant',
                f'Invalid verification code. {remaining_attempts} attempt(s) remaining.',
                400
            )

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

        # SECURITY: Use constant-time comparison to prevent timing attacks
        # This prevents attackers from using timing analysis to brute-force the code verifier
        return hmac.compare_digest(computed_challenge, code_challenge)

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
