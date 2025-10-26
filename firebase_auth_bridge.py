"""
Firebase Auth Bridge for MCP OAuth

Bridges MCP OAuth 2.1 flow with Firebase Authentication (Google Cloud Identity Platform).
Wraps Firebase's createAuthUri and signInWithIdp endpoints to provide OAuth-compatible
authentication while maintaining Firebase token management.

Based on the simplified Firebase approach from python-limacharlie/oauth_firebase_simple.py
"""

import urllib.parse
import requests
import time
import logging
from typing import Dict, Tuple, Optional
import os


class FirebaseAuthError(Exception):
    """Firebase authentication errors."""
    pass


class FirebaseAuthBridge:
    """
    Bridge between MCP OAuth and Firebase Authentication.

    Uses Firebase's createAuthUri approach where Firebase manages the OAuth
    flow with providers (Google, Microsoft, etc.), eliminating the need for
    managing OAuth credentials directly.

    Flow:
    1. createAuthUri: Get OAuth URL from Firebase
    2. User authenticates via Firebase-managed provider
    3. signInWithIdp: Exchange provider response for Firebase tokens
    """

    # Firebase API key from environment or default
    # In production, this should come from LimaCharlie constants
    FIREBASE_API_KEY = os.getenv(
        "FIREBASE_API_KEY",
        "AIzaSyDFV_-rUEBq5xPQwNqC0pBr_r5aS3UbpKQ"  # LimaCharlie's Firebase project, NOT A SECRET
    )

    # Firebase Auth API endpoints
    _BASE = "https://identitytoolkit.googleapis.com/v1"
    _CREATE_AUTH_URI = f"{_BASE}/accounts:createAuthUri"
    _SIGN_IN_WITH_IDP = f"{_BASE}/accounts:signInWithIdp"
    _REFRESH = "https://securetoken.googleapis.com/v1/token"

    def __init__(self):
        """Initialize Firebase auth bridge."""
        logging.info(f"Firebase Auth Bridge initialized with API key: {self.FIREBASE_API_KEY[:20]}...")

    def create_auth_uri(
        self,
        provider_id: str,
        redirect_uri: str,
        scopes: Tuple[str, ...] = ("openid", "email", "profile")
    ) -> Tuple[str, str]:
        """
        Get OAuth authorization URI from Firebase.

        Firebase's createAuthUri endpoint generates the proper OAuth URL
        for the specified provider, handling all provider-specific details.

        Args:
            provider_id: OAuth provider (e.g., "google.com", "microsoft.com")
            redirect_uri: Where to redirect after auth (must be registered)
            scopes: OAuth scopes to request

        Returns:
            Tuple of (session_id, auth_uri)

        Raises:
            FirebaseAuthError: If request fails
        """
        url = f"{self._CREATE_AUTH_URI}?key={self.FIREBASE_API_KEY}"
        payload = {
            "providerId": provider_id,
            "continueUri": redirect_uri,
            "authFlowType": "CODE_FLOW",
            "oauthScope": " ".join(scopes),
        }

        try:
            logging.debug(f"Creating Firebase auth URI for provider: {provider_id}")
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()

            data = response.json()
            session_id = data.get("sessionId")
            auth_uri = data.get("authUri")

            if not session_id or not auth_uri:
                raise FirebaseAuthError("Missing sessionId or authUri in Firebase response")

            logging.info(f"Created Firebase auth URI, session: {session_id[:20]}...")
            return session_id, auth_uri

        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to create Firebase auth URI: {e}")
            raise FirebaseAuthError(f"Failed to create auth URI: {str(e)}")
        except KeyError as e:
            logging.error(f"Invalid Firebase response format: {e}")
            raise FirebaseAuthError(f"Invalid Firebase response: {str(e)}")

    def sign_in_with_idp(
        self,
        request_uri: str,
        query_string: str,
        session_id: str,
        provider_id: str = "google.com"
    ) -> Dict[str, any]:
        """
        Exchange provider OAuth response for Firebase tokens.

        Args:
            request_uri: The redirect URI used in auth request
            query_string: Full query string from provider redirect
            session_id: Session ID from createAuthUri
            provider_id: OAuth provider ID

        Returns:
            Dictionary with Firebase tokens:
            {
                'id_token': str,        # Firebase ID token (JWT)
                'refresh_token': str,   # Firebase refresh token
                'expires_at': int,      # Token expiration timestamp
                'uid': str,             # Firebase user ID
                'provider': str         # OAuth provider used
            }

        Raises:
            FirebaseAuthError: If exchange fails
        """
        url = f"{self._SIGN_IN_WITH_IDP}?key={self.FIREBASE_API_KEY}"
        payload = {
            "requestUri": request_uri,
            "postBody": query_string,  # Full query from provider redirect
            "sessionId": session_id,
            "returnSecureToken": True,
            "returnIdpCredential": True,
        }

        try:
            logging.debug(f"Signing in with IdP, session: {session_id[:20]}...")
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()

            data = response.json()

            # Extract tokens and user info
            id_token = data.get('idToken')
            refresh_token = data.get('refreshToken')
            expires_in = int(data.get('expiresIn', '3600'))
            firebase_uid = data.get('localId')

            if not id_token or not refresh_token:
                raise FirebaseAuthError("Missing tokens in Firebase signIn response")

            # Calculate expiry timestamp
            expires_at = int(time.time()) + expires_in

            result = {
                'id_token': id_token,
                'refresh_token': refresh_token,
                'expires_at': expires_at,
                'uid': firebase_uid,
                'provider': provider_id,
                'api_key': self.FIREBASE_API_KEY  # For SDK usage
            }

            logging.info(f"Successfully signed in via Firebase, UID: {firebase_uid}")
            return result

        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to sign in with IdP: {e}")
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_data = e.response.json()
                    error_msg = error_data.get('error', {}).get('message', str(e))
                    logging.error(f"Firebase error details: {error_msg}")
                    raise FirebaseAuthError(f"Firebase sign-in failed: {error_msg}")
                except:
                    pass
            raise FirebaseAuthError(f"Failed to sign in with IdP: {str(e)}")
        except KeyError as e:
            logging.error(f"Invalid Firebase signIn response format: {e}")
            raise FirebaseAuthError(f"Invalid Firebase response: {str(e)}")

    def refresh_id_token(self, refresh_token: str) -> Tuple[str, int]:
        """
        Refresh an expired Firebase ID token.

        Args:
            refresh_token: Firebase refresh token

        Returns:
            Tuple of (new_id_token, expires_at_timestamp)

        Raises:
            FirebaseAuthError: If refresh fails
        """
        url = f"{self._REFRESH}?key={self.FIREBASE_API_KEY}"
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }

        try:
            logging.debug("Refreshing Firebase ID token")
            response = requests.post(url, data=payload, timeout=10)
            response.raise_for_status()

            data = response.json()
            new_id_token = data.get("id_token")
            expires_in = int(data.get("expires_in", "3600"))

            if not new_id_token:
                raise FirebaseAuthError("Missing id_token in refresh response")

            # Calculate expiration with buffer
            expires_at = int(time.time()) + expires_in - 60  # 60 second buffer

            logging.info("Successfully refreshed Firebase ID token")
            return new_id_token, expires_at

        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to refresh Firebase token: {e}")
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_data = e.response.json()
                    error_msg = error_data.get('error', {}).get('message', str(e))
                    logging.error(f"Firebase refresh error: {error_msg}")
                    raise FirebaseAuthError(f"Token refresh failed: {error_msg}")
                except:
                    pass
            raise FirebaseAuthError(f"Failed to refresh token: {str(e)}")

    def validate_provider_callback(self, callback_path: str) -> str:
        """
        Validate and extract query string from provider callback.

        Args:
            callback_path: Full callback path with query parameters

        Returns:
            Query string to pass to signInWithIdp

        Raises:
            FirebaseAuthError: If callback contains errors
        """
        if not callback_path:
            raise FirebaseAuthError("Empty callback path")

        # Parse the URL to get query string
        parsed = urllib.parse.urlparse(callback_path if callback_path.startswith('http') else f"http://localhost{callback_path}")
        query_string = parsed.query or parsed.fragment

        if not query_string:
            raise FirebaseAuthError("No query parameters in callback")

        # Check for OAuth errors in query
        params = urllib.parse.parse_qs(query_string)
        if 'error' in params:
            error = params['error'][0]
            error_desc = params.get('error_description', ['Unknown error'])[0]
            logging.error(f"OAuth error in callback: {error} - {error_desc}")
            raise FirebaseAuthError(f"OAuth error: {error} - {error_desc}")

        logging.debug(f"Validated provider callback with query params: {list(params.keys())}")
        return query_string

    def get_user_info_from_token(self, id_token: str) -> Optional[Dict[str, any]]:
        """
        Decode Firebase ID token to get user information.

        Note: This is a simple implementation. For production,
        should verify token signature using Firebase Admin SDK.

        Args:
            id_token: Firebase ID token (JWT)

        Returns:
            User info dict if successful, None otherwise
        """
        try:
            # Split JWT and decode payload
            parts = id_token.split('.')
            if len(parts) != 3:
                return None

            # Base64 decode payload (add padding if needed)
            import base64
            import json

            payload = parts[1]
            # Add padding
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding

            decoded = base64.urlsafe_b64decode(payload)
            user_info = json.loads(decoded)

            logging.debug(f"Decoded user info from token: {user_info.get('user_id', 'unknown')}")
            return user_info

        except Exception as e:
            logging.error(f"Failed to decode ID token: {e}")
            return None


# Singleton instance for convenience
_firebase_bridge = None


def get_firebase_bridge() -> FirebaseAuthBridge:
    """
    Get singleton Firebase auth bridge instance.

    Returns:
        FirebaseAuthBridge instance
    """
    global _firebase_bridge
    if _firebase_bridge is None:
        _firebase_bridge = FirebaseAuthBridge()
    return _firebase_bridge
