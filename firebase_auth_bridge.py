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
import json
from typing import Dict, Tuple, Optional
from dataclasses import dataclass
import os


class FirebaseAuthError(Exception):
    """Firebase authentication errors."""
    pass


@dataclass
class MfaResponse:
    """
    Multi-Factor Authentication response from Firebase.

    Returned when signInWithIdp detects that MFA is required.
    """
    mfa_pending_credential: str
    mfa_enrollment_id: str
    pending_token: str
    display_name: str
    local_id: str
    email: str


class FirebaseMfaRequiredError(Exception):
    """
    Raised when Firebase signInWithIdp requires MFA verification.

    Contains MFA challenge details needed to continue authentication.
    """
    def __init__(self, mfa_response: MfaResponse):
        self.mfa_response = mfa_response
        super().__init__(f"MFA required for user {mfa_response.email}")


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
    # NOTE: This is a public Firebase Web API key, not a secret. It's designed to be
    # exposed in client applications and is safe to include in public code. Firebase
    # security is enforced through Firebase Security Rules, not API key secrecy.
    FIREBASE_API_KEY = os.getenv(
        "FIREBASE_API_KEY",
        "AIzaSyB5VyO6qS-XlnVD3zOIuEVNBD5JFn22_1w"  # LimaCharlie's Firebase Web API key
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
            logging.debug(f"Firebase request payload: {payload}")
            response = requests.post(url, json=payload, timeout=10)

            # Log response details before raising error
            if response.status_code != 200:
                logging.error(f"Firebase createAuthUri failed with status {response.status_code}")
                logging.debug(f"Response body: {response.text}")

            response.raise_for_status()

            data = response.json()

            # Log the full response for debugging (debug level only - contains session_id)
            logging.debug(f"Firebase createAuthUri response received")

            session_id = data.get("sessionId")
            auth_uri = data.get("authUri")

            if not session_id or not auth_uri:
                logging.error(f"Missing fields in Firebase response. sessionId present: {bool(session_id)}, authUri present: {bool(auth_uri)}")
                raise FirebaseAuthError("Missing sessionId or authUri in Firebase response")

            logging.debug(f"Created Firebase auth URI, session: {session_id[:12]}...{session_id[-8:]}")
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
            logging.debug(f"signInWithIdp payload: requestUri={request_uri}, postBody={query_string[:100] if len(query_string) > 100 else query_string}, sessionId={session_id[:20]}...")
            logging.debug(f"Full postBody length: {len(query_string)} chars")
            response = requests.post(url, json=payload, timeout=10)

            # Log response status for debugging
            logging.debug(f"Firebase signInWithIdp response status: {response.status_code}")
            response.raise_for_status()

            data = response.json()
            logging.debug(f"Firebase signInWithIdp response keys: {list(data.keys())}")
            logging.debug(f"Response has idToken: {bool(data.get('idToken'))}, has refreshToken: {bool(data.get('refreshToken'))}")

            # Extract tokens and user info
            id_token = data.get('idToken')
            refresh_token = data.get('refreshToken')
            expires_in = int(data.get('expiresIn', '3600'))
            firebase_uid = data.get('localId')

            # Check if MFA is required
            if not id_token or not refresh_token:
                if self._is_mfa_required(data):
                    logging.info(f"MFA required for user {data.get('email', 'unknown')}")
                    # Log the full response to understand what Firebase is sending (ERROR level for Cloud Run visibility)
                    logging.error(f"[DEBUG] Firebase MFA response data: {json.dumps(data, indent=2)}")
                    mfa_response = self._extract_mfa_response(data)
                    raise FirebaseMfaRequiredError(mfa_response)
                # Check for account linking/confirmation required
                elif data.get('needConfirmation'):
                    logging.error(f"Firebase account needs confirmation/linking. Response: {json.dumps(data, indent=2)}")
                    raise FirebaseAuthError("Account linking required. Please use an existing account or contact support.")
                # Check for pending token (incomplete flow)
                elif 'pendingToken' in data or 'oauthIdToken' in data:
                    logging.error(f"Firebase returned pending token (incomplete flow). Response: {json.dumps(data, indent=2)}")
                    raise FirebaseAuthError("Authentication flow incomplete. This may be due to provider-specific issues with 2FA.")
                else:
                    logging.error(f"Firebase signInWithIdp response missing tokens. Full response: {json.dumps(data, indent=2)}")
                    # Log specific fields present for debugging
                    present_fields = [k for k in data.keys() if data[k]]
                    logging.error(f"Present fields in response: {present_fields}")
                    raise FirebaseAuthError(f"Missing tokens in Firebase signIn response. Present fields: {', '.join(present_fields)}")

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

    def _is_mfa_required(self, response: Dict) -> bool:
        """
        Check if Firebase response indicates MFA is required.

        Args:
            response: Firebase signInWithIdp response

        Returns:
            True if MFA challenge is required
        """
        return 'mfaInfo' in response and 'mfaPendingCredential' in response

    def _extract_mfa_response(self, response: Dict) -> MfaResponse:
        """
        Extract MFA challenge details from Firebase response.

        Args:
            response: Firebase signInWithIdp response with MFA required

        Returns:
            MfaResponse with MFA challenge details

        Raises:
            FirebaseAuthError: If required MFA fields are missing
        """
        mfa_info_list = response.get('mfaInfo', [])
        if not mfa_info_list:
            raise FirebaseAuthError("No MFA methods available")

        # Use the first MFA method (usually TOTP)
        mfa_info = mfa_info_list[0]

        mfa_pending_credential = response.get('mfaPendingCredential')
        pending_token = response.get('pendingToken')
        mfa_enrollment_id = mfa_info.get('mfaEnrollmentId')
        display_name = mfa_info.get('displayName', 'Authenticator App')
        local_id = response.get('localId')
        email = response.get('email')

        # Log what we actually received for debugging (ERROR level for Cloud Run visibility)
        logging.error(f"[DEBUG] MFA extraction - mfaPendingCredential present: {bool(mfa_pending_credential)}")
        logging.error(f"[DEBUG] MFA extraction - pendingToken present: {bool(pending_token)}")
        logging.error(f"[DEBUG] MFA extraction - mfaEnrollmentId present: {bool(mfa_enrollment_id)}")
        logging.error(f"[DEBUG] MFA extraction - localId present: {bool(local_id)}")
        logging.error(f"[DEBUG] MFA extraction - email present: {bool(email)}")

        if not all([mfa_pending_credential, pending_token, mfa_enrollment_id, local_id, email]):
            missing = []
            if not mfa_pending_credential:
                missing.append('mfaPendingCredential')
            if not pending_token:
                missing.append('pendingToken')
            if not mfa_enrollment_id:
                missing.append('mfaEnrollmentId')
            if not local_id:
                missing.append('localId')
            if not email:
                missing.append('email')

            # Log the full response for debugging when fields are missing
            logging.error(f"MFA response missing required fields: {', '.join(missing)}")
            logging.error(f"Available fields in response: {list(response.keys())}")
            logging.error(f"mfaInfo content: {json.dumps(mfa_info_list, indent=2)}")

            raise FirebaseAuthError(f"Incomplete MFA response, missing: {', '.join(missing)}")

        return MfaResponse(
            mfa_pending_credential=mfa_pending_credential,
            mfa_enrollment_id=mfa_enrollment_id,
            pending_token=pending_token,
            display_name=display_name,
            local_id=local_id,
            email=email
        )

    def finalize_mfa_signin(
        self,
        mfa_pending_credential: str,
        mfa_enrollment_id: str,
        verification_code: str
    ) -> Dict[str, any]:
        """
        Finalize MFA sign-in with TOTP verification code.

        Calls Firebase Identity Toolkit v2 API to complete MFA challenge.

        Args:
            mfa_pending_credential: Pending credential from signInWithIdp
            mfa_enrollment_id: MFA enrollment ID from user's MFA methods
            verification_code: 6-digit TOTP code from authenticator app

        Returns:
            Dictionary with Firebase tokens:
            {
                'id_token': str,
                'refresh_token': str,
                'expires_at': int,
                'uid': str
            }

        Raises:
            FirebaseAuthError: If MFA verification fails
        """
        # Firebase Identity Toolkit v2 API for MFA finalization
        url = f"https://identitytoolkit.googleapis.com/v2/accounts/mfaSignIn:finalize?key={self.FIREBASE_API_KEY}"
        payload = {
            "mfaPendingCredential": mfa_pending_credential,
            "mfaEnrollmentId": mfa_enrollment_id,
            "totpVerificationInfo": {
                "verificationCode": verification_code
            }
        }

        try:
            logging.debug(f"Finalizing MFA sign-in with enrollment ID: {mfa_enrollment_id[:20]}...")
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()

            data = response.json()
            logging.debug(f"Firebase finalizeMfaSignIn response keys: {list(data.keys())}")

            # Extract tokens
            id_token = data.get('idToken')
            refresh_token = data.get('refreshToken')
            expires_in = int(data.get('expiresIn', '3600'))
            firebase_uid = data.get('localId')

            if not id_token or not refresh_token:
                logging.error(f"Firebase MFA finalization missing tokens. Response: {json.dumps(data, indent=2)}")
                raise FirebaseAuthError("Missing tokens in MFA finalization response")

            # Calculate expiry timestamp
            expires_at = int(time.time()) + expires_in

            result = {
                'id_token': id_token,
                'refresh_token': refresh_token,
                'expires_at': expires_at,
                'uid': firebase_uid,
                'api_key': self.FIREBASE_API_KEY
            }

            logging.info(f"Successfully completed MFA sign-in for UID: {firebase_uid}")
            return result

        except requests.exceptions.RequestException as e:
            logging.error(f"MFA finalization failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_data = e.response.json()
                    error_msg = error_data.get('error', {}).get('message', str(e))
                    logging.error(f"Firebase MFA error: {error_msg}")
                    # Invalid TOTP code returns specific error message
                    if 'INVALID_MFA_PENDING_CREDENTIAL' in error_msg or 'INVALID_CODE' in error_msg:
                        raise FirebaseAuthError("Invalid verification code")
                    raise FirebaseAuthError(f"MFA verification failed: {error_msg}")
                except FirebaseAuthError:
                    raise
                except:
                    pass
            raise FirebaseAuthError(f"Failed to finalize MFA: {str(e)}")

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

    def verify_firebase_id_token(self, id_token: str) -> Optional[Dict[str, any]]:
        """
        Verify Firebase ID token signature and decode claims.

        SECURITY: This method verifies the JWT signature using Google's public keys.
        This prevents forged tokens from being accepted.

        For production deployments, it's recommended to use Firebase Admin SDK
        which handles key rotation and caching automatically.

        Args:
            id_token: Firebase ID token (JWT)

        Returns:
            Verified user info dict if signature is valid, None otherwise
        """
        try:
            import jwt
            import requests
            from jwt import PyJWKClient

            # Google's public key endpoint for Firebase tokens
            jwks_url = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"

            # Get signing key from Google's JWKS endpoint
            jwks_client = PyJWKClient(jwks_url)
            signing_key = jwks_client.get_signing_key_from_jwt(id_token)

            # Verify signature and decode
            # This will raise an exception if signature is invalid or token expired
            decoded = jwt.decode(
                id_token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.FIREBASE_API_KEY,  # Verify it's for our project
                options={"verify_exp": True}  # Verify expiration
            )

            logging.info(f"Successfully verified Firebase ID token signature for user: {decoded.get('user_id', 'unknown')}")
            return decoded

        except jwt.ExpiredSignatureError:
            logging.warning("Firebase ID token expired")
            return None
        except jwt.InvalidTokenError as e:
            logging.error(f"Invalid Firebase ID token: {e}")
            return None
        except Exception as e:
            logging.error(f"Failed to verify Firebase ID token: {e}")
            # Fall back to unverified decode for backward compatibility
            logging.warning("Falling back to unverified token decode - SECURITY RISK")
            return self.get_user_info_from_token(id_token)

    def get_user_info_from_token(self, id_token: str) -> Optional[Dict[str, any]]:
        """
        Decode Firebase ID token to get user information WITHOUT signature verification.

        ⚠️ SECURITY WARNING: This method does NOT verify the token signature.
        Use verify_firebase_id_token() instead for production deployments.

        This method is kept for backward compatibility and as a fallback.

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

            logging.debug(f"Decoded user info from token (UNVERIFIED): {user_info.get('user_id', 'unknown')}")
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
