"""
OAuth Token Manager

Handles token validation, refresh, and lifecycle management for MCP OAuth.
Bridges MCP access tokens with Firebase ID tokens and manages automatic refresh.
"""

import logging
import time
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass

from oauth_state_manager import OAuthStateManager, AccessTokenData
from firebase_auth_bridge import FirebaseAuthBridge, FirebaseAuthError


@dataclass
class TokenValidationResult:
    """Result of token validation."""
    valid: bool
    uid: Optional[str] = None
    firebase_id_token: Optional[str] = None
    firebase_refresh_token: Optional[str] = None
    scope: Optional[str] = None
    error: Optional[str] = None
    refreshed: bool = False  # True if token was auto-refreshed


class OAuthTokenManager:
    """
    Manages OAuth token validation and refresh for MCP.

    Responsibilities:
    - Validate MCP access tokens against Redis
    - Auto-refresh expired Firebase tokens
    - Provide token info for request authentication
    - Handle token revocation
    """

    def __init__(
        self,
        state_manager: Optional[OAuthStateManager] = None,
        firebase_bridge: Optional[FirebaseAuthBridge] = None
    ):
        """
        Initialize token manager.

        Args:
            state_manager: OAuth state manager (creates new if None)
            firebase_bridge: Firebase auth bridge (creates new if None)
        """
        self.state_manager = state_manager or OAuthStateManager()
        self.firebase_bridge = firebase_bridge or FirebaseAuthBridge()
        logging.info("OAuth Token Manager initialized")

    def validate_access_token(
        self,
        access_token: str,
        auto_refresh: bool = True
    ) -> TokenValidationResult:
        """
        Validate MCP access token and optionally refresh Firebase tokens.

        Args:
            access_token: MCP access token to validate
            auto_refresh: If True, automatically refresh expired Firebase tokens

        Returns:
            TokenValidationResult with validation status and token data
        """
        # Look up token in Redis
        token_data = self.state_manager.get_access_token_data(access_token)

        if not token_data:
            logging.debug(f"Access token not found or expired: {access_token[:10]}...")
            return TokenValidationResult(
                valid=False,
                error="Invalid or expired access token"
            )

        # Check if Firebase token needs refresh
        firebase_expires_in = token_data.firebase_expires_at - int(time.time())
        needs_refresh = firebase_expires_in < 300  # Refresh if < 5 minutes remaining

        if needs_refresh and auto_refresh and token_data.firebase_refresh_token:
            logging.info(f"Firebase token expiring soon ({firebase_expires_in}s), refreshing...")
            try:
                # Refresh Firebase token
                new_id_token, new_expires_at = self.firebase_bridge.refresh_id_token(
                    token_data.firebase_refresh_token
                )

                # Update token data in Redis
                success = self.state_manager.update_access_token_firebase_tokens(
                    access_token,
                    new_id_token,
                    new_expires_at
                )

                if success:
                    logging.info(f"Successfully refreshed Firebase token for access token {access_token[:10]}...")
                    token_data.firebase_id_token = new_id_token
                    token_data.firebase_expires_at = new_expires_at

                    return TokenValidationResult(
                        valid=True,
                        uid=token_data.uid,
                        firebase_id_token=new_id_token,
                        firebase_refresh_token=token_data.firebase_refresh_token,
                        scope=token_data.scope,
                        refreshed=True
                    )
                else:
                    logging.warning(f"Failed to update Redis with refreshed token")

            except FirebaseAuthError as e:
                logging.error(f"Failed to refresh Firebase token: {e}")
                # Continue with existing token if refresh fails
                # Token might still be valid for a short time

        # Return validation result
        return TokenValidationResult(
            valid=True,
            uid=token_data.uid,
            firebase_id_token=token_data.firebase_id_token,
            firebase_refresh_token=token_data.firebase_refresh_token,
            scope=token_data.scope,
            refreshed=False
        )

    def refresh_access_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """
        Issue a new access token using a refresh token.

        This implements the OAuth 2.1 refresh token grant type.

        Args:
            refresh_token: MCP refresh token

        Returns:
            Token response dict with new access_token, or None if invalid
        """
        # Look up refresh token
        refresh_data = self.state_manager.get_refresh_token_data(refresh_token)

        if not refresh_data:
            logging.warning(f"Refresh token not found: {refresh_token[:10]}...")
            return None

        uid = refresh_data.get('uid')
        firebase_refresh_token = refresh_data.get('firebase_refresh_token')
        scope = refresh_data.get('scope', '')
        old_access_token = refresh_data.get('access_token')

        if not uid or not firebase_refresh_token:
            logging.error(f"Invalid refresh token data")
            return None

        try:
            # Refresh Firebase token first
            new_firebase_id_token, new_firebase_expires_at = self.firebase_bridge.refresh_id_token(
                firebase_refresh_token
            )

            # Generate new MCP access token
            new_access_token = self.state_manager.generate_access_token()

            # Store new access token with refreshed Firebase tokens
            self.state_manager.store_access_token(
                access_token=new_access_token,
                uid=uid,
                firebase_id_token=new_firebase_id_token,
                firebase_refresh_token=firebase_refresh_token,
                firebase_expires_at=new_firebase_expires_at,
                scope=scope
            )

            # Revoke old access token (optional - could keep for grace period)
            if old_access_token:
                self.state_manager.revoke_access_token(old_access_token)

            # Calculate expires_in
            expires_in = OAuthStateManager.TOKEN_TTL

            logging.info(f"Issued new access token via refresh for UID: {uid}")

            return {
                "access_token": new_access_token,
                "token_type": "Bearer",
                "expires_in": expires_in,
                "refresh_token": refresh_token,  # Can rotate this for extra security
                "scope": scope
            }

        except FirebaseAuthError as e:
            logging.error(f"Failed to refresh Firebase token for refresh grant: {e}")
            return None

    def revoke_token(self, token: str, token_type_hint: Optional[str] = None) -> bool:
        """
        Revoke an access or refresh token.

        Args:
            token: Token to revoke
            token_type_hint: "access_token" or "refresh_token" (optional)

        Returns:
            True if revoked successfully
        """
        revoked = False

        # Try to revoke as access token
        if token_type_hint != "refresh_token":
            if self.state_manager.revoke_access_token(token):
                logging.info(f"Revoked access token: {token[:10]}...")
                revoked = True

        # Try to revoke as refresh token
        if token_type_hint != "access_token":
            if self.state_manager.revoke_refresh_token(token):
                logging.info(f"Revoked refresh token: {token[:10]}...")
                revoked = True

        if not revoked:
            logging.warning(f"Token not found for revocation: {token[:10]}...")

        return revoked

    def introspect_token(self, token: str) -> Dict[str, Any]:
        """
        Get token metadata (OAuth 2.0 Token Introspection).

        Args:
            token: Token to introspect

        Returns:
            Token introspection response
        """
        token_data = self.state_manager.get_access_token_data(token)

        if not token_data:
            return {
                "active": False
            }

        # Check expiration
        is_active = token_data.expires_at > int(time.time())

        result = {
            "active": is_active,
            "scope": token_data.scope,
            "client_id": "mcp",  # We don't track client_id per token currently
            "token_type": "Bearer",
            "exp": token_data.expires_at,
            "iat": token_data.created_at,
            "sub": token_data.uid,  # Firebase UID as subject
        }

        return result

    def get_token_info_for_request(self, access_token: str) -> Optional[Dict[str, Any]]:
        """
        Get token information needed for authenticating LimaCharlie API requests.

        This is the main method used by the request middleware to get
        authentication context from an MCP access token.

        Args:
            access_token: MCP access token from Authorization header

        Returns:
            Dict with uid, firebase_id_token, and mode, or None if invalid
        """
        validation = self.validate_access_token(access_token, auto_refresh=True)

        if not validation.valid:
            return None

        return {
            "uid": validation.uid,
            "firebase_id_token": validation.firebase_id_token,
            "firebase_refresh_token": validation.firebase_refresh_token,
            "mode": "oauth",  # Always OAuth mode for MCP tokens
            "scope": validation.scope,
            "refreshed": validation.refreshed
        }

    def create_token_response(
        self,
        uid: str,
        firebase_id_token: str,
        firebase_refresh_token: str,
        firebase_expires_at: int,
        scope: str
    ) -> Dict[str, Any]:
        """
        Create OAuth token response with new MCP tokens.

        Called after successful authorization to issue tokens.

        Args:
            uid: Firebase user ID
            firebase_id_token: Firebase ID token
            firebase_refresh_token: Firebase refresh token
            firebase_expires_at: Firebase token expiration
            scope: Granted scopes

        Returns:
            OAuth token response dict
        """
        # Generate MCP tokens
        access_token = self.state_manager.generate_access_token()
        refresh_token = self.state_manager.generate_refresh_token()

        # Store access token
        self.state_manager.store_access_token(
            access_token=access_token,
            uid=uid,
            firebase_id_token=firebase_id_token,
            firebase_refresh_token=firebase_refresh_token,
            firebase_expires_at=firebase_expires_at,
            scope=scope
        )

        # Store refresh token
        self.state_manager.store_refresh_token(
            refresh_token=refresh_token,
            access_token=access_token,
            uid=uid,
            firebase_refresh_token=firebase_refresh_token,
            scope=scope
        )

        # Build OAuth 2.0 token response
        response = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": OAuthStateManager.TOKEN_TTL,
            "refresh_token": refresh_token,
            "scope": scope
        }

        logging.info(f"Created token response for UID: {uid}")
        return response


# Singleton instance for convenience
_token_manager = None


def get_token_manager() -> OAuthTokenManager:
    """
    Get singleton token manager instance.

    Returns:
        OAuthTokenManager instance
    """
    global _token_manager
    if _token_manager is None:
        _token_manager = OAuthTokenManager()
    return _token_manager
