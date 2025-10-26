"""
OAuth State Manager

Manages OAuth state, authorization codes, and token mappings using Redis.
Provides secure, multi-tenant state management for MCP OAuth 2.1 flow.
"""

import redis
import json
import secrets
import time
import os
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict


@dataclass
class OAuth State:
    """OAuth authorization request state."""
    state: str
    code_challenge: str
    code_challenge_method: str
    redirect_uri: str
    client_id: str
    scope: str
    resource: str
    created_at: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OAuthState":
        return cls(**data)


@dataclass
class AuthorizationCode:
    """Authorization code with associated data."""
    code: str
    state: str
    uid: str
    firebase_id_token: str
    firebase_refresh_token: str
    firebase_expires_at: int
    created_at: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthorizationCode":
        return cls(**data)


@dataclass
class AccessTokenData:
    """Access token with Firebase token mapping."""
    access_token: str
    uid: str
    firebase_id_token: str
    firebase_refresh_token: str
    firebase_expires_at: int
    scope: str
    created_at: int
    expires_at: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AccessTokenData":
        return cls(**data)


@dataclass
class ClientRegistration:
    """Dynamic client registration data."""
    client_id: str
    client_name: str
    redirect_uris: list[str]
    created_at: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ClientRegistration":
        # Convert redirect_uris back to list if it was serialized
        if isinstance(data.get('redirect_uris'), str):
            data['redirect_uris'] = json.loads(data['redirect_uris'])
        return cls(**data)


class OAuthStateManager:
    """
    Manages OAuth state and token storage in Redis.

    Provides multi-tenant secure storage for:
    - OAuth authorization request state (CSRF protection)
    - Authorization codes (temporary, single-use)
    - Access tokens mapped to Firebase tokens
    - Client registrations
    """

    # Key prefixes for Redis
    STATE_PREFIX = "oauth:state:"
    CODE_PREFIX = "oauth:code:"
    TOKEN_PREFIX = "oauth:token:"
    CLIENT_PREFIX = "oauth:client:"
    REFRESH_PREFIX = "oauth:refresh:"

    # TTL values (seconds)
    STATE_TTL = 600  # 10 minutes
    CODE_TTL = 300  # 5 minutes
    TOKEN_TTL = 3600  # 1 hour (access token)
    REFRESH_TTL = 2592000  # 30 days (refresh token)

    def __init__(self, redis_url: Optional[str] = None):
        """
        Initialize OAuth state manager.

        Args:
            redis_url: Redis connection URL (default: from REDIS_URL env var)
        """
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379")
        self.redis_client = redis.from_url(
            self.redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_keepalive=True
        )
        logging.info(f"OAuth State Manager initialized with Redis at {self.redis_url}")

    def ping(self) -> bool:
        """
        Test Redis connection.

        Returns:
            True if Redis is reachable
        """
        try:
            return self.redis_client.ping()
        except Exception as e:
            logging.error(f"Redis ping failed: {e}")
            return False

    # ===== OAuth State Management =====

    def generate_state(self) -> str:
        """
        Generate secure random state parameter.

        Returns:
            Base64-encoded random state (32 bytes = 43 chars)
        """
        return secrets.token_urlsafe(32)

    def store_oauth_state(
        self,
        state: str,
        code_challenge: str,
        code_challenge_method: str,
        redirect_uri: str,
        client_id: str,
        scope: str,
        resource: str
    ) -> None:
        """
        Store OAuth authorization request state.

        Args:
            state: CSRF state parameter
            code_challenge: PKCE code challenge
            code_challenge_method: PKCE method (must be S256)
            redirect_uri: Client redirect URI
            client_id: OAuth client ID
            scope: Requested scopes
            resource: Target resource URI
        """
        oauth_state = OAuthState(
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            redirect_uri=redirect_uri,
            client_id=client_id,
            scope=scope,
            resource=resource,
            created_at=int(time.time())
        )

        key = f"{self.STATE_PREFIX}{state}"
        self.redis_client.setex(
            key,
            self.STATE_TTL,
            json.dumps(oauth_state.to_dict())
        )
        logging.debug(f"Stored OAuth state: {state[:10]}... for client {client_id}")

    def get_oauth_state(self, state: str) -> Optional[OAuthState]:
        """
        Retrieve and validate OAuth state.

        Args:
            state: State parameter to look up

        Returns:
            OAuthState if found and valid, None otherwise
        """
        key = f"{self.STATE_PREFIX}{state}"
        data = self.redis_client.get(key)

        if not data:
            logging.warning(f"OAuth state not found: {state[:10]}...")
            return None

        try:
            oauth_state = OAuthState.from_dict(json.loads(data))
            logging.debug(f"Retrieved OAuth state: {state[:10]}...")
            return oauth_state
        except Exception as e:
            logging.error(f"Failed to deserialize OAuth state: {e}")
            return None

    def consume_oauth_state(self, state: str) -> Optional[OAuthState]:
        """
        Retrieve and delete OAuth state (single-use).

        Args:
            state: State parameter to consume

        Returns:
            OAuthState if found, None otherwise
        """
        oauth_state = self.get_oauth_state(state)
        if oauth_state:
            key = f"{self.STATE_PREFIX}{state}"
            self.redis_client.delete(key)
            logging.debug(f"Consumed OAuth state: {state[:10]}...")
        return oauth_state

    # ===== Authorization Code Management =====

    def generate_authorization_code(self) -> str:
        """
        Generate secure random authorization code.

        Returns:
            Base64-encoded random code (32 bytes)
        """
        return secrets.token_urlsafe(32)

    def store_authorization_code(
        self,
        code: str,
        state: str,
        uid: str,
        firebase_id_token: str,
        firebase_refresh_token: str,
        firebase_expires_at: int
    ) -> None:
        """
        Store authorization code with Firebase token mapping.

        Args:
            code: Authorization code
            state: Associated OAuth state
            uid: Firebase UID
            firebase_id_token: Firebase ID token
            firebase_refresh_token: Firebase refresh token
            firebase_expires_at: Firebase token expiration timestamp
        """
        auth_code = AuthorizationCode(
            code=code,
            state=state,
            uid=uid,
            firebase_id_token=firebase_id_token,
            firebase_refresh_token=firebase_refresh_token,
            firebase_expires_at=firebase_expires_at,
            created_at=int(time.time())
        )

        key = f"{self.CODE_PREFIX}{code}"
        self.redis_client.setex(
            key,
            self.CODE_TTL,
            json.dumps(auth_code.to_dict())
        )
        logging.debug(f"Stored authorization code: {code[:10]}... for UID {uid}")

    def consume_authorization_code(self, code: str) -> Optional[AuthorizationCode]:
        """
        Retrieve and delete authorization code (single-use).

        Args:
            code: Authorization code to consume

        Returns:
            AuthorizationCode if found, None otherwise
        """
        key = f"{self.CODE_PREFIX}{code}"
        data = self.redis_client.get(key)

        if not data:
            logging.warning(f"Authorization code not found: {code[:10]}...")
            return None

        try:
            auth_code = AuthorizationCode.from_dict(json.loads(data))
            # Delete immediately (single-use)
            self.redis_client.delete(key)
            logging.debug(f"Consumed authorization code: {code[:10]}...")
            return auth_code
        except Exception as e:
            logging.error(f"Failed to deserialize authorization code: {e}")
            return None

    # ===== Access Token Management =====

    def generate_access_token(self) -> str:
        """
        Generate secure random access token.

        Returns:
            Base64-encoded random token (32 bytes)
        """
        return secrets.token_urlsafe(32)

    def generate_refresh_token(self) -> str:
        """
        Generate secure random refresh token.

        Returns:
            Base64-encoded random token (32 bytes)
        """
        return secrets.token_urlsafe(32)

    def store_access_token(
        self,
        access_token: str,
        uid: str,
        firebase_id_token: str,
        firebase_refresh_token: str,
        firebase_expires_at: int,
        scope: str,
        ttl: int = TOKEN_TTL
    ) -> None:
        """
        Store access token with Firebase token mapping.

        Args:
            access_token: MCP access token
            uid: Firebase UID
            firebase_id_token: Firebase ID token
            firebase_refresh_token: Firebase refresh token
            firebase_expires_at: Firebase token expiration
            scope: Granted scopes
            ttl: Access token TTL in seconds
        """
        token_data = AccessTokenData(
            access_token=access_token,
            uid=uid,
            firebase_id_token=firebase_id_token,
            firebase_refresh_token=firebase_refresh_token,
            firebase_expires_at=firebase_expires_at,
            scope=scope,
            created_at=int(time.time()),
            expires_at=int(time.time()) + ttl
        )

        key = f"{self.TOKEN_PREFIX}{access_token}"
        self.redis_client.setex(
            key,
            ttl,
            json.dumps(token_data.to_dict())
        )
        logging.debug(f"Stored access token: {access_token[:10]}... for UID {uid}")

    def get_access_token_data(self, access_token: str) -> Optional[AccessTokenData]:
        """
        Retrieve access token data.

        Args:
            access_token: MCP access token

        Returns:
            AccessTokenData if found and valid, None otherwise
        """
        key = f"{self.TOKEN_PREFIX}{access_token}"
        data = self.redis_client.get(key)

        if not data:
            logging.debug(f"Access token not found: {access_token[:10]}...")
            return None

        try:
            token_data = AccessTokenData.from_dict(json.loads(data))

            # Check if expired
            if token_data.expires_at < int(time.time()):
                logging.warning(f"Access token expired: {access_token[:10]}...")
                return None

            return token_data
        except Exception as e:
            logging.error(f"Failed to deserialize access token: {e}")
            return None

    def update_access_token_firebase_tokens(
        self,
        access_token: str,
        firebase_id_token: str,
        firebase_expires_at: int
    ) -> bool:
        """
        Update Firebase tokens for an existing access token (after refresh).

        Args:
            access_token: MCP access token
            firebase_id_token: New Firebase ID token
            firebase_expires_at: New expiration timestamp

        Returns:
            True if updated successfully
        """
        token_data = self.get_access_token_data(access_token)
        if not token_data:
            return False

        # Update Firebase tokens
        token_data.firebase_id_token = firebase_id_token
        token_data.firebase_expires_at = firebase_expires_at

        key = f"{self.TOKEN_PREFIX}{access_token}"
        ttl = token_data.expires_at - int(time.time())
        if ttl <= 0:
            return False

        self.redis_client.setex(
            key,
            ttl,
            json.dumps(token_data.to_dict())
        )
        logging.debug(f"Updated Firebase tokens for access token: {access_token[:10]}...")
        return True

    def revoke_access_token(self, access_token: str) -> bool:
        """
        Revoke (delete) an access token.

        Args:
            access_token: MCP access token to revoke

        Returns:
            True if revoked
        """
        key = f"{self.TOKEN_PREFIX}{access_token}"
        deleted = self.redis_client.delete(key)
        if deleted:
            logging.info(f"Revoked access token: {access_token[:10]}...")
        return bool(deleted)

    # ===== Refresh Token Management =====

    def store_refresh_token(
        self,
        refresh_token: str,
        access_token: str,
        uid: str,
        firebase_refresh_token: str,
        scope: str
    ) -> None:
        """
        Store refresh token mapping to access token and Firebase refresh token.

        Args:
            refresh_token: MCP refresh token
            access_token: Associated MCP access token
            uid: Firebase UID
            firebase_refresh_token: Firebase refresh token
            scope: Granted scopes
        """
        refresh_data = {
            "refresh_token": refresh_token,
            "access_token": access_token,
            "uid": uid,
            "firebase_refresh_token": firebase_refresh_token,
            "scope": scope,
            "created_at": int(time.time())
        }

        key = f"{self.REFRESH_PREFIX}{refresh_token}"
        self.redis_client.setex(
            key,
            self.REFRESH_TTL,
            json.dumps(refresh_data)
        )
        logging.debug(f"Stored refresh token: {refresh_token[:10]}... for UID {uid}")

    def get_refresh_token_data(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve refresh token data.

        Args:
            refresh_token: MCP refresh token

        Returns:
            Refresh token data dict if found
        """
        key = f"{self.REFRESH_PREFIX}{refresh_token}"
        data = self.redis_client.get(key)

        if not data:
            logging.debug(f"Refresh token not found: {refresh_token[:10]}...")
            return None

        try:
            return json.loads(data)
        except Exception as e:
            logging.error(f"Failed to deserialize refresh token: {e}")
            return None

    def revoke_refresh_token(self, refresh_token: str) -> bool:
        """
        Revoke (delete) a refresh token.

        Args:
            refresh_token: MCP refresh token to revoke

        Returns:
            True if revoked
        """
        key = f"{self.REFRESH_PREFIX}{refresh_token}"
        deleted = self.redis_client.delete(key)
        if deleted:
            logging.info(f"Revoked refresh token: {refresh_token[:10]}...")
        return bool(deleted)

    # ===== Client Registration Management =====

    def generate_client_id(self) -> str:
        """
        Generate unique client ID for dynamic registration.

        Returns:
            Client ID string
        """
        return f"mcp_{secrets.token_urlsafe(16)}"

    def store_client_registration(
        self,
        client_id: str,
        client_name: str,
        redirect_uris: list[str]
    ) -> None:
        """
        Store dynamic client registration.

        Args:
            client_id: Generated client ID
            client_name: Client application name
            redirect_uris: List of registered redirect URIs
        """
        registration = ClientRegistration(
            client_id=client_id,
            client_name=client_name,
            redirect_uris=redirect_uris,
            created_at=int(time.time())
        )

        key = f"{self.CLIENT_PREFIX}{client_id}"
        # Client registrations don't expire
        self.redis_client.set(key, json.dumps(registration.to_dict()))
        logging.info(f"Stored client registration: {client_id} ({client_name})")

    def get_client_registration(self, client_id: str) -> Optional[ClientRegistration]:
        """
        Retrieve client registration.

        Args:
            client_id: Client ID to look up

        Returns:
            ClientRegistration if found
        """
        key = f"{self.CLIENT_PREFIX}{client_id}"
        data = self.redis_client.get(key)

        if not data:
            logging.debug(f"Client registration not found: {client_id}")
            return None

        try:
            return ClientRegistration.from_dict(json.loads(data))
        except Exception as e:
            logging.error(f"Failed to deserialize client registration: {e}")
            return None

    def validate_redirect_uri(self, client_id: str, redirect_uri: str) -> bool:
        """
        Validate that redirect_uri is registered for client.

        Args:
            client_id: Client ID
            redirect_uri: Redirect URI to validate

        Returns:
            True if valid
        """
        client = self.get_client_registration(client_id)
        if not client:
            return False

        return redirect_uri in client.redirect_uris

    # ===== Health and Maintenance =====

    def health_check(self) -> Dict[str, Any]:
        """
        Get health status of Redis connection and storage.

        Returns:
            Health status dict
        """
        try:
            ping_ok = self.ping()
            info = self.redis_client.info("stats")

            return {
                "healthy": ping_ok,
                "redis_url": self.redis_url,
                "total_connections": info.get("total_connections_received", 0),
                "commands_processed": info.get("total_commands_processed", 0),
                "connected_clients": info.get("connected_clients", 0)
            }
        except Exception as e:
            logging.error(f"Health check failed: {e}")
            return {
                "healthy": False,
                "error": str(e)
            }

    def cleanup_expired(self) -> int:
        """
        Manually cleanup expired keys (Redis handles this automatically).

        Returns:
            Number of keys cleaned up
        """
        # Redis handles TTL expiration automatically
        # This is a no-op, but provided for completeness
        return 0
