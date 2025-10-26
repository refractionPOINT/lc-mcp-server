"""
OAuth Metadata and Discovery Endpoints

Implements OAuth 2.0 metadata discovery endpoints required by MCP specification:
- Protected Resource Metadata (RFC 9728)
- Authorization Server Metadata (RFC 8414)

These endpoints allow MCP clients to discover OAuth endpoints and capabilities.
"""

import os
import logging
from typing import Dict, Any
from urllib.parse import urljoin


class OAuthMetadataProvider:
    """
    Provides OAuth metadata for MCP server discovery.

    Implements:
    - /.well-known/oauth-protected-resource (RFC 9728)
    - /.well-known/oauth-authorization-server (RFC 8414)
    """

    def __init__(self, server_url: str = None):
        """
        Initialize metadata provider.

        Args:
            server_url: Base URL of the MCP server (e.g., https://mcp.example.com)
                       If not provided, uses MCP_SERVER_URL env var or localhost
        """
        self.server_url = server_url or os.getenv("MCP_SERVER_URL", "http://localhost:8080")
        # Ensure no trailing slash
        self.server_url = self.server_url.rstrip('/')
        logging.info(f"OAuth metadata configured for server URL: {self.server_url}")

    def get_protected_resource_metadata(self) -> Dict[str, Any]:
        """
        Get Protected Resource Metadata (RFC 9728).

        This endpoint tells OAuth clients:
        - What resource this server represents
        - Which authorization servers can issue tokens for it
        - What scopes are available
        - How to provide bearer tokens

        Returns:
            Protected resource metadata dict
        """
        metadata = {
            # The resource identifier for this MCP server
            # Points to the actual MCP endpoint at /mcp
            "resource": f"{self.server_url}/mcp",

            # Authorization servers that can issue tokens for this resource
            # For now, we are our own auth server
            "authorization_servers": [self.server_url],

            # Scopes supported by this resource
            "scopes_supported": [
                "limacharlie:read",     # Read-only access
                "limacharlie:write",    # Write access (modifying resources)
                "limacharlie:admin"     # Administrative operations
            ],

            # How bearer tokens should be provided
            "bearer_methods_supported": ["header"],

            # Additional resource-specific metadata
            "resource_documentation": f"{self.server_url}/docs",
            "resource_signing_alg_values_supported": ["RS256"],
        }

        return metadata

    def get_authorization_server_metadata(self) -> Dict[str, Any]:
        """
        Get Authorization Server Metadata (RFC 8414).

        This endpoint tells OAuth clients:
        - Where to send authorization requests
        - Where to exchange codes for tokens
        - Where to register clients
        - What OAuth features are supported

        Returns:
            Authorization server metadata dict
        """
        metadata = {
            # Issuer identifier for this authorization server
            "issuer": self.server_url,

            # OAuth 2.0 endpoints
            "authorization_endpoint": urljoin(self.server_url, "/authorize"),
            "token_endpoint": urljoin(self.server_url, "/token"),
            "registration_endpoint": urljoin(self.server_url, "/register"),

            # Optional endpoints
            "revocation_endpoint": urljoin(self.server_url, "/revoke"),
            "introspection_endpoint": urljoin(self.server_url, "/introspect"),

            # Scopes supported
            "scopes_supported": [
                "limacharlie:read",
                "limacharlie:write",
                "limacharlie:admin"
            ],

            # Response types supported (OAuth 2.1 requires code flow only)
            "response_types_supported": ["code"],

            # Grant types supported
            "grant_types_supported": [
                "authorization_code",
                "refresh_token"
            ],

            # PKCE is required (OAuth 2.1)
            "code_challenge_methods_supported": ["S256"],

            # Token endpoint authentication methods
            # We support public clients (no client authentication)
            "token_endpoint_auth_methods_supported": ["none"],

            # Response modes
            "response_modes_supported": ["query", "fragment"],

            # OAuth 2.0 features
            "require_request_uri_registration": False,
            "require_pushed_authorization_requests": False,

            # Additional metadata
            "service_documentation": f"{self.server_url}/docs/oauth",
            "ui_locales_supported": ["en-US"],

            # Token properties
            "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "introspection_endpoint_auth_methods_supported": ["none"],
        }

        return metadata

    def generate_www_authenticate_header(
        self,
        error: str = None,
        error_description: str = None,
        scope: str = None,
        status_code: int = 401
    ) -> str:
        """
        Generate WWW-Authenticate header for OAuth challenges.

        Used in 401 and 403 responses to guide clients through OAuth flow.

        Args:
            error: OAuth error code (e.g., "invalid_token", "insufficient_scope")
            error_description: Human-readable error description
            scope: Required or recommended scopes
            status_code: HTTP status code (401 or 403)

        Returns:
            WWW-Authenticate header value
        """
        # Base challenge with metadata URL
        metadata_url = urljoin(self.server_url, "/.well-known/oauth-protected-resource")
        parts = [f'Bearer resource_metadata="{metadata_url}"']

        # Add scope if provided
        if scope:
            parts.append(f'scope="{scope}"')

        # Add error information for 401 responses
        if status_code == 401 or error:
            if error:
                parts.append(f'error="{error}"')
            if error_description:
                parts.append(f'error_description="{error_description}"')

        # Join all parts
        header = ", ".join(parts)

        logging.debug(f"Generated WWW-Authenticate header: {header[:100]}...")
        return header

    def validate_metadata_consistency(self) -> Dict[str, Any]:
        """
        Validate that metadata is consistent and well-formed.

        Returns:
            Validation result dict with status and any errors
        """
        errors = []

        # Validate server URL
        if not self.server_url:
            errors.append("Server URL not configured")
        elif not self.server_url.startswith(('http://', 'https://')):
            errors.append(f"Invalid server URL scheme: {self.server_url}")

        # Check that authorization server in resource metadata matches issuer
        resource_meta = self.get_protected_resource_metadata()
        auth_meta = self.get_authorization_server_metadata()

        if self.server_url not in resource_meta.get("authorization_servers", []):
            errors.append("Server URL not in authorization_servers list")

        if auth_meta.get("issuer") != self.server_url:
            errors.append("Issuer does not match server URL")

        # Validate endpoints are HTTPS in production
        if self.server_url.startswith('http://') and 'localhost' not in self.server_url:
            errors.append("WARNING: Using HTTP for non-localhost server (should use HTTPS)")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": [e for e in errors if e.startswith("WARNING:")]
        }


# Singleton instance
_metadata_provider = None


def get_metadata_provider() -> OAuthMetadataProvider:
    """
    Get singleton metadata provider instance.

    Returns:
        OAuthMetadataProvider instance
    """
    global _metadata_provider
    if _metadata_provider is None:
        _metadata_provider = OAuthMetadataProvider()
    return _metadata_provider


# Helper functions for common use cases

def get_default_scope() -> str:
    """
    Get default scope for authorization requests.

    Returns:
        Space-separated scope string
    """
    return "limacharlie:read limacharlie:write"


def parse_scope_string(scope: str) -> list[str]:
    """
    Parse space-separated scope string into list.

    Args:
        scope: Space-separated scopes

    Returns:
        List of individual scope strings
    """
    if not scope:
        return []
    return scope.strip().split()


def validate_scope(scope: str) -> bool:
    """
    Validate that requested scope is supported.

    Args:
        scope: Space-separated scope string

    Returns:
        True if all scopes are valid
    """
    requested = parse_scope_string(scope)
    metadata = get_metadata_provider()
    supported = metadata.get_protected_resource_metadata().get("scopes_supported", [])

    for s in requested:
        if s not in supported:
            logging.warning(f"Unsupported scope requested: {s}")
            return False

    return True


def filter_scope_to_supported(scope: str) -> str:
    """
    Filter requested scope to only supported scopes.

    Args:
        scope: Space-separated scope string

    Returns:
        Filtered scope string with only supported scopes
    """
    requested = parse_scope_string(scope)
    metadata = get_metadata_provider()
    supported = metadata.get_protected_resource_metadata().get("scopes_supported", [])

    filtered = [s for s in requested if s in supported]
    return " ".join(filtered) if filtered else get_default_scope()
