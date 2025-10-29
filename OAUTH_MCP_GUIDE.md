# MCP OAuth 2.1 Guide for LimaCharlie

## Overview

The LimaCharlie MCP server now supports full **OAuth 2.1 with PKCE** authentication, compliant with the [MCP specification](https://modelcontextprotocol.io/specification/draft/basic/authorization). This enables secure, standardized authentication for MCP clients like Claude Code.

### Key Features

- **OAuth 2.1 Authorization Code Flow** with PKCE (Proof Key for Code Exchange)
- **Firebase Authentication Integration** - Seamless integration with LimaCharlie's existing auth infrastructure
- **Multi-Organization Support** - Works with LimaCharlie's multi-tenant architecture
- **Automatic Token Refresh** - Transparently renews Firebase tokens before expiration
- **Stateful Session Management** - Redis-backed OAuth state storage
- **Standard Discovery** - RFC 9728 and RFC 8414 compliant metadata endpoints

## Architecture

```
┌─────────────┐                  ┌──────────────┐                 ┌─────────────┐
│             │  1. Discovery    │              │                 │             │
│ MCP Client  │ ───────────────> │  MCP Server  │                 │  Firebase   │
│ (Claude     │                  │   (OAuth     │                 │   Auth      │
│  Code)      │  2. /authorize   │    Server)   │  3. Firebase    │  (Google    │
│             │ ───────────────> │              │ ───────────────>│   OAuth)    │
│             │                  │              │     OAuth        │             │
│             │  4. Redirect     │              │                 │             │
│             │ <─────────────── │              │  5. Firebase    │             │
│             │                  │              │     Tokens      │             │
│             │  6. /token       │              │ <───────────────│             │
│             │ ───────────────> │              │                 │             │
│             │                  │       ┌──────┴──────┐          │             │
│             │  7. Access Token │       │    Redis    │          │             │
│             │ <─────────────── │       │  (OAuth     │          └─────────────┘
│             │                  │       │   State)    │
│             │  8. API Request  │       └─────────────┘
│             │ ───────────────> │
│             │    + Bearer      │
│             │      Token       │
└─────────────┘                  └──────────────┘
```

### OAuth Flow Steps

1. **Discovery**: Client fetches `/.well-known/oauth-protected-resource` to find authorization server
2. **Authorization Request**: Client initiates OAuth flow at `/authorize` with PKCE challenge
3. **Firebase OAuth**: Server redirects user to Firebase-managed OAuth (Google or Microsoft)
4. **User Authentication**: User authenticates with selected provider via Firebase
5. **Authorization Code**: Server receives Firebase tokens, generates OAuth authorization code
6. **Token Exchange**: Client exchanges code for access token at `/token` with PKCE verifier
7. **Access Granted**: Server returns MCP access token mapped to Firebase tokens
8. **API Access**: Client uses access token in `Authorization: Bearer <token>` header

## Provider Selection

The server supports multiple OAuth providers concurrently. Users can select their preferred authentication provider when initiating the OAuth flow.

### Supported Providers

| Provider | Parameter Value | Description |
|----------|----------------|-------------|
| Google | `google` | Google accounts (default) |
| Microsoft | `microsoft` | Microsoft/Azure AD accounts |

### How to Specify Provider

Add the `provider` query parameter to the authorization request:

**Google OAuth (default)**:
```
GET /authorize?response_type=code&client_id=...&redirect_uri=...&state=...&code_challenge=...&code_challenge_method=S256
```

**Microsoft OAuth (explicit)**:
```
GET /authorize?provider=microsoft&response_type=code&client_id=...&redirect_uri=...&state=...&code_challenge=...&code_challenge_method=S256
```

**Using curl**:
```bash
# Google authentication (default)
curl "http://localhost:8080/authorize?client_id=test&redirect_uri=http://localhost&state=xyz&code_challenge=abc&code_challenge_method=S256&response_type=code"

# Microsoft authentication
curl "http://localhost:8080/authorize?provider=microsoft&client_id=test&redirect_uri=http://localhost&state=xyz&code_challenge=abc&code_challenge_method=S256&response_type=code"
```

### Provider Persistence

The selected provider is automatically stored with your OAuth session and used throughout the authentication flow. You don't need to specify it again in token exchange requests - the server remembers your choice.

### Invalid Provider Handling

If you specify an unsupported provider, the server returns a `400 Bad Request` error:

```json
{
  "error": "invalid_request",
  "error_description": "Unsupported provider: facebook. Supported: google, microsoft"
}
```

## Setup & Configuration

### Prerequisites

1. **Redis Server** - Required for OAuth state storage
2. **Firebase API Key** - LimaCharlie's Firebase project key
3. **HTTPS Domain** - For production deployment (localhost OK for development)

### Environment Variables

```bash
# Required for OAuth
export PUBLIC_MODE=true
export MCP_OAUTH_ENABLED=true
export REDIS_URL=redis://localhost:6379
export MCP_SERVER_URL=https://mcp.yourcompany.com  # Your public MCP server URL
export FIREBASE_API_KEY=<your-firebase-api-key>

# Optional
export GCS_BUCKET_NAME=<bucket>      # For large result storage
export GEMINI_API_KEY=<key>          # For AI-powered tools
export MCP_PROFILE=all               # Tool profile to expose
```

### Installation

#### Option 1: Docker Compose (Recommended)

```bash
# 1. Create .env file
cat > .env <<EOF
FIREBASE_API_KEY=<your-key>
MCP_SERVER_URL=http://localhost:8080
GEMINI_API_KEY=<optional>
EOF

# 2. Start services
docker-compose up -d

# 3. Check health
curl http://localhost:8080/
curl http://localhost:8080/.well-known/oauth-protected-resource
```

#### Option 2: Manual Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start Redis
docker run -d -p 6379:6379 redis:7-alpine

# 3. Configure environment
export PUBLIC_MODE=true
export MCP_OAUTH_ENABLED=true
export REDIS_URL=redis://localhost:6379
export MCP_SERVER_URL=http://localhost:8080
export FIREBASE_API_KEY=<your-key>

# 4. Run server
uvicorn server:app --host 0.0.0.0 --port 8080
```

### Verify Setup

```bash
# 1. Check OAuth metadata
curl http://localhost:8080/.well-known/oauth-authorization-server | jq

# 2. Check protected resource metadata
curl http://localhost:8080/.well-known/oauth-protected-resource | jq

# 3. Check Redis connection
redis-cli ping

# 4. Check server health
curl http://localhost:8080/ | jq
```

## Claude Code Integration

### Configuration

Add to Claude Code settings (`~/.config/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "limacharlie": {
      "transportType": "sse",
      "transportOptions": {
        "url": "http://localhost:8080/mcp/"
      }
    }
  }
}
```

### OAuth Flow in Claude Code

1. **First Connection**: Claude Code detects OAuth requirement from 401 response
2. **Authorization**: Opens browser for Google OAuth via Firebase
3. **Token Storage**: Securely stores access/refresh tokens
4. **Auto-Refresh**: Automatically renews tokens before expiration
5. **Multi-Org**: Each tool call requires `oid` parameter for organization selection

## OAuth Endpoints

### Discovery Endpoints

#### GET /.well-known/oauth-protected-resource

Returns protected resource metadata per RFC 9728.

**Response**:
```json
{
  "resource": "http://localhost:8080",
  "authorization_servers": ["http://localhost:8080"],
  "scopes_supported": [
    "limacharlie:read",
    "limacharlie:write",
    "limacharlie:admin"
  ],
  "bearer_methods_supported": ["header"]
}
```

#### GET /.well-known/oauth-authorization-server

Returns authorization server metadata per RFC 8414.

**Response**:
```json
{
  "issuer": "http://localhost:8080",
  "authorization_endpoint": "http://localhost:8080/authorize",
  "token_endpoint": "http://localhost:8080/token",
  "registration_endpoint": "http://localhost:8080/register",
  "scopes_supported": ["limacharlie:read", "limacharlie:write", "limacharlie:admin"],
  "response_types_supported": ["code"],
  "code_challenge_methods_supported": ["S256"]
}
```

### OAuth Flow Endpoints

#### GET /authorize

Initiates OAuth authorization flow.

**Parameters**:
- `response_type`: Must be `code`
- `client_id`: OAuth client ID
- `redirect_uri`: Client redirect URI (localhost or HTTPS)
- `scope`: Requested scopes (space-separated)
- `state`: CSRF protection state
- `code_challenge`: PKCE challenge (S256)
- `code_challenge_method`: Must be `S256`
- `resource`: Target resource URI (optional)
- `provider`: OAuth provider to use - `google` or `microsoft` (optional, default: `google`)

**Response**: Redirects to Firebase OAuth URL for selected provider

#### POST /token

Exchanges authorization code for access token.

**Parameters** (form-encoded):
- `grant_type`: `authorization_code` or `refresh_token`
- `code`: Authorization code (for authorization_code grant)
- `redirect_uri`: Same URI used in /authorize
- `code_verifier`: PKCE verifier
- `refresh_token`: Refresh token (for refresh_token grant)

**Response**:
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJ...",
  "scope": "limacharlie:read limacharlie:write"
}
```

#### POST /register

Dynamic client registration per RFC 7591.

**Request**:
```json
{
  "client_name": "My MCP Client",
  "redirect_uris": ["http://localhost:8080/callback"]
}
```

**Response**:
```json
{
  "client_id": "mcp_abc123...",
  "client_name": "My MCP Client",
  "redirect_uris": ["http://localhost:8080/callback"],
  "token_endpoint_auth_method": "none"
}
```

#### POST /revoke

Revokes access or refresh token.

**Parameters** (form-encoded):
- `token`: Token to revoke
- `token_type_hint`: `access_token` or `refresh_token` (optional)

**Response**: Empty 200 OK

#### POST /introspect

Introspects token status.

**Parameters** (form-encoded):
- `token`: Token to introspect

**Response**:
```json
{
  "active": true,
  "scope": "limacharlie:read limacharlie:write",
  "client_id": "mcp_client",
  "exp": 1234567890,
  "sub": "firebase-uid-123"
}
```

## Scopes

The server supports three scope levels:

| Scope | Description | Operations |
|-------|-------------|------------|
| `limacharlie:read` | Read-only access | List sensors, get events, search |
| `limacharlie:write` | Write access | Create rules, modify resources |
| `limacharlie:admin` | Administrative | Delete resources, manage users |

## Security Considerations

### PKCE Protection

- All authorization flows **require** PKCE with S256
- Code challenges are cryptographically validated
- Prevents authorization code interception attacks

### CSRF Protection

- State parameters required for all authorization requests
- Single-use state values stored in Redis
- 10-minute expiration on authorization states

### Token Security

- Access tokens: 1-hour TTL
- Refresh tokens: 30-day TTL with rotation
- Authorization codes: 5-minute TTL, single-use
- All tokens stored securely in Redis with TTL

### Multi-Tenancy

- Firebase UID extracted from validated tokens
- Each request requires `oid` parameter for organization selection
- No cross-organization token reuse
- Redis keys namespaced to prevent leakage

### HTTPS Requirements

- Production deployments **must** use HTTPS
- Redirect URIs must be `localhost` or `https://`
- Authorization endpoints reject insecure redirects

## Troubleshooting

### OAuth Not Working

**Symptom**: 401 responses without WWW-Authenticate header

**Solutions**:
1. Check `MCP_OAUTH_ENABLED=true`
2. Verify Redis is running: `redis-cli ping`
3. Check logs for OAuth initialization errors
4. Ensure `PUBLIC_MODE=true`

### Redis Connection Failed

**Symptom**: "Redis connection failed" in logs

**Solutions**:
1. Check Redis is running: `docker ps | grep redis`
2. Verify `REDIS_URL` environment variable
3. Test connection: `redis-cli -u $REDIS_URL ping`
4. Check firewall rules

### Firebase Auth Errors

**Symptom**: "Failed to create auth URI" or "Sign-in failed"

**Solutions**:
1. Verify `FIREBASE_API_KEY` is correct
2. Check Firebase project configuration
3. Ensure Google OAuth is enabled in Firebase Console
4. Review Firebase quotas and limits

### Token Refresh Failures

**Symptom**: "Failed to refresh token" errors

**Solutions**:
1. Check Firebase refresh token is valid
2. Verify Firebase API key hasn't changed
3. Check network connectivity to Firebase APIs
4. Review Redis token storage

### PKCE Verification Failed

**Symptom**: "PKCE verification failed" on token exchange

**Solutions**:
1. Ensure client uses S256 code challenge method
2. Verify code_verifier matches original code_challenge
3. Check for URL encoding issues in parameters
4. Verify authorization code hasn't expired (5 min TTL)

## Monitoring & Logging

### Health Checks

```bash
# Server health
curl http://localhost:8080/

# OAuth metadata
curl http://localhost:8080/.well-known/oauth-protected-resource

# Redis health
redis-cli -u $REDIS_URL --json INFO stats
```

### Logging

Enable debug logging for OAuth:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Key log messages to monitor:
- `"MCP OAuth 2.1 support enabled"` - OAuth initialized
- `"Redis connection successful"` - Redis OK
- `"Valid OAuth access token for UID"` - Token validated
- `"Successfully refreshed Firebase token"` - Auto-refresh working

### Metrics

Monitor these Redis keys:
```bash
# OAuth state count
redis-cli KEYS "oauth:state:*" | wc -l

# Active access tokens
redis-cli KEYS "oauth:token:*" | wc -l

# Client registrations
redis-cli KEYS "oauth:client:*" | wc -l
```

## Migration Guide

### From Legacy Bearer Token Auth

**Before** (Direct Firebase JWT):
```json
{
  "mcpServers": {
    "limacharlie": {
      "transportType": "sse",
      "transportOptions": {
        "url": "http://localhost:8080/mcp/",
        "headers": {
          "Authorization": "Bearer <firebase-jwt>",
          "x-lc-oid": "<org-id>"
        }
      }
    }
  }
}
```

**After** (MCP OAuth):
```json
{
  "mcpServers": {
    "limacharlie": {
      "transportType": "sse",
      "transportOptions": {
        "url": "http://localhost:8080/mcp/"
      }
    }
  }
}
```

OAuth flow handles authentication automatically!

### Backward Compatibility

The server supports both authentication methods simultaneously:
- **MCP OAuth tokens** - Validated via Redis, auto-refresh
- **Legacy tokens** - Direct Firebase JWT or API keys (existing behavior)

No breaking changes to existing integrations.

## API Reference

### Python SDK Usage

```python
from oauth_endpoints import get_oauth_endpoints
from oauth_token_manager import get_token_manager
from oauth_metadata import get_metadata_provider

# Get OAuth components
oauth = get_oauth_endpoints()
tokens = get_token_manager()
metadata = get_metadata_provider()

# Validate access token
validation = tokens.validate_access_token("eyJ...")
if validation.valid:
    print(f"UID: {validation.uid}")
    print(f"Scope: {validation.scope}")

# Get token info for request
info = tokens.get_token_info_for_request("eyJ...")
if info:
    # Use Firebase tokens for LimaCharlie API
    sdk = limacharlie.Manager(oid="org-123", uid=info['uid'])
```

## Support

For issues or questions:
- GitHub: https://github.com/refractionPOINT/lc-mcp-server/issues
- Documentation: https://docs.limacharlie.io
- Community: https://community.limacharlie.io

## References

- [MCP OAuth Specification](https://modelcontextprotocol.io/specification/draft/basic/authorization)
- [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-07)
- [RFC 7636 - PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 8414 - Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 9728 - Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [Firebase Authentication](https://firebase.google.com/docs/auth)
