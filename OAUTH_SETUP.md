# OAuth 2.1 Setup Guide

This document provides comprehensive instructions for deploying and using the LimaCharlie MCP Server with OAuth 2.1 authentication.

## Overview

The LimaCharlie MCP Server supports two modes:
- **STDIO mode**: For local CLI usage (Claude Desktop)
- **HTTP mode**: For remote access with OAuth 2.1 authentication

This guide focuses on HTTP mode with OAuth authentication using Firebase as the identity provider.

## Architecture

The OAuth implementation follows these specifications:
- **OAuth 2.1** with Authorization Code flow + PKCE (S256)
- **Firebase Authentication** for identity management (Google, Microsoft providers)
- **Redis** for secure state management
- **AES-256-GCM** encryption for token storage
- **RFC 8414** Authorization Server Metadata
- **RFC 9728** Protected Resource Metadata
- **RFC 7662** Token Introspection

## Prerequisites

1. **Redis Server** (v6.0+)
2. **Docker & Docker Compose** (optional, for containerized deployment)
3. **Firebase Project** (optional, for custom Firebase configuration)
4. **LimaCharlie API Credentials** (OID + API Key)

## Quick Start with Docker Compose

### 1. Generate Encryption Key

```bash
# Generate a secure 32-byte encryption key
openssl rand -hex 32
```

### 2. Create Environment File

Create a `.env` file in the project root:

```bash
# Copy the example environment file
cp .env.example .env
```

Edit `.env` and set the following **required** variables:

```env
# Server Mode
MCP_MODE=http

# Encryption (REQUIRED for HTTP mode)
ENCRYPTION_KEY=<your-32-byte-hex-key-from-step-1>

# Redis
REDIS_PASSWORD=changeme

# LimaCharlie API Credentials
LC_OID=<your-organization-id>
LC_API_KEY=<your-api-key>

# Public Server URL (update for production)
MCP_SERVER_URL=http://localhost:8080
```

### 3. Start the Server

```bash
# Start Redis and MCP server
docker-compose up -d

# View logs
docker-compose logs -f mcp-server

# Check health
curl http://localhost:8080/health
```

### 4. Test OAuth Flow

```bash
# Get authorization server metadata
curl http://localhost:8080/.well-known/oauth-authorization-server | jq

# Start authorization flow
open "http://localhost:8080/authorize?client_id=test&redirect_uri=http://localhost:3000/callback&response_type=code&scope=limacharlie:read%20limacharlie:write&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=random_state_123"
```

## Manual Deployment

### 1. Install Redis

```bash
# Ubuntu/Debian
sudo apt-get install redis-server

# macOS
brew install redis

# Start Redis
redis-server
```

### 2. Set Environment Variables

```bash
export MCP_MODE=http
export HTTP_PORT=8080
export MCP_SERVER_URL=http://localhost:8080

# Redis configuration
export REDIS_ADDRESS=localhost:6379
export REDIS_PASSWORD=changeme
export REDIS_DB=0

# Encryption key (32 bytes as 64 hex characters)
export ENCRYPTION_KEY=$(openssl rand -hex 32)

# Firebase (optional - uses default if not set)
export FIREBASE_API_KEY=AIzaSyB5VyO6qS-XlnVD3zOIuEVNBD5JFn22_1w

# LimaCharlie credentials
export LC_OID=<your-organization-id>
export LC_API_KEY=<your-api-key>
```

### 3. Build and Run

```bash
# Build the server
go build -o lc-mcp-server ./cmd/server

# Run the server
./lc-mcp-server
```

## OAuth Flow

### Authorization Request

```
GET /authorize?
  client_id=<client_id>&
  redirect_uri=<redirect_uri>&
  response_type=code&
  scope=limacharlie:read limacharlie:write&
  code_challenge=<pkce_challenge>&
  code_challenge_method=S256&
  state=<random_state>
```

### Provider Selection

The user will be presented with a provider selection page:
- **Google** (google.com)
- **Microsoft** (microsoft.com)

### Firebase Authentication

After provider selection, the user is redirected to Firebase for authentication. Firebase handles:
- OAuth flow with the selected provider
- User consent
- MFA if enabled

### Token Exchange

After successful authentication:

```bash
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=<authorization_code>&
redirect_uri=<redirect_uri>&
code_verifier=<pkce_verifier>&
client_id=<client_id>
```

Response:

```json
{
  "access_token": "eyJhbGciOiJS...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "v1.MR...",
  "scope": "limacharlie:read limacharlie:write"
}
```

### Using Access Tokens

Include the access token in API requests:

```bash
curl -H "Authorization: Bearer <access_token>" \
  http://localhost:8080/mcp
```

### Token Refresh

```bash
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=<refresh_token>&
client_id=<client_id>
```

### Token Revocation

```bash
POST /revoke
Content-Type: application/x-www-form-urlencoded

token=<access_or_refresh_token>&
client_id=<client_id>
```

## Scopes

The server supports the following OAuth scopes:

- `limacharlie:read` - Read-only access to LimaCharlie resources
- `limacharlie:write` - Write access to LimaCharlie resources
- `limacharlie:admin` - Administrative access (full permissions)

Default scope: `limacharlie:read limacharlie:write`

## Security Features

### Token Encryption

All tokens (ID tokens, refresh tokens) are encrypted at rest using AES-256-GCM:
- **Key Size**: 256 bits (32 bytes)
- **Nonce**: 96 bits (12 bytes), randomly generated per encryption
- **Authentication**: GCM provides authenticated encryption

### PKCE (Proof Key for Code Exchange)

All authorization flows require PKCE with SHA-256:
- **code_challenge_method**: S256
- **code_verifier**: 43-128 character random string
- **code_challenge**: Base64URL(SHA256(code_verifier))

### State Management

- **OAuth state**: 10-minute TTL
- **Authorization codes**: 5-minute TTL, single-use
- **Access tokens**: 1-hour TTL
- **Refresh tokens**: 30-day TTL with rotation

### Atomic Operations

All state operations use Redis Lua scripts to prevent TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities.

## MFA Support

The server supports Multi-Factor Authentication through Firebase:
- **TOTP** (Time-Based One-Time Password)
- Automatic MFA challenge presentation
- MFA verification endpoint

## Discovery Endpoints

### Authorization Server Metadata (RFC 8414)

```bash
curl http://localhost:8080/.well-known/oauth-authorization-server
```

### Protected Resource Metadata (RFC 9728)

```bash
curl http://localhost:8080/.well-known/oauth-protected-resource
```

## Monitoring

### Health Check

```bash
curl http://localhost:8080/health
```

Response:

```json
{
  "status": "healthy",
  "time": "2025-01-15T10:30:00Z"
}
```

### Readiness Check

```bash
curl http://localhost:8080/ready
```

Response:

```json
{
  "status": "ready",
  "checks": {
    "redis": true
  },
  "time": "2025-01-15T10:30:00Z"
}
```

## Production Deployment

### Environment Variables

For production, ensure you configure:

```env
# Use HTTPS in production
MCP_SERVER_URL=https://mcp.example.com

# Strong Redis password
REDIS_PASSWORD=<strong-random-password>

# Production encryption key
ENCRYPTION_KEY=<secure-32-byte-hex-key>

# CORS configuration
CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com

# Optional: Custom Firebase project
FIREBASE_API_KEY=<your-firebase-api-key>
```

### TLS/HTTPS

For production, deploy behind a reverse proxy (nginx, Caddy, Traefik) with TLS:

```nginx
server {
    listen 443 ssl http2;
    server_name mcp.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Redis Security

For production Redis:

```bash
# Use password authentication
requirepass <strong-random-password>

# Bind to localhost only (if on same host)
bind 127.0.0.1

# Enable persistence
save 900 1
save 300 10
save 60 10000

# Enable AOF
appendonly yes
```

## Troubleshooting

### Server won't start

Check logs for configuration errors:

```bash
# Docker
docker-compose logs mcp-server

# Manual
./lc-mcp-server 2>&1 | tee server.log
```

Common issues:
- Missing `ENCRYPTION_KEY` (must be 64 hex characters)
- Redis connection failure
- Invalid LimaCharlie credentials

### OAuth flow fails

1. Check authorization server metadata is accessible
2. Verify redirect_uri matches exactly
3. Ensure PKCE parameters are correct
4. Check Redis connectivity

### Token refresh fails

- Refresh token may have expired (30-day TTL)
- Refresh token rotation - old token is revoked after use
- Redis connection issues

## Development

### Running Tests

```bash
go test ./...
```

### Local Development

```bash
# Start Redis
redis-server

# Set environment variables
export MCP_MODE=http
export ENCRYPTION_KEY=$(openssl rand -hex 32)
export LC_OID=test
export LC_API_KEY=test

# Run server
go run ./cmd/server
```

## Support

For issues or questions:
- GitHub Issues: https://github.com/refractionPOINT/lc-mcp-server/issues
- Documentation: https://github.com/refractionPOINT/lc-mcp-server

## License

Apache 2.0
