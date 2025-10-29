# LimaCharlie MCP Server - Quick Reference Guide

## Key Files by Category

### Core Architecture
| File | Purpose | Key Classes/Functions |
|------|---------|---------------------|
| `server.py` | Main server (6364 lines) | `wrap_tool_for_multi_mode()`, `get_sdk_from_context()`, `RequestContextMiddleware` |
| `rate_limiter.py` | Rate limiting | `RedisRateLimiter`, per-IP sliding window |
| `token_encryption.py` | Token encryption at rest | `TokenEncryption`, AES-256-GCM |

### Authentication & Sessions
| File | Purpose | Key Classes |
|------|---------|-----------|
| `oauth_state_manager.py` | Redis session storage | `OAuthStateManager`, stores states/codes/tokens |
| `oauth_token_manager.py` | Token validation | `OAuthTokenManager`, refresh token rotation |
| `oauth_endpoints.py` | OAuth 2.1 endpoints | `OAuthEndpoints`, handles authorize/token/callback |
| `firebase_auth_bridge.py` | OAuth provider bridge | `FirebaseAuthBridge`, wraps Firebase/Google OAuth |
| `oauth_metadata.py` | OAuth metadata | `OAuthMetadataProvider`, serves .well-known endpoints |

## Context Variables (Request Isolation)

```python
request_context_var          # HTTP Request object (per-request)
sdk_context_var              # limacharlie.Manager instance (per-request)
uid_auth_context_var         # (uid, api_key, mode, oauth_creds) tuple
current_oid_context_var      # Current organization ID for nested calls
```

## Authentication Modes Summary

### Mode 1: Normal (Single Org)
- Env: `LC_OID` + `LC_API_KEY`
- Tools: No `oid` parameter needed
- SDK: Created once, used for all tools

### Mode 2: UID + API Key (Multi-Org)
- Env: `LC_UID` + `LC_API_KEY`
- Tools: REQUIRE `oid` parameter
- SDK: Created per-tool with OID

### Mode 3: UID + OAuth (Multi-Org, RECOMMENDED)
- Env: `LC_UID` + `~/.limacharlie` config file
- Tools: REQUIRE `oid` parameter
- SDK: Created per-tool, credentials refreshed automatically

## Critical Functions

### Authentication Extraction
```python
get_auth_info(request)           # Extract auth from HTTP headers
get_sdk_from_context(ctx)        # Get or create SDK for current request
get_uid_from_environment()       # Load UID from env/config
get_auth_from_sdk_config()       # Load creds from ~/.limacharlie
```

### Tool Wrapping
```python
wrap_tool_for_multi_mode()       # Adds oid parameter, validates auth
mcp_tool_with_gcs()              # Decorator: GCS + multi-mode wrapper
create_mcp_for_profile()         # Create MCP instance with filtered tools
```

### Credential Management
```python
make_sdk(oid, token, api_key)    # Create limacharlie.Manager instance
RequestContextMiddleware         # ASGI middleware: request isolation
```

## Request Flow (HTTP Mode)

```
1. RequestContextMiddleware.__call__()
   ├─ Store Request in request_context_var
   ├─ Reset sdk_context_var, uid_auth_context_var
   
2. Route to tool endpoint
   
3. wrap_tool_for_multi_mode wrapper executes
   ├─ Extract oid from kwargs (UID mode only)
   ├─ Create SDK with credentials (if UID mode)
   ├─ Store SDK in sdk_context_var
   ├─ Call actual tool function
   └─ Shutdown SDK
   
4. Tool function executes
   ├─ Call get_sdk_from_context(ctx)
   ├─ Use SDK for API calls
   └─ Return result
   
5. RequestContextMiddleware finally block
   ├─ Shutdown SDK if exists
   ├─ Reset all contextvars
   └─ Send response
```

## Security Controls Checklist

### Multi-Tenant Isolation
- [x] OID parameter required in UID mode
- [x] No OID inheritance from context
- [x] SDK created per-request (not cached)
- [x] No global OAuth credentials (explicit passing)

### Token Security
- [x] AES-256-GCM encryption in Redis
- [x] Refresh token rotation (detect theft)
- [x] Authorization code TOCTOU fix (atomic deletion)
- [x] Firebase ID token verification
- [x] Access token auto-refresh (< 5 min to expiry)

### DoS Protection
- [x] Rate limiting per IP (Redis + Lua)
- [x] `/authorize`: 10 req/min
- [x] `/token`: 20 req/min
- [x] `/register`: 5 req/min

### Access Control
- [x] Profile-based tool filtering
- [x] PKCE validation (authorization code flow)
- [x] State CSRF protection (10 min TTL)

## Configuration Variables

### Authentication
```bash
PUBLIC_MODE              # "true" for HTTP, "false" for STDIO
LC_OID                   # Organization ID (normal mode)
LC_API_KEY               # API key or JWT token
LC_UID                   # User ID (enables UID mode)
LC_CURRENT_ENV           # Environment in ~/.limacharlie (default: "default")
```

### OAuth (if MCP_OAUTH_ENABLED=true)
```bash
REDIS_URL                # Redis connection URL
REDIS_ENCRYPTION_KEY     # Base64 AES-256 key for token encryption
MCP_OAUTH_ENABLED        # "true" to enable OAuth endpoints
OAUTH_SERVER_URL         # Public OAuth server URL
```

### Storage
```bash
GCS_BUCKET_NAME          # Google Cloud Storage bucket for large results
GCS_TOKEN_THRESHOLD      # Token count before uploading (default: 1000)
GCS_URL_EXPIRY_HOURS     # Signed URL expiry (default: 24)
GCS_SIGNER_SERVICE_ACCOUNT  # Service account for signing
```

### Tools & Features
```bash
MCP_PROFILE              # "all", "historical_data", "live_investigation", etc.
GOOGLE_API_KEY           # For AI-powered generation features
LLM_YAML_RETRY_COUNT     # Retries for LLM YAML parsing (default: 10)
```

## Redis Key Structure

```
oauth:state:<state>              # OAuth authorization state (10 min TTL)
oauth:code:<code>                # Authorization code (5 min TTL)
oauth:token:<access_token>       # Access token (1 hour TTL)
oauth:refresh:<refresh_token>    # Refresh token (30 day TTL)
oauth:client:<client_id>         # Client registration
oauth:session:<state>            # Firebase state mapping
rate_limit:<endpoint>:<ip>       # Rate limit counter (sliding window)
```

## Profiles & Tools

### Available Profiles
- `all` - All tools (default)
- `core` - 6 essential tools
- `historical_data` - Historical analysis
- `live_investigation` - Real-time forensics
- `threat_response` - Incident response
- `fleet_management` - Sensor management
- `detection_engineering` - Detection development
- `ai_powered` - AI content generation
- `platform_admin` - Configuration

### Core Tools (in all profiles)
```python
test_tool, get_sensor_info, list_sensors, 
get_online_sensors, is_online, search_hosts
```

## Deployment Checklist

### Pre-Deployment
- [ ] Set `REDIS_ENCRYPTION_KEY` for token protection
- [ ] Configure Redis connection: `REDIS_URL`
- [ ] Generate encryption key: `python -c 'import os,base64; print(base64.b64encode(os.urandom(32)).decode())'`

### Local Development (STDIO)
```bash
export PUBLIC_MODE=false
export LC_OID="your-org-id"
export LC_API_KEY="your-api-key"
export MCP_PROFILE="all"
python3 server.py
```

### Production (HTTP)
```bash
export PUBLIC_MODE=true
export REDIS_URL="redis://redis:6379"
export REDIS_ENCRYPTION_KEY="<base64-key>"
export MCP_OAUTH_ENABLED="true"
uvicorn server:app --host 0.0.0.0 --port 8080 --workers 1
```

### Docker
```bash
docker build -t lc-mcp-server .
docker run -e PUBLIC_MODE=true -e REDIS_URL=redis://redis:6379 \
  -e REDIS_ENCRYPTION_KEY="<key>" -p 8080:8080 lc-mcp-server
```

## Testing Security

### Test Files
- `test_uid_mode.py` - UID mode functionality
- `test_server.py` - Server basics
- `test_security_fixes.py` - Security vulnerability fixes
- `test_critical_fixes.py` - Critical security tests

### Run Tests
```bash
pytest test_security_fixes.py -v
pytest test_critical_fixes.py -v
pytest test_uid_mode.py -v
```

## Common Issues & Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| Tokens not encrypted | `REDIS_ENCRYPTION_KEY` not set | Set env var with base64 key |
| Cross-tenant access | OID not passed to tool | Add `oid=oid` to nested calls |
| Rate limit exceeded | Too many requests per minute | Check rate limit headers, wait |
| Auth header rejected | Wrong format | Use `Bearer <token>:<oid>` or headers |
| Redis connection failed | Redis not running | Start Redis: `redis-server` |

## Performance Tuning

### Thread Pool
```python
SDK_THREAD_POOL = ThreadPoolExecutor(max_workers=100)
```
- Increase `max_workers` for more concurrent requests
- Monitor thread pool utilization

### Redis Connection
```python
socket_keepalive=True           # Keep connections alive
socket_connect_timeout=5        # 5 second connection timeout
```

### GCS Upload
- Default threshold: 1000 tokens (~4KB)
- Adjust `GCS_TOKEN_THRESHOLD` for different result sizes
- Signed URLs valid for 24 hours (adjust `GCS_URL_EXPIRY_HOURS`)

## Key Security Decisions

### Why Not Global OAuth Credentials?
- **Reason**: Concurrent requests could leak User A's credentials to User B
- **Solution**: Credentials stored in contextvars (thread-local), passed explicitly

### Why Refresh Token Rotation?
- **Reason**: Detect theft - if old token used again, it's suspicious
- **Solution**: Each refresh generates new token, revokes old one

### Why No OID Inheritance?
- **Reason**: Nested tools could operate on wrong organization
- **Solution**: Force explicit OID parameter in all tool calls

### Why AES-256-GCM for Redis?
- **Reason**: Redis compromise shouldn't expose credentials
- **Solution**: All tokens encrypted at rest, only decrypted when needed

---

**Last Updated**: 2025-10-26
**Status**: Security fixes applied (7 critical issues resolved)
