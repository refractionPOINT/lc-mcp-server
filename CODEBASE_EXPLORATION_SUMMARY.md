# Codebase Exploration Summary - LimaCharlie MCP Server

**Date**: October 26, 2025  
**Analyzed**: Complete authentication, authorization, session management, and data storage architecture  
**Status**: 7 critical security issues identified and fixed

---

## Documents Generated

This exploration has produced three comprehensive analysis documents:

### 1. **ARCHITECTURE_AND_SECURITY_ANALYSIS.md** (Main Document)
- Complete architecture overview
- All authentication/authorization mechanisms
- User credential storage and management
- Session management approach
- Shared state and global variables
- Database and storage access patterns
- Critical security controls
- Request routing and context management
- Data flow diagrams
- Key findings and deployment recommendations

### 2. **QUICK_REFERENCE.md** (Developer Guide)
- Quick lookup tables for key files
- Context variables summary
- Authentication modes at a glance
- Critical functions reference
- Request flow diagram
- Security checklist
- Configuration variables
- Redis key structure
- Profiles and tools
- Deployment checklist
- Common issues and solutions

### 3. **CODEBASE_EXPLORATION_SUMMARY.md** (This File)
- What was explored
- Key findings
- Critical files
- Security improvements
- Next steps

---

## What Was Explored

### Codebase Structure
- 21 Python files totaling 6,364+ lines
- 3 deployment modes (STDIO, HTTP, OAuth)
- 100+ MCP tools organized in 9 profiles
- Comprehensive test suite (8 test files)

### Core Architecture
1. **Deployment Modes**
   - STDIO: Local development (Claude Desktop/Code)
   - HTTP: Public service deployment (uvicorn + Starlette)
   - OAuth: Multi-user authentication flow

2. **Authentication Methods**
   - Normal Mode: Single org with OID + API Key
   - UID + API Key: Multi-org with explicit OID per tool
   - UID + OAuth: Multi-org with automatic token refresh

3. **Session Management**
   - Request-scoped contextvars (thread-safe isolation)
   - SDK created per-request, shutdown after response
   - OAuth state stored in Redis with TTLs

4. **Data Storage**
   - Redis: OAuth state, tokens, rate limit counters
   - GCS: Large results (>1000 tokens)
   - Encrypted tokens: AES-256-GCM at rest

---

## Critical Findings

### Architecture Strengths

1. **Multi-Tenant Isolation**
   - Explicit OID parameters (no inheritance)
   - Request-scoped SDK instances
   - Python contextvars for thread-safe isolation
   - Principle: explicit over implicit

2. **Token Security**
   - AES-256-GCM encryption in Redis
   - Refresh token rotation (detects theft)
   - Authorization code TOCTOU fix (atomic deletion)
   - Firebase ID token verification

3. **Context Isolation**
   - Four contextvars provide per-request state
   - Middleware resets all on entry
   - Credentials never in global variables
   - SDK shutdown in finally block

4. **DoS Protection**
   - Rate limiting per IP (Redis + Lua)
   - Different limits per endpoint
   - Returns 429 with Retry-After header

5. **Access Control**
   - Profile-based tool filtering
   - PKCE authorization code flow
   - State CSRF protection

### Security Fixes Applied

| Issue | Severity | Status |
|-------|----------|--------|
| Global OAuth credentials race condition | CRITICAL | Fixed |
| Plaintext Firebase tokens in Redis | CRITICAL | Fixed |
| Authorization code TOCTOU race condition | CRITICAL | Fixed |
| Sensitive data in error logs | CRITICAL | Fixed |
| Missing refresh token rotation | CRITICAL | Fixed |
| No JWT signature verification | CRITICAL | Fixed |
| OID context inheritance vulnerability | HIGH | Fixed |

---

## Key Components

### Authentication & Authorization
- `server.py`: Authentication extraction (lines 1052-1109)
- `get_sdk_from_context()`: SDK creation logic (lines 1124-1232)
- `wrap_tool_for_multi_mode()`: Tool wrapper with oid validation (lines 588-782)
- `RequestContextMiddleware`: Request isolation (lines 1236-1284)

### Session & Token Management
- `oauth_state_manager.py`: Redis state storage with encryption
- `oauth_token_manager.py`: Token validation and refresh with rotation
- `token_encryption.py`: AES-256-GCM encryption implementation
- `firebase_auth_bridge.py`: OAuth provider integration

### Security & DoS Protection
- `rate_limiter.py`: Per-IP rate limiting with Lua script
- `oauth_endpoints.py`: OAuth 2.1 endpoint implementation
- `oauth_metadata.py`: OAuth metadata and scopes

### Request Routing
- Profile-based MCP instances (9 profiles)
- TrailingSlashMiddleware for path normalization
- Mount-based routing for profile-specific endpoints

---

## Critical File Locations

### Main Application
```
server.py (6364 lines)
├─ STDIO/HTTP mode switching: lines 189-211
├─ Context variables: lines 162-174
├─ Thread pool: line 160
├─ Profiles definition: lines 272-490
├─ get_auth_info(): lines 1052-1109
├─ get_sdk_from_context(): lines 1124-1232
├─ wrap_tool_for_multi_mode(): lines 588-782
├─ RequestContextMiddleware: lines 1236-1284
├─ Tool definitions: lines 1320+
└─ HTTP app setup: lines 6050-6270
```

### OAuth & Security
```
oauth_state_manager.py: OAuth state + tokens (Redis)
oauth_token_manager.py: Token validation + refresh with rotation
oauth_endpoints.py: OAuth 2.1 endpoints (/authorize, /token, /callback)
firebase_auth_bridge.py: Firebase Identity Platform integration
token_encryption.py: AES-256-GCM encryption for tokens at rest
rate_limiter.py: Per-IP rate limiting with sliding window
oauth_metadata.py: OAuth metadata + scopes
```

### Security Documentation
```
SECURITY_FIXES.md: 6 critical vulnerabilities resolved
SECURITY_FIX_OID_INHERITANCE.md: OID inheritance vulnerability fix
AUTHENTICATION.md: Authentication configuration guide
```

---

## Architecture Patterns

### 1. Request-Scoped SDK (Request Isolation)
```python
# Per-request instance, not cached
sdk = limacharlie.Manager(oid, secret_api_key=api_key)
try:
    # Use for this request only
    result = sdk.sensor(sid).simpleRequest(cmd)
finally:
    sdk.shutdown()  # Always clean up
```

### 2. Contextvars for Thread-Safe Isolation
```python
request_context_var: ContextVar[Request]     # HTTP request
sdk_context_var: ContextVar[Manager]         # Current SDK
uid_auth_context_var: ContextVar[tuple]      # Auth context (uid, key, mode, creds)
```

### 3. Tool Wrapper with Validation
```python
@wrap_tool_for_multi_mode(requires_oid=True)  # Adds oid parameter
def tool_function(param1, param2, oid, ctx):  # oid injected by wrapper
    # Wrapper validates oid in UID mode
    # Wrapper creates SDK
    # Wrapper stores SDK in context
    pass
```

### 4. Middleware for Request Lifecycle
```python
RequestContextMiddleware:
├─ On entry: reset contextvars
├─ Extract auth headers
├─ Create/set up SDK
├─ Route to tool
└─ On exit: shutdown SDK, reset contextvars
```

---

## Deployment Models

### STDIO Mode (Local)
```
Claude Desktop/Code
    ↓ stdin: JSON-RPC
MCP Server
    ├─ Load credentials from environment/config
    ├─ Create SDK once
    ├─ Tool calls use shared SDK
    └─ stdout: JSON-RPC response
```

### HTTP Mode (Public)
```
Client (HTTP Request)
    ↓ Authorization header
Uvicorn + Starlette
    ├─ RequestContextMiddleware
    ├─ Extract and validate auth
    ├─ Route to Profile MCP
    ├─ Tool wrapper validates OID
    ├─ Tool executes with SDK
    ├─ GCS upload if large
    └─ HTTP Response

Redis
    ├─ OAuth state (encrypted)
    ├─ Access tokens (encrypted)
    ├─ Refresh tokens (encrypted)
    └─ Rate limit counters
```

---

## Security Guarantees

### Multi-Tenant Isolation
- [x] Each tool call requires explicit OID parameter
- [x] SDK created per-request (not shared)
- [x] No inheritance from context (forces explicit passing)
- [x] Credentials passed explicitly (no globals)

### Token Protection
- [x] All tokens encrypted in Redis (AES-256-GCM)
- [x] Refresh token rotation on each use
- [x] Authorization codes deleted immediately after exchange
- [x] Firebase ID tokens verified by Firebase SDK
- [x] Auto-refresh if expiring soon (< 5 min)

### DoS Prevention
- [x] Per-IP rate limiting on OAuth endpoints
- [x] Redis-backed sliding window (atomic Lua script)
- [x] Different limits per endpoint
- [x] 429 responses with Retry-After header

### Access Control
- [x] Profile-based tool filtering
- [x] PKCE for authorization code flow
- [x] State CSRF protection (10 min TTL)
- [x] No OAuth discovery headers on 401

---

## Configuration Best Practices

### Production Deployment
```bash
# Encryption
export REDIS_ENCRYPTION_KEY="<base64-256-bit-key>"

# Session storage
export REDIS_URL="redis://redis:6379"

# OAuth (multi-user)
export MCP_OAUTH_ENABLED="true"
export OAUTH_SERVER_URL="https://mcp.example.com"

# Large results
export GCS_BUCKET_NAME="your-bucket"
export GCS_TOKEN_THRESHOLD="1000"

# Tool profiles
export MCP_PROFILE="all"

# Server
export PUBLIC_MODE="true"
```

### Key Rotation Strategy
1. Generate new key: `python -c 'import os,base64; print(base64.b64encode(os.urandom(32)).decode())'`
2. Update `REDIS_ENCRYPTION_KEY`
3. Old tokens with old key can't be decrypted (will fail gracefully)
4. New tokens use new key
5. Plan token expiry (refresh tokens rotate every 30 days)

---

## Next Steps for Development

1. **Token Key Rotation Strategy**
   - Implement key versioning in encrypted tokens
   - Allow decryption with multiple keys during rotation period
   - Automatic key rollover after expiry

2. **Audit Logging**
   - Add structured logging for security events
   - Track token usage, token refresh, rate limit violations
   - Implement log ingestion (CloudLogging, Splunk, etc.)

3. **Tenant Isolation Verification**
   - Add integration tests for cross-tenant scenarios
   - Verify each profile has correct tool access
   - Test UID mode OID parameter enforcement

4. **Performance Optimization**
   - Monitor thread pool utilization
   - Consider connection pooling for Redis
   - Benchmark SDK creation overhead

5. **Operational Improvements**
   - Implement metrics endpoint (token count, request latency)
   - Add health checks for Redis, GCS
   - Create runbook for emergency key rotation

---

## Testing Coverage

### Test Files Reviewed
- `test_uid_mode.py`: UID mode functionality and isolation
- `test_server.py`: Server basics and auth
- `test_security_fixes.py`: Security vulnerability fixes
- `test_critical_fixes.py`: Critical security tests
- Additional: OAuth integration, deployment, nested calls

### Security Tests
- Context isolation under concurrent load
- Cross-tenant boundary enforcement
- Token encryption/decryption
- Refresh token rotation
- Rate limiting effectiveness
- PKCE validation

---

## Repository Status

- **Branch**: multi-org (active development)
- **Recent Commits**: 05960d8 (Fix), 1efcb57 (Pass oid clearly), ebe1bbb (Fix dockerfile)
- **Outstanding Changes**: FIXES_APPLIED.md, SECURITY_FIXES.md, SECURITY_FIX_OID_INHERITANCE.md, verify_docker_includes.py

---

## Resources

### Documentation Files
- `/ARCHITECTURE_AND_SECURITY_ANALYSIS.md` - Complete architectural analysis
- `/QUICK_REFERENCE.md` - Developer quick reference
- `/SECURITY_FIXES.md` - Security vulnerabilities and fixes
- `/SECURITY_FIX_OID_INHERITANCE.md` - OID inheritance fix details
- `/AUTHENTICATION.md` - Authentication setup guide
- `/OAUTH_MCP_GUIDE.md` - OAuth flow documentation

### Key Functions by Purpose

**Authentication**
- `get_auth_info(request)` - Extract auth from HTTP headers
- `get_sdk_from_context(ctx)` - Get/create SDK for request
- `get_uid_from_environment()` - Load UID from env/config
- `get_auth_from_sdk_config()` - Load from ~/.limacharlie

**Tool Wrapping**
- `wrap_tool_for_multi_mode()` - Add oid param, validate auth
- `mcp_tool_with_gcs()` - GCS + multi-mode decorator
- `create_mcp_for_profile()` - Create profile-filtered MCP

**Credential Management**
- `make_sdk()` - Create Manager instance
- `RequestContextMiddleware` - Request isolation

---

**Created**: 2025-10-26  
**Explorer**: Claude Code Analysis  
**Completeness**: Comprehensive (architecture, auth, sessions, storage, security)
