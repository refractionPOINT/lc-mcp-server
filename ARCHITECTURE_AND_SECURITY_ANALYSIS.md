# LimaCharlie MCP Server - Architecture & Security Analysis

## Executive Summary

This is a **Model Context Protocol (MCP) server** that exposes the LimaCharlie security platform to AI agents. The server supports two deployment modes (STDIO for local use and HTTP for public services), with sophisticated multi-tenant OAuth 2.1 authentication, comprehensive security controls, and context-based user isolation.

**Key Architecture**: Request-scoped SDK instances, contextvars-based request isolation, Redis-backed session management, and explicit credential passing to prevent cross-tenant contamination.

---

## 1. Overall Architecture and Entry Points

### Deployment Modes

#### STDIO Mode (Default - LOCAL)
- **Purpose**: Local development, Claude Desktop/Code integration
- **Entry Point**: `__main__` block in `server.py:6280-6357`
- **Authentication**: Environment variables (`LC_OID`, `LC_API_KEY`, `LC_UID`)
- **Flow**:
  1. Check for UID mode (multi-org) via `get_uid_from_environment()`
  2. Load auth credentials from environment or `~/.limacharlie` config
  3. Create MCP instance for selected profile
  4. Run via `mcp.run(transport="stdio")`

#### HTTP Mode (PUBLIC_MODE=true)
- **Purpose**: Deployed public service (mcp.limacharlie.io)
- **Entry Point**: Uvicorn runs `app` variable (Starlette application)
- **Location**: `server.py:6050-6270`
- **Authentication**: HTTP headers (`Authorization`, `x-lc-oid`, `x-lc-uid`)
- **Components**:
  - Profile-specific MCP instances mounted as Starlette routes
  - OAuth 2.1 endpoints (if `MCP_OAUTH_ENABLED=true`)
  - RequestContextMiddleware for request isolation

### Thread Pool Architecture

```python
SDK_THREAD_POOL = ThreadPoolExecutor(max_workers=100, thread_name_prefix="sdk-worker")
```
- **Purpose**: Prevents thread pool exhaustion for concurrent SDK calls
- **Usage**: Large result uploads to GCS, tool execution
- **Cleanup**: Registered with `atexit.register(cleanup_thread_pool)`

---

## 2. Authentication and Authorization Mechanisms

### Three Authentication Modes

#### Mode 1: Normal Mode (Single Organization)
- **Environment**: `LC_OID` (organization ID) + `LC_API_KEY` (or JWT)
- **HTTP Headers**: `Authorization: Bearer <jwt|api_key>:<oid>` OR `x-lc-oid: <oid>`
- **SDK Creation**: `limacharlie.Manager(oid, jwt=token, secret_api_key=api_key)`
- **Use Case**: Single org clients, direct API access
- **Location**: `server.py:1111-1121` (make_sdk function)

#### Mode 2: UID Mode with API Key (Multi-Organization)
- **Environment**: `LC_UID` + `LC_API_KEY`
- **HTTP Header**: `Authorization: Bearer <api_key>` + `x-lc-uid: <uid>`
- **Tool Parameter**: Each tool requires explicit `oid` parameter
- **SDK Creation per Tool**: `limacharlie.Manager(oid, secret_api_key=api_key)`
- **Context Storage**: `uid_auth_context_var.set((uid, api_key, "api_key", None))`

#### Mode 3: UID Mode with OAuth (Multi-Organization - RECOMMENDED)
- **Environment**: `LC_UID` (+ `LC_CURRENT_ENV` for environment selection)
- **Credentials**: Loaded from `~/.limacharlie` JSON file
- **SDK Creation**: `limacharlie.Manager(oid=oid, oauth_creds=oauth_creds)`
- **Context Storage**: `uid_auth_context_var.set((uid, None, "oauth", oauth_creds))`
- **Token Refresh**: Automatic JWT renewal by SDK
- **Location**: `server.py:6300-6333` (STDIO mode initialization)

### Context Variables (Request Isolation)

Three contextvars provide per-request isolation:

```python
request_context_var: ContextVar              # HTTP Request object
sdk_context_var: ContextVar[Manager | None]  # SDK instance
uid_auth_context_var: ContextVar[tuple]      # (uid, api_key, mode, oauth_creds)
current_oid_context_var: ContextVar[str]     # Current OID for nested calls
```

**Isolation Mechanism**:
- Each HTTP request resets all contextvars via `RequestContextMiddleware`
- SDK created per-request and shutdown after response
- OAuth credentials stored in context, NOT global variables

### HTTP Authentication Flow

**Location**: `server.py:1052-1109` (get_auth_info function)

1. Extract `Authorization: Bearer` header
2. Check for UID mode via `x-lc-uid` header
   - If present: validate API key format (UUID) → UID mode
   - If absent: check for `x-lc-oid` or `:oid` suffix → Normal mode
3. Parse credentials:
   - Format `jwt:oid` → JWT + OID
   - Format `api_key:oid` → API key + OID (UUID format)
   - Format `jwt` (x-lc-oid header) → JWT only

**Security**: No WWW-Authenticate headers in 401 responses to prevent OAuth discovery attempts.

### OAuth 2.1 Integration (Optional)

**Enabled via**: `MCP_OAUTH_ENABLED=true` + OAuth modules
**Components**:
- `FirebaseAuthBridge`: OAuth flow via Firebase Identity Platform
- `OAuthStateManager`: Redis-backed state management
- `OAuthTokenManager`: Token validation and refresh
- `OAuthEndpoints`: OAuth 2.1 protocol implementation

**Token Flow**:
1. Client requests `/authorize` with PKCE code_challenge
2. FirebaseAuthBridge returns Google OAuth URL
3. User authenticates with Google
4. Callback redirected to `/oauth/callback`
5. Token endpoint issues MCP access token + refresh token
6. Both stored encrypted in Redis with TTLs

---

## 3. User Credentials Storage and Management

### Storage Locations

#### Environment Variables (STDIO Mode)
```bash
LC_OID              # Organization ID
LC_API_KEY          # API Key (UUID format) OR JWT token
LC_UID              # User ID (enables UID mode)
LC_CURRENT_ENV      # Environment name in ~/.limacharlie (default: "default")
GOOGLE_API_KEY      # For AI-powered features
```

#### SDK Config File (~/.limacharlie)
**Format**: JSON with per-environment OAuth + API credentials
```json
{
  "default": {
    "oid": "org-id",
    "uid": "user-id",
    "api_key": "...",
    "oauth": {
      "id_token": "...",
      "refresh_token": "...",
      "expires_at": 1234567890,
      "provider": "google"
    }
  }
}
```
**Loading**: `get_auth_from_sdk_config()` in `server.py:927-967`

#### Redis (OAuth State)
**Encryption**: AES-256-GCM when `REDIS_ENCRYPTION_KEY` is set
**Stored Data**:
- OAuth state (10 min TTL)
- Authorization codes (5 min TTL)
- Access tokens (1 hour TTL)
- Refresh tokens (30 day TTL)

**Key Structure**:
```python
STATE_PREFIX = "oauth:state:"        # Encrypted state data
CODE_PREFIX = "oauth:code:"          # Encrypted auth codes
TOKEN_PREFIX = "oauth:token:"        # Encrypted access tokens
REFRESH_PREFIX = "oauth:refresh:"    # Encrypted refresh tokens
```

### Credential Handling in Tools

**Location**: `server.py:588-782` (wrap_tool_for_multi_mode wrapper)

**Key Security Pattern**:
1. Extract `oid` parameter from kwargs (NEVER from context fallback)
2. Validate mode (UID vs Normal)
3. Create SDK with explicit credentials
4. Store SDK in `sdk_context_var`
5. Execute tool
6. Shutdown SDK
7. Reset contextvars

```python
# SECURE: Explicit credential passing
if mode == "oauth":
    sdk = limacharlie.Manager(oid=oid, oauth_creds=oauth_creds)
else:
    sdk = limacharlie.Manager(oid, secret_api_key=api_key)
```

---

## 4. Session Management Approach

### Request Lifecycle (HTTP Mode)

**RequestContextMiddleware** (lines 1236-1284):
```
1. ASGI Request arrives
   ├─ Store Request in request_context_var
   ├─ Reset sdk_context_var to None
   └─ Reset uid_auth_context_var to None
   
2. Extract Auth Headers
   ├─ get_auth_info() parses Authorization header
   └─ get_sdk_from_context() creates SDK or sets UID mode
   
3. Tool Execution
   ├─ Wrapper reads oid parameter
   ├─ Creates SDK (if UID mode) or uses existing
   ├─ Stores SDK in sdk_context_var
   ├─ Executes tool function
   └─ Returns result
   
4. Cleanup (finally block)
   ├─ Shutdown SDK if exists
   ├─ Reset all contextvars
   └─ Response sent
```

### Session Isolation Guarantees

**Per-Request Isolation**:
- Each HTTP request gets fresh contextvar state
- Middleware resets all three contextvars on entry
- Cleanup in finally block ensures no leakage

**Per-Tenant Isolation (UID Mode)**:
- Each tool call creates new SDK instance
- OID parameter explicitly passed (never inherited)
- Credentials in context, not globals

**No Global State**:
- `limacharlie.GLOBAL_OAUTH` NOT used (explicit credentials passed)
- Thread pool is stateless (just execute and return)
- Redis is per-request (state TTLs ensure cleanup)

### Token Refresh Strategy

**OAuth Mode**:
- JWT refresh happens automatically by SDK
- `LC_CURRENT_ENV` determines which environment's credentials to use
- Credentials loaded once at startup for STDIO mode

**API Key Mode**:
- No token refresh (API keys don't expire)
- New API key required for reauthentication

**Access Token Refresh** (OAuth endpoints):
- `/token` endpoint with `refresh_token` grant
- **Refresh Token Rotation**: Old token revoked, new one issued (detects theft)
- **Token Validation**: `oauth_token_manager.validate_access_token()` checks Redis
- **Auto-Refresh**: If Firebase token < 5 min to expiry, refresh automatically

---

## 5. Shared State and Global Variables

### Safe Global State (STATELESS)

```python
# Safe - configuration only
PUBLIC_MODE = os.getenv("PUBLIC_MODE", "false").lower() == "true"
MCP_PROFILE = os.getenv("MCP_PROFILE", "all").lower()
GCS_BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")

# Safe - tool registry (immutable after registration)
TOOL_REGISTRY: dict[str, tuple[Any, bool]] = {}

# Safe - thread pool (stateless)
SDK_THREAD_POOL = ThreadPoolExecutor(max_workers=100)
```

### UNSAFE Global State (REMOVED)

**Removed in Security Fix #1** (SECURITY_FIXES.md):
```python
# VULNERABLE (REMOVED)
limacharlie.GLOBAL_OAUTH = oauth_creds  # Race condition!
```
**Reason**: In concurrent requests, User A's credentials could leak to User B

### Request-Scoped State (SAFE)

All request-specific data in contextvars:
```python
request_context_var: ContextVar[Request]           # Per-request HTTP request
sdk_context_var: ContextVar[Manager | None]        # Per-request SDK instance
uid_auth_context_var: ContextVar[tuple | None]     # Per-request auth context
current_oid_context_var: ContextVar[str | None]    # Per-request OID
```

**Protection Mechanism**: Python's `contextvars` is thread-safe and task-local in async contexts.

---

## 6. Database and Storage Access Patterns

### Redis (Session & OAuth State)

**Location**: `oauth_state_manager.py:128-150`

**Connection**:
```python
self.redis_client = redis.from_url(
    self.redis_url or "redis://localhost:6379",
    decode_responses=True,
    socket_keepalive=True
)
```

**Data Stored**:
1. **OAuth States** (CSRF protection)
   - Key: `oauth:state:<state_value>`
   - TTL: 600 seconds (10 minutes)
   - Data: code_challenge, redirect_uri, client_id, scope

2. **Authorization Codes** (single-use)
   - Key: `oauth:code:<code_value>`
   - TTL: 300 seconds (5 minutes)
   - Data: uid, firebase_id_token (ENCRYPTED), firebase_refresh_token (ENCRYPTED)
   - **Atomic Deletion**: Code deleted immediately after use (TOCTOU protection)

3. **Access Tokens** (session tokens)
   - Key: `oauth:token:<access_token>`
   - TTL: 3600 seconds (1 hour)
   - Data: uid, firebase_id_token (ENCRYPTED), firebase_refresh_token (ENCRYPTED)

4. **Refresh Tokens** (long-lived)
   - Key: `oauth:refresh:<refresh_token>`
   - TTL: 2592000 seconds (30 days)
   - Data: access_token, uid, firebase_refresh_token (ENCRYPTED)
   - **Rotation**: Each use generates NEW refresh token, revokes old one

### Encryption at Rest (Redis)

**Location**: `token_encryption.py`

**Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Size**: 256 bits (32 bytes)
- **Nonce**: 96 bits, unique per encryption
- **Auth Tag**: 128 bits, detects tampering
- **Encoding**: Base64 for Redis storage

**Key Management**:
- Environment variable: `REDIS_ENCRYPTION_KEY` (base64-encoded)
- Generation: `python -c 'import os,base64; print(base64.b64encode(os.urandom(32)).decode())'`
- Recommended: Store in secret management system (Google Secret Manager, AWS KMS)

**Protected Fields**:
- `firebase_id_token` (user identity token)
- `firebase_refresh_token` (long-lived credential)
- All stored in authorization codes, access tokens, refresh tokens

### Google Cloud Storage (Large Results)

**Location**: `server.py:515-586` (upload_to_gcs function)

**When Used**:
- Token count > `GCS_TOKEN_THRESHOLD` (default: 1000)
- Fallback: Temp files if GCS not configured

**Upload Process**:
1. Estimate token count via JSON serialization
2. Create temporary file or GCS blob
3. Upload with `content_type='application/json'`
4. Generate signed URL with 24-hour expiry

**Security**:
- Service account authentication via `google.auth.default()`
- Signed URLs expire after `GCS_URL_EXPIRY_HOURS` (default: 24)
- Results returned as `resource_link` instead of inline

### LimaCharlie SDK Access

**Pattern**: Request-scoped Manager instances

```python
# Each tool execution:
sdk = limacharlie.Manager(oid, secret_api_key=api_key)
try:
    # Use SDK
    sensor = sdk.sensor(sid)
    result = sensor.simpleRequest(cmd)
finally:
    sdk.shutdown()
```

**No Caching**: Each request creates fresh SDK instance
- Ensures latest credentials
- Prevents stale auth state
- Automatic cleanup via `shutdown()`

**Async Support**: 
- SDK calls wrapped in thread pool to avoid blocking
- `loop.run_in_executor(SDK_THREAD_POOL, func, args)`
- Allows multiple concurrent requests

---

## 7. Critical Security Controls

### Multi-Tenant Isolation

**Principle**: Explicit over implicit

**Enforcement Mechanisms**:

1. **OID Parameter Requirement**
   - Location: `wrap_tool_for_multi_mode()` lines 653-659, 725-731
   - UID mode tools MUST have `oid` parameter
   - Raises `ValueError` if missing
   - No inheritance from context

2. **SDK Per-Request Creation**
   - Line 664, 668: Create new SDK per tool call
   - Prevents auth context leakage
   - Ensures isolated database access

3. **No OID Inheritance**
   - SECURITY_FIX_OID_INHERITANCE.md
   - Removed: `oid = kwargs.pop('oid', None) or current_oid_context_var.get()`
   - Changed to: `oid = kwargs.pop('oid', None)`
   - Forces explicit parameter passing in nested calls

### Token Security

**Encryption**:
- All tokens encrypted in Redis with AES-256-GCM
- Enabled via `REDIS_ENCRYPTION_KEY` environment variable
- Fallback: Works unencrypted (with warning)

**Refresh Token Rotation**:
- Each `/token` endpoint call with refresh_token:
  1. Validate refresh token exists
  2. Create NEW refresh token
  3. Revoke OLD refresh token
  4. Detects theft attempts (using revoked token = suspicious)

**Authorization Code TOCTOU Fix**:
- Location: `oauth_endpoints.py:260-280` (handle_oauth_callback)
- Atomic deletion in Redis: code removed immediately after use
- Prevents replay attacks

**JWT Verification**:
- Firebase ID tokens verified by Firebase library
- Prevents token forgery

### Rate Limiting (DoS Protection)

**Location**: `rate_limiter.py:20-232`

**Mechanism**: Redis-backed sliding window per IP

**Limits** (per minute):
- `/authorize`: 10 requests
- `/oauth/callback`: 10 requests
- `/token`: 20 requests
- `/register`: 5 requests
- `/revoke`: 10 requests
- `/introspect`: 30 requests

**Implementation**:
- Lua script for atomic check + increment
- Extracts client IP from X-Forwarded-For or direct connection
- Returns 429 Too Many Requests with Retry-After header

### Profile-Based Access Control

**Purpose**: Restrict tools available to client

**Definition**: `server.py:272-490` (PROFILES dict)

**Profiles**:
- `core`: 6 essential tools (included in all)
- `all`: 100+ tools (default)
- `historical_data`: Historical analysis (read-only variant available)
- `live_investigation`: Real-time forensics
- `threat_response`: Incident response actions
- `fleet_management`: Sensor management
- `detection_engineering`: Detection development
- `ai_powered`: AI content generation
- `platform_admin`: Configuration management

**Enforcement**: Tools registered based on selected profile only

### Logging & Auditing

**Security Consideration**: Sensitive data exclusion
- Tokens logged at DEBUG level only
- Full values never logged (first 10 chars + last 4 for brevity)
- OAuth states truncated: `"...{state[:8]}...{state[-4:]}"`

**Location**: Multiple DEBUG statements throughout oauth_*.py

---

## 8. Request Routing and Context Management

### Profile Routing (HTTP Mode)

**Mounted Endpoints**:
```python
/              → Health check + profile listing
/mcp/          → "all" profile (100+ tools) 
/{profile}/    → Specific profile (historical_data, live_investigation, etc.)

# OAuth endpoints (if MCP_OAUTH_ENABLED):
/authorize                              → OAuth authorize endpoint
/oauth/callback                         → OAuth callback handler
/token                                  → OAuth token endpoint
/register                               → Dynamic client registration
/revoke                                 → Token revocation
/introspect                             → Token introspection
/.well-known/oauth-protected-resource   → OAuth metadata
/.well-known/oauth-authorization-server → Authorization server metadata
```

**Router Implementation**:
- Starlette Mount for profile MCPs
- TrailingSlashMiddleware for path normalization
- Routes created dynamically based on `available_profiles`

### Tool Function Flow

**Step 1: Tool Registration**
- Location: `mcp_tool_with_gcs()` decorator (lines 783-886)
- Stores function in `TOOL_REGISTRY` (not immediately registered)
- Applies GCS wrapper and multi-mode wrapper

**Step 2: Profile-Based Filtering**
- Location: `create_mcp_for_profile()` (lines 888-925)
- Creates MCP instance for selected profile
- Registers only tools in `get_profile_tools(profile_name)`
- Others remain unavailable

**Step 3: Request Arrives**
- RequestContextMiddleware captures HTTP request
- Extracts auth headers
- Calls `get_sdk_from_context()` to create/set up SDK

**Step 4: Tool Wrapper Executes**
- Wrapper added by `wrap_tool_for_multi_mode()` runs first
- Validates `oid` parameter (if UID mode)
- Creates new SDK with credentials
- Stores in `sdk_context_var`
- Calls actual tool function

**Step 5: Tool Function Uses Context**
- Calls `get_sdk_from_context(ctx)` to retrieve SDK
- Makes API calls via SDK
- Returns result

**Step 6: GCS Wrapper Handles Result**
- Estimates token count
- If > threshold: uploads to GCS, returns signed URL
- Else: returns result inline

**Step 7: Cleanup**
- Middleware finally block:
  - Shuts down SDK
  - Resets all contextvars
  - Response sent to client

---

## 9. Data Flow Diagrams

### STDIO Mode (Local)
```
Claude Desktop/Code
        │
        ├─ stdin: JSON-RPC
        │
    MCP Server (STDIO)
        │
        ├─ Load LC_OID, LC_API_KEY from env
        ├─ Create limacharlie.Manager(oid, api_key=key)
        ├─ Call tool function
        └─ SDK makes API calls
        │
        └─ stdout: JSON-RPC response
```

### HTTP Mode (Public)
```
Client (curl/Claude)
        │
        ├─ HTTP: Authorization: Bearer <jwt|api_key>:<oid>
        ├─ x-lc-oid: <oid>  OR  x-lc-uid: <uid>
        │
    Uvicorn + Starlette
        │
        ├─ RequestContextMiddleware
        │  ├─ Store Request in request_context_var
        │  └─ Reset sdk_context_var, uid_auth_context_var
        │
        ├─ get_auth_info() → Extract credentials
        ├─ get_sdk_from_context() → Create SDK or set UID mode
        │
        ├─ Route to Profile MCP
        │  └─ Invoke tool function
        │
        ├─ Wrapper: Create SDK (if UID) / Get SDK (if normal)
        │
        ├─ Tool: Call get_sdk_from_context(ctx)
        │  └─ limacharlie.Manager makes API calls
        │
        ├─ GCS: Check token count
        │  ├─ Large: Upload to GCS → return signed URL
        │  └─ Small: Return inline
        │
        └─ Cleanup: SDK.shutdown(), reset contextvars
        │
        └─ HTTP 200: JSON response
```

### OAuth 2.1 Flow (if MCP_OAUTH_ENABLED)
```
Client App
    │
    ├─ GET /authorize?code_challenge=...&state=...
    │
    └─ OAuthEndpoints.handle_authorize()
       ├─ Validate PKCE, state, redirect_uri
       ├─ Store OAuth state in Redis (10 min TTL)
       ├─ Call FirebaseAuthBridge.create_auth_uri()
       │  └─ Firebase returns Google OAuth URL
       ├─ Store firebase_state ↔ oauth_state mapping
       └─ Redirect to Google OAuth URL
    
Google OAuth
    │
    └─ User authenticates → redirects back
    
Client receives Google auth code
    │
    └─ Redirect to /oauth/callback?code=...&state=...
    
OAuthEndpoints.handle_oauth_callback()
    ├─ Validate state in Redis
    ├─ Exchange Firebase session_id + auth code
    └─ FirebaseAuthBridge.signInWithIdp()
       ├─ Returns Firebase ID token + refresh token
       └─ Store in authorization code (Redis, 5 min TTL)
    
Client exchanges authorization code for access token
    │
    └─ POST /token (grant_type=authorization_code, code=..., code_verifier=...)
    
OAuthEndpoints.handle_token()
    ├─ Validate PKCE: code_verifier matches code_challenge
    ├─ Delete authorization code from Redis (atomic)
    ├─ Generate MCP access token
    ├─ Generate MCP refresh token (NEW)
    ├─ Store access_token → firebase_id_token (encrypted)
    ├─ Store refresh_token → firebase_refresh_token (encrypted)
    └─ Return { access_token, refresh_token, expires_in }
    
Client uses access token
    │
    └─ GET /mcp/list_sensors
       Authorization: Bearer <access_token>
    
MCP Server
    ├─ oauth_token_manager.validate_access_token()
    │  ├─ Look up access_token in Redis
    │  ├─ Check if Firebase token needs refresh (< 5 min to expiry)
    │  └─ Auto-refresh if needed
    ├─ Extract uid, firebase_id_token
    ├─ Create SDK with oauth_creds
    └─ Execute tool
    
Refresh Token Usage
    │
    └─ POST /token (grant_type=refresh_token, refresh_token=...)
    
OAuthTokenManager.refresh_access_token()
    ├─ Look up refresh_token in Redis
    ├─ Refresh Firebase token via FirebaseAuthBridge
    ├─ Generate NEW access_token
    ├─ Generate NEW refresh_token (rotation!)
    ├─ Revoke OLD refresh_token
    └─ Return { new_access_token, new_refresh_token }
```

---

## 10. Summary of Key Findings

### Strengths

1. **Multi-Tenant Isolation**: Explicit OID parameters, no inheritance, request-scoped SDK
2. **Context-Based Security**: Using Python contextvars for thread-safe request isolation
3. **Token Encryption**: AES-256-GCM encryption at rest in Redis
4. **Refresh Token Rotation**: Detects theft attempts via reuse detection
5. **Rate Limiting**: Per-IP DoS protection on OAuth endpoints
6. **PKCE Implementation**: Prevents authorization code interception
7. **TOCTOU Protection**: Atomic Redis operations for authorization codes
8. **No Global State**: Removed GLOBAL_OAUTH, credentials passed explicitly
9. **Profile-Based RBAC**: Tools available based on selected profile
10. **Comprehensive Logging**: Sensitive data excluded from logs

### Critical Security Fixes Applied

1. **Global OAuth Race Condition** (CRITICAL) - Fixed by explicit credential passing
2. **Plaintext Tokens in Redis** (CRITICAL) - Fixed by AES-256-GCM encryption
3. **Authorization Code Replay** (CRITICAL) - Fixed by atomic deletion
4. **Sensitive Data Logging** (CRITICAL) - Fixed by excluding from ERROR logs
5. **Missing Token Rotation** (CRITICAL) - Fixed by refresh token rotation
6. **No JWT Verification** (CRITICAL) - Fixed via Firebase verification
7. **OID Inheritance Bug** (HIGH) - Fixed by removing context fallback

### Deployment Recommendations

1. **Always set `REDIS_ENCRYPTION_KEY`** in production
2. **Use OAuth mode** (`LC_UID` + `~/.limacharlie`) instead of API keys
3. **Rotate `REDIS_ENCRYPTION_KEY`** periodically
4. **Monitor rate limit headers** for abuse attempts
5. **Use reverse proxy** with X-Forwarded-For headers
6. **Set `PUBLIC_MODE=true`** only for HTTP deployment
7. **Configure `GCS_BUCKET_NAME`** for large result handling
8. **Enable `MCP_OAUTH_ENABLED`** for public multi-user scenarios

---

## File Index

### Core Application
- `server.py` - Main MCP server (6364 lines)
  - STDIO/HTTP mode switching
  - Authentication handling
  - Context management
  - Tool definitions and wrappers

### OAuth & Security
- `oauth_state_manager.py` - Redis session management
- `oauth_token_manager.py` - Token validation and refresh
- `oauth_endpoints.py` - OAuth 2.1 protocol endpoints
- `oauth_metadata.py` - OAuth metadata provider
- `firebase_auth_bridge.py` - Firebase authentication bridge
- `token_encryption.py` - AES-256-GCM encryption
- `rate_limiter.py` - Rate limiting for DoS protection

### Testing & Documentation
- `test_uid_mode.py` - Multi-org mode tests
- `test_server.py` - Server functionality tests
- `test_security_fixes.py` - Security fix verification
- `test_critical_fixes.py` - Critical vulnerability tests
- `SECURITY_FIXES.md` - Security vulnerability documentation
- `SECURITY_FIX_OID_INHERITANCE.md` - OID inheritance fix
- `AUTHENTICATION.md` - Auth configuration guide
- `OAUTH_MCP_GUIDE.md` - OAuth flow documentation

### Configuration
- `requirements.txt` - Python dependencies
- `Dockerfile` - Container image definition
- `docker-compose.yml` - Local deployment
- `.claude/CLAUDE.md` - User instructions

