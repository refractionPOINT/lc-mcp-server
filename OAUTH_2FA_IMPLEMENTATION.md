# OAuth 2FA Implementation Guide

## Overview

This document describes the OAuth 2.1 with PKCE implementation in the LimaCharlie MCP Server, specifically focusing on how Multi-Factor Authentication (MFA) is handled when users authenticate with Google accounts that have 2FA enabled.

## Architecture

### Two Layers of Authentication

The system handles two distinct authentication layers:

1. **Google 2FA** (Provider-level)
   - Handled transparently by Google during OAuth flow
   - User completes Google's 2FA challenge before OAuth callback
   - No special handling required by our application

2. **Firebase MFA** (Application-level)
   - TOTP-based challenge presented by our application
   - Triggered after successful OAuth callback if user has Firebase MFA enabled
   - Requires explicit handling in our OAuth flow

## Authentication Flow

### Standard OAuth Flow (No MFA)

```
1. Client initiates OAuth → /oauth/authorize
2. Server redirects to Google OAuth
3. User authenticates with Google (may include Google 2FA)
4. Google redirects to /oauth/callback with authorization code
5. Server exchanges code with Firebase signInWithIdp
6. Firebase returns idToken + refreshToken
7. Server generates authorization code for client
8. Client exchanges code for access token
```

### OAuth Flow with Firebase MFA

```
1-4. Same as standard flow
5. Server exchanges code with Firebase signInWithIdp
6. Firebase returns MFA challenge (NO idToken/refreshToken)
7. Server stores MFA session in Redis
8. Server redirects to /mfa.html with session_id
9. User enters TOTP code
10. Client POSTs to /oauth/mfa/verify
11. Server calls Firebase finalizeMfaSignIn
12. Firebase returns idToken + refreshToken
13. Server generates authorization code for client
14. Client exchanges code for access token
```

## Key Components

### 1. Firebase Auth Bridge (firebase_auth_bridge.py)

Interfaces with Firebase Identity Toolkit API.

**Important Fields:**

```python
@dataclass
class MfaResponse:
    mfa_pending_credential: str  # Required - MFA credential
    mfa_enrollment_id: str       # Required - Which MFA method to use
    display_name: str            # Required - User's name
    local_id: str                # Required - Firebase user ID
    email: str                   # Required - User's email
    pending_token: Optional[str] = None  # Optional - only for phone auth flows
```

**Critical Insight:** The `pending_token` field is ONLY returned for phone-based MFA flows. OAuth+TOTP flows do NOT include this field. This was the source of the original bug - treating it as required.

**Key Methods:**

- `sign_in_with_idp()` - Exchanges OAuth code with Firebase
- `finalize_mfa_sign_in()` - Completes MFA challenge with TOTP code
- `_is_mfa_required()` - Detects if Firebase is requesting MFA
- `_extract_mfa_response()` - Extracts MFA data from Firebase response

### 2. OAuth State Manager (oauth_state_manager.py)

Manages OAuth sessions in Redis.

**Session Types:**

```python
@dataclass
class OAuthSession:
    """OAuth authorization request session."""
    client_id: str
    redirect_uri: str
    code_challenge: str
    scope: str
    oid: Optional[str] = None

@dataclass
class MfaSession:
    """MFA challenge session - stored between MFA prompt and verification."""
    mfa_pending_credential: str
    mfa_enrollment_id: str
    oauth_state: str
    display_name: str
    local_id: str
    email: str
    attempt_count: int = 0
    pending_token: Optional[str] = None  # Optional for OAuth flows
```

**Storage Keys:**
- `oauth:state:{state}` - OAuth session (15 min TTL)
- `oauth:mfa:{session_id}` - MFA session (10 min TTL)
- `oauth:code:{code}` - Authorization code session (10 min TTL)

### 3. OAuth Endpoints (oauth_endpoints.py)

Implements OAuth 2.1 endpoints.

**Endpoints:**

- `GET /oauth/authorize` - Initiates OAuth flow
- `GET /oauth/callback` - Handles provider callback
- `POST /oauth/token` - Exchanges authorization code for access token
- `POST /oauth/mfa/verify` - Verifies TOTP code for MFA

**Query String Preservation:**

A critical detail for 2FA flows - the raw query string from the OAuth provider must be preserved exactly as received:

```python
# In server.py - callback handler
params = dict(request.query_params)
params['_raw_query_string'] = str(request.url.query)

# In oauth_endpoints.py - handle_oauth_callback
raw_query = params.pop('_raw_query_string', None)
if raw_query:
    callback_path = "?" + raw_query  # Use exact string from provider
else:
    callback_path = "?" + urllib.parse.urlencode(params)  # Fallback
```

This prevents re-encoding issues that can cause Firebase to reject the OAuth response.

### 4. CORS Configuration (server.py)

OAuth clients (especially localhost development clients) require CORS support:

```python
base_app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)
```

**Why regex instead of wildcard:**
- Cannot use `allow_origins=["*"]` with `allow_credentials=True`
- Browser security blocks this combination
- Regex pattern allows localhost on any port while maintaining credential support

## Error Handling

### Common Scenarios

1. **MFA Required**
   ```python
   raise FirebaseMfaRequiredError(mfa_response)
   ```
   Triggers redirect to MFA page.

2. **Account Linking Required**
   ```python
   raise FirebaseAuthError("Account linking required...")
   ```
   User tried to sign in with provider but account exists with different provider.

3. **Incomplete Flow**
   ```python
   raise FirebaseAuthError("Authentication flow incomplete...")
   ```
   Firebase returned unexpected state (e.g., pendingToken without full MFA data).

4. **Invalid TOTP Code**
   ```python
   raise FirebaseAuthError("Invalid verification code...")
   ```
   User entered wrong TOTP code during MFA challenge.

### Logging Strategy

The implementation uses extensive debug logging for troubleshooting:

```python
# Enable debug logs via environment variable
LOG_LEVEL=DEBUG

# Key log points:
logging.debug(f"signInWithIdp payload: requestUri={request_uri}...")
logging.debug(f"Firebase signInWithIdp response keys: {list(data.keys())}")
logging.debug(f"MFA extraction - pendingToken present: {bool(pending_token)} (optional)")
```

## Security Considerations

### PKCE (Proof Key for Code Exchange)

All OAuth flows use PKCE to prevent authorization code interception:

```python
# Client generates:
code_verifier = secrets.token_urlsafe(32)
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).decode().rstrip('=')

# Server validates during token exchange:
if generated_challenge != stored_challenge:
    raise ValueError("Invalid code_verifier")
```

### State Parameter

Prevents CSRF attacks:

```python
state = secrets.token_urlsafe(32)
# Stored in Redis, validated on callback
```

### Session Timeouts

- OAuth sessions: 15 minutes
- MFA sessions: 10 minutes
- Authorization codes: 10 minutes

### Rate Limiting

MFA verification is rate-limited to prevent brute force:

```python
MAX_MFA_ATTEMPTS = 5

if mfa_session.attempt_count >= MAX_MFA_ATTEMPTS:
    raise FirebaseAuthError("Too many failed attempts. Please restart login.")
```

## Testing

### Manual Testing with Google 2FA

1. **Setup:**
   - Create Google account with 2FA enabled
   - Enable Firebase MFA (TOTP) for the same account in Firebase console

2. **Test Flow:**
   ```bash
   # Start OAuth flow
   curl "http://localhost:8080/oauth/authorize?\
     client_id=your_client&\
     redirect_uri=http://localhost:3000/callback&\
     response_type=code&\
     scope=read:sensors&\
     code_challenge=CHALLENGE&\
     code_challenge_method=S256&\
     state=STATE"

   # Follow redirects through:
   # 1. Google OAuth consent
   # 2. Google 2FA prompt (if account has it)
   # 3. MFA TOTP page (if Firebase MFA enabled)
   # 4. Final redirect to client with code
   ```

3. **Verify Logs:**
   ```
   Firebase signInWithIdp response keys: ['mfaPendingCredential', 'mfaInfo', ...]
   MFA extraction - pendingToken present: False (optional)
   MFA required for user test@example.com
   ```

### Common Issues

**Issue:** "Incomplete MFA response, missing: pendingToken"
- **Cause:** Old code treated pendingToken as required
- **Fix:** Made pendingToken optional (only needed for phone auth)

**Issue:** CORS error on callback
- **Cause:** Missing CORS headers for localhost
- **Fix:** Added CORS middleware with localhost regex

**Issue:** Firebase rejects callback parameters
- **Cause:** Query string re-encoding changed parameter format
- **Fix:** Preserve raw query string from provider

## Configuration

### Environment Variables

```bash
# Required
FIREBASE_API_KEY=your_firebase_api_key
REDIS_HOST=localhost
REDIS_PORT=6379

# OAuth Configuration
OAUTH_PROVIDER_NAME=google
OAUTH_CLIENT_ID=your_google_client_id
OAUTH_CLIENT_SECRET=your_google_client_secret
OAUTH_AUTHORIZE_URL=https://accounts.google.com/o/oauth2/v2/auth
OAUTH_TOKEN_URL=https://oauth2.googleapis.com/token

# Optional
LOG_LEVEL=DEBUG  # Enable detailed logging
```

### Redis Requirements

Redis is required for:
- OAuth state management
- MFA session storage
- Authorization code storage

All use short TTLs (10-15 minutes) for security.

## Future Enhancements

Potential improvements:

1. **Multiple MFA Methods:** Support SMS, phone call, or hardware tokens
2. **Remember Device:** Allow users to skip MFA on trusted devices
3. **Backup Codes:** Provide recovery codes in case of lost TOTP device
4. **WebAuthn:** Support FIDO2/WebAuthn for passwordless MFA
5. **Audit Logging:** Track all authentication attempts for security monitoring

## References

- [OAuth 2.1 Specification](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [Firebase Identity Toolkit API](https://firebase.google.com/docs/reference/rest/auth)
- [Google OAuth 2.0](https://developers.google.com/identity/protocols/oauth2)
