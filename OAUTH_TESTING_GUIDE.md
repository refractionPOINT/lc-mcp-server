# OAuth Mode Manual Testing Guide

This guide provides step-by-step instructions for manually testing the OAuth authentication mode in STDIO mode.

## Prerequisites

1. **LimaCharlie Account**: Active LimaCharlie account with access to multiple organizations
2. **OAuth Credentials**: OAuth credentials configured in `~/.limacharlie` file
3. **Python Environment**: Python 3.11+ with required dependencies installed

## Setup OAuth Credentials

### Option 1: Using LimaCharlie CLI (Recommended)

The easiest way to set up OAuth credentials is using the official LimaCharlie CLI:

```bash
# Install the CLI if not already installed
pip3 install limacharlie

# Login using OAuth (this will open a browser for authentication)
limacharlie login

# Optionally create multiple environments
limacharlie login --environment production
limacharlie login --environment staging
```

This will create/update the `~/.limacharlie` file with OAuth credentials.

### Option 2: Manual Configuration

If you already have OAuth credentials, ensure your `~/.limacharlie` file is formatted like this:

```json
{
  "default": {
    "oid": "optional-default-org-id",
    "uid": "your-user-id",
    "oauth": {
      "refresh_token": "your-refresh-token",
      "api_key": "firebase-api-key",
      "id_token": "your-id-token",
      "expires_at": 1234567890,
      "provider": "firebase"
    }
  },
  "production": {
    "oid": "prod-org-id",
    "uid": "your-user-id",
    "oauth": { ... }
  }
}
```

## Manual Test Cases

### Test 1: OAuth Mode with Default Environment

**Setup:**
```bash
export LC_UID="your-user-id"
# Do NOT set LC_API_KEY
# Do NOT set LC_CURRENT_ENV (uses "default")
```

**Expected Behavior:**
- Server should detect OAuth credentials from `~/.limacharlie` default environment
- Server logs should show: "Found OAuth credentials in SDK config"
- All tools should accept the `oid` parameter
- Manager SDK should be created with only `oid` parameter (using GLOBAL_OAUTH)

**Test Command:**
```bash
# Start the server
python3 server.py

# In another terminal, test a tool call
# (This depends on your MCP client setup)
```

**Verification:**
- Check server logs for: `"OAuth mode: Creating SDK for oid=<org-id>"`
- Verify no errors about missing authentication
- Confirm tool calls succeed with different `oid` values

### Test 2: OAuth Mode with Custom Environment

**Setup:**
```bash
export LC_UID="your-user-id"
export LC_CURRENT_ENV="production"
# Do NOT set LC_API_KEY
```

**Expected Behavior:**
- Server should load OAuth credentials from "production" environment
- Server logs should show: "Loading credentials from SDK config environment: production"

**Verification:**
- Check server logs confirm "production" environment was used
- Verify authentication succeeds with production OAuth credentials

### Test 3: OAuth Precedence Over API Key

**Setup:**
```bash
export LC_UID="your-user-id"
export LC_API_KEY="some-api-key"
# OAuth credentials available in ~/.limacharlie
```

**Expected Behavior:**
- OAuth should take precedence over API key
- Server should use OAuth authentication, not the API key
- Server logs should show: "Found OAuth credentials in SDK config"

**Verification:**
- Check context variable is set to: `(uid, None, "oauth")`
- Verify API key is NOT used for authentication

### Test 4: API Key Fallback (No OAuth)

**Setup:**
```bash
export LC_UID="your-user-id"
export LC_API_KEY="valid-api-key"
# Temporarily rename ~/.limacharlie to prevent OAuth detection
mv ~/.limacharlie ~/.limacharlie.bak
```

**Expected Behavior:**
- Server should fall back to API key mode
- Server logs should show: "Found API key in SDK config" or use LC_API_KEY env var

**Verification:**
- Check context variable is set to: `(uid, "api-key", "api_key")`
- Verify tools work with API key authentication

**Cleanup:**
```bash
mv ~/.limacharlie.bak ~/.limacharlie
```

### Test 5: JWT Auto-Renewal

**Setup:**
```bash
export LC_UID="your-user-id"
# Use default OAuth credentials
```

**Test Procedure:**
1. Start the server with OAuth mode
2. Make tool calls over an extended period (30+ minutes)
3. Monitor for JWT token refresh operations

**Expected Behavior:**
- LimaCharlie SDK should automatically refresh JWT tokens before expiry
- No authentication failures should occur due to token expiration
- Tool calls should continue working seamlessly

**Verification:**
- Check for SDK log messages about token refresh
- Verify no "unauthorized" or "token expired" errors

### Test 6: Multi-Organization Operations

**Setup:**
```bash
export LC_UID="your-user-id"
# OAuth credentials configured
```

**Test Procedure:**
1. Make a tool call with `oid="org-1"`
2. Make a tool call with `oid="org-2"`
3. Make a tool call with `oid="org-3"`
4. Verify each call targets the correct organization

**Expected Behavior:**
- Each tool call should create an SDK for the specified OID
- Operations should be isolated per organization
- No cross-contamination between organizations

**Verification:**
- Check server logs show different OIDs being used
- Verify results are specific to each organization
- Confirm no permission errors for organizations you have access to

### Test 7: Error Handling - No OAuth, No API Key

**Setup:**
```bash
export LC_UID="your-user-id"
# Remove OAuth credentials
mv ~/.limacharlie ~/.limacharlie.bak
# Do NOT set LC_API_KEY
```

**Expected Behavior:**
- Server should detect missing credentials
- Should log an error or warning about missing authentication
- Context variable should be None or server should fail to initialize

**Verification:**
- Server should not start in an invalid authentication state
- Clear error message should indicate missing credentials

**Cleanup:**
```bash
mv ~/.limacharlie.bak ~/.limacharlie
```

### Test 8: Invalid Environment Name

**Setup:**
```bash
export LC_UID="your-user-id"
export LC_CURRENT_ENV="nonexistent-environment"
```

**Expected Behavior:**
- Server should handle missing environment gracefully
- Should return None values from `get_auth_from_sdk_config()`
- Should fall back to LC_API_KEY if available

**Verification:**
- Check server logs for: "Environment 'nonexistent-environment' not found in SDK config"
- Verify graceful degradation to API key mode if available

## Debugging Tips

### Enable Debug Logging

Add this to your environment:
```bash
export LOG_LEVEL=DEBUG
```

Or add to the top of `server.py`:
```python
logging.basicConfig(level=logging.DEBUG)
```

### Check OAuth Credentials

Verify your OAuth credentials are valid:
```python
from limacharlie import _getEnvironmentCreds

oid, uid, api_key, oauth = _getEnvironmentCreds("default")
print(f"UID: {uid}")
print(f"OAuth: {oauth is not None}")
print(f"Provider: {oauth.get('provider') if oauth else 'N/A'}")
```

### Inspect Context Variable

During runtime, you can inspect the context variable:
```python
from server import uid_auth_context_var

uid, api_key, mode = uid_auth_context_var.get()
print(f"UID: {uid}")
print(f"Mode: {mode}")
print(f"API Key: {'set' if api_key else 'None'}")
```

## Success Criteria

The OAuth implementation is working correctly if:

1. ✓ OAuth credentials are detected from `~/.limacharlie`
2. ✓ OAuth mode takes precedence over API key when both available
3. ✓ Multiple environments can be selected via `LC_CURRENT_ENV`
4. ✓ JWT tokens are auto-renewed without user intervention
5. ✓ Multi-organization operations work with different OIDs
6. ✓ API key fallback works when OAuth not available
7. ✓ Clear error messages for missing credentials
8. ✓ All automated tests pass

## Common Issues

### Issue: "OAuth credentials not found"
- **Solution**: Run `limacharlie login` to set up OAuth credentials

### Issue: "Environment not found"
- **Solution**: Check `LC_CURRENT_ENV` matches an environment in `~/.limacharlie`

### Issue: "Permission denied for organization"
- **Solution**: Verify your user account has access to the specified OID

### Issue: "Token expired" errors
- **Solution**: Ensure LimaCharlie SDK is up to date for proper JWT renewal

## Next Steps

After manual testing is complete:

1. Document any issues or edge cases discovered
2. Update automated tests if new scenarios are identified
3. Consider adding integration tests with a test organization
4. Update user-facing documentation with OAuth setup instructions
