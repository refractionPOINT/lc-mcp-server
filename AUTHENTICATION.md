# Authentication Setup for LimaCharlie MCP Server

## Overview

This MCP server supports two authentication modes controlled by the `PUBLIC_MODE` environment variable:

### Public Mode (PUBLIC_MODE=true)
Used when deploying as a public service. Requires HTTP headers for authentication:
- `Authorization: Bearer <JWT_TOKEN>` - Your LimaCharlie JWT token
- `x-lc-oid: <ORGANIZATION_ID>` - Your LimaCharlie organization ID

### Local Mode (PUBLIC_MODE=false, default)
Used for local development or private deployments. Uses the LimaCharlie SDK's default authentication from environment variables or config files. No HTTP headers required.

## Important Notes

1. **No OAuth Flow**: This server does NOT use OAuth authentication. The 401 responses are configured to not include any `WWW-Authenticate` headers to prevent MCP clients from attempting OAuth discovery.

2. **Token Formats**: The Authorization header supports three formats:
   - JWT only: `Bearer <jwt>` (OID must be in x-lc-oid header)
   - JWT with OID: `Bearer <jwt>:<oid>`
   - API Key with OID: `Bearer <api_key>:<oid>`

## Claude Code Configuration

Add this to your Claude Code settings:

```json
{
  "mcpServers": {
    "lc-custom": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-p", "8080:8080", "lc-mcp-server"],
      "env": {
        "GOOGLE_API_KEY": "<YOUR_GOOGLE_API_KEY>",
        "PUBLIC_MODE": "true"
      },
      "transportType": "sse",
      "transportOptions": {
        "url": "http://localhost:8080/sse",
        "headers": {
          "Authorization": "Bearer <YOUR_JWT_TOKEN>",
          "x-lc-oid": "<YOUR_ORGANIZATION_ID>"
        }
      }
    }
  }
}
```

**Important**: Use a generic name like "lc-custom" instead of "limacharlie" to avoid any special handling by Claude Code.

## Testing Authentication

Use the included `test_auth.py` script to verify the authentication behavior:

```bash
python test_auth.py http://localhost:8000
```

This will test various authentication scenarios and verify that no WWW-Authenticate headers are present in 401 responses.

## Troubleshooting

If you get "HTTP 401 trying to load well-known OAuth metadata" error:
1. Make sure you're using the latest version of the server with the authentication fixes
2. Verify that the server is NOT returning any WWW-Authenticate headers
3. Check that your headers are correctly configured in Claude Code settings