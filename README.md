# LimaCharlie MCP Server

A high-performance [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server for [LimaCharlie](https://limacharlie.io/), enabling AI assistants like Claude to interact with your security infrastructure through natural language.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://go.dev/)
[![MCP](https://img.shields.io/badge/MCP-1.0-purple)](https://modelcontextprotocol.io/)

## What is This?

This server bridges AI assistants and the LimaCharlie security platform through the Model Context Protocol. It allows Claude (and other MCP-compatible AI assistants) to:

- **Query telemetry** with natural language (translated to LCQL)
- **Investigate endpoints** in real-time (processes, network, files)
- **Respond to threats** (isolate hosts, tag sensors, task endpoints)
- **Manage detections** (D&R rules, YARA rules, false positives)
- **Administer platforms** (outputs, integrations, configurations)
- **Generate security content** with AI (rules, queries, playbooks)

**LimaCharlie** is a Security Infrastructure as a Service (SIaaS) platform providing EDR, XDR, SIEM capabilities through a unified API. This MCP server makes that API accessible to AI assistants.

## Features

- **121 MCP Tools** across 8 specialized profiles
- **Multi-Tenant Architecture** with strict credential isolation
- **Dual Transport Modes**: STDIO (local) and HTTP (cloud with OAuth 2.1)
- **AI-Powered Generation**: Automatic rule and query creation using Google Gemini
- **Production-Ready**: Thread-safe SDK caching, graceful shutdown, health checks
- **Secure by Design**: Context-based auth, SHA-256 cache keys, UID validation
- **High Performance**: Single ~55MB binary, sub-second cold starts
- **Flexible Authentication**: API keys, JWT tokens, OAuth 2.1 with PKCE

## Quick Start

### Local MCP Server

```bash
# 1. Build the server
go build -o lc-mcp-server ./cmd/server

# 2. Set your credentials
export LC_OID="your-organization-id"
export LC_API_KEY="your-api-key"

# 3. Run the server
./lc-mcp-server
```

### Remote MCP Server

Claude Code can connect to the LimaCharlie hosted MCP server using http. This is the simplest method to get up and running.

#### Step 1: Add the MCP server

```bash
claude mcp add --transport http lc-remote "https://mcp.limacharlie.io/mcp"
```

#### Step 2: Execute Claude Code

```bash
claude
```

#### Step 3: Authenticate to LimaCharlie

1. Run `/mcp` from within Claude and select your remote MCP server
2. Select option `2. Authenticate` from the menu
3. A browser window will open for authentication. Authenticate using your LimaCharlie credentials
4. If successful, you will get the following message within Claude Code: `Authentication successful. Connected to lc-remote.`


## Running with Claude Code (STDIO Mode)

Claude Code can connect to this server locally using STDIO transport. This is the recommended method for development and personal use.

### Step 1: Build the Server

```bash
cd /path/to/lc-mcp-server
go build -o lc-mcp-server ./cmd/server
```

### Step 2: Configure Claude Code

#### Option 1: Add MCP server via CLI

To add the local MCP server via the CLI, execute the following command, substituting the `YOUR_OID`, `YOUR_API_KEY`, and `YOUR_EXECUTABLE` placeholders with your values:

```bash
claude mcp add --transport stdio lc-local --env LC_OID="YOUR_OID" LC_API_KEY="YOUR_API_KEY" MCP_MODE="stdio" MCP_PROFILE="all" -- YOUR_EXECUTABLE
```

**Example:**
```bash
claude mcp add --transport stdio lc-local --env LC_OID="abcd1234-d34d-b33f-1010-12346ab94321" LC_API_KEY="123453a1-c0ff-ee43-fa11-f8142de5a490" MCP_MODE="stdio" MCP_PROFILE="all" -- /home/username/lc-mcp-server/lc-mcp-server
```

#### Option 2: Add MCP server via config file
Edit your Claude Code MCP settings file (usually at `~/.config/claude-code/mcp.json`):

```json
{
  "mcpServers": {
    "limacharlie": {
      "command": "/absolute/path/to/lc-mcp-server",
      "args": [],
      "env": {
        "LC_OID": "your-organization-id",
        "LC_API_KEY": "your-api-key",
        "MCP_MODE": "stdio",
        "MCP_PROFILE": "all",
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

### Step 3: Restart Claude Code

Restart Claude Code to load the MCP server. You can verify it's working by asking:

> "Can you list my online sensors?"

Claude will use the `list_sensors` or `get_online_sensors` tool to query your LimaCharlie organization.

### Profile-Specific Configuration

You can configure multiple MCP server instances with different profiles:

```json
{
  "mcpServers": {
    "limacharlie-investigate": {
      "command": "/path/to/lc-mcp-server",
      "args": [],
      "env": {
        "LC_OID": "your-org-id",
        "LC_API_KEY": "your-api-key",
        "MCP_MODE": "stdio",
        "MCP_PROFILE": "live_investigation",
        "LOG_LEVEL": "warn"
      }
    },
    "limacharlie-detect": {
      "command": "/path/to/lc-mcp-server",
      "args": [],
      "env": {
        "LC_OID": "your-org-id",
        "LC_API_KEY": "your-api-key",
        "MCP_MODE": "stdio",
        "MCP_PROFILE": "detection_engineering",
        "LOG_LEVEL": "warn"
      }
    }
  }
}
```

## Tool Profiles

The server organizes tools into profiles for different use cases:

| Profile | Tools | Description | Use Cases |
|---------|-------|-------------|-----------|
| **core** | 6 | Essential sensor operations | Sensor inventory, status checks, host search |
| **historical_data** | 12 | Telemetry analysis and queries | LCQL queries, event retrieval, IOC searches, detection history |
| **historical_data_readonly** | 12 | Read-only telemetry access | Same as above, but safe for restricted users |
| **live_investigation** | 18 | Real-time endpoint inspection | Process lists, network connections, YARA scanning, artifacts |
| **threat_response** | 8 | Incident response actions | Network isolation, sensor tagging, reliable tasking |
| **fleet_management** | 9 | Sensor deployment and lifecycle | Installation keys, cloud sensors, platform enumeration |
| **detection_engineering** | 19 | Detection rule management | D&R rules, YARA rules, false positives, MITRE ATT&CK |
| **platform_admin** | 44 | Complete platform control | Outputs, integrations, lookups, secrets, playbooks |
| **ai_powered** | 6 | AI-assisted content generation | Auto-generate rules, queries, selectors, playbooks |
| **all** | 121+ | All profiles combined | Full platform access |

## Configuration

### Authentication Modes

The server supports three authentication modes:

#### 1. Normal Mode (Single Organization)

```bash
export LC_OID="your-organization-id"
export LC_API_KEY="your-api-key"
export MCP_MODE="stdio"
export MCP_PROFILE="all"
```

#### 2. UID + API Key (Multi-Organization)

```bash
export LC_UID="user@example.com"
export LC_API_KEY="your-user-api-key"
export MCP_MODE="stdio"
export MCP_PROFILE="all"
```

When using UID mode, tools that support multi-org operations accept an `oid` parameter to specify which organization to operate on.

#### 3. UID + OAuth (Multi-Organization with JWT)

```bash
export LC_UID="user@example.com"
export LC_JWT="your-jwt-token"
export MCP_MODE="stdio"
export MCP_PROFILE="all"
```

Or use environment-based configuration:

```bash
export LC_UID="user@example.com"
export LC_CURRENT_ENV="default"  # Uses ~/.limacharlie config
export MCP_MODE="stdio"
export MCP_PROFILE="all"
```

### Optional Configuration

```bash
# Logging
export LOG_LEVEL="info"  # debug, info, warn, error

# SDK Caching
export SDK_CACHE_TTL="5m"  # Cache TTL (e.g., "5m", "1h", "30s")

# AI-Powered Tools (requires Google Gemini)
export GOOGLE_API_KEY="your-google-api-key"
export LLM_YAML_RETRY_COUNT="10"  # Validation retry count
```

## Usage Examples

### Example 1: Query Recent Detections

```
User: "Show me all detections from the last 24 hours"

Claude uses: get_historic_detections
→ Returns: List of detections with event data, rules, and metadata
```

### Example 2: Investigate a Suspicious Process

```
User: "Check what processes are running on sensor abc-123-def"

Claude uses: get_processes
→ Returns: Process list with PIDs, paths, command lines, parent relationships

User: "Scan process 1234 for malware with YARA"

Claude uses: yara_scan_process
→ Returns: YARA matches if any rules trigger
```

### Example 3: Create a Detection Rule

```
User: "Create a D&R rule to detect PowerShell downloading files from the internet"

Claude uses: generate_dr_rule_detection (AI-powered)
→ Generates: LCQL-based detection logic
→ Then uses: set_dr_general_rule
→ Result: New detection rule deployed
```

### Example 4: Search for IOCs Across Fleet

```
User: "Search for IP 192.168.1.100 in telemetry from the last week"

Claude uses: search_iocs
→ Returns: All events containing that IP with timestamps and sensor IDs
```

### Example 5: Isolate Compromised Endpoint

```
User: "Isolate sensor xyz-789 from the network"

Claude uses: isolate_network
→ Result: Sensor network isolation activated

User: "Tag it as 'compromised'"

Claude uses: add_tag
→ Result: Tag applied for tracking
```

## Architecture

### Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         Claude / AI                         │
└────────────────────────┬────────────────────────────────────┘
                         │ MCP Protocol (STDIO or HTTP)
┌────────────────────────▼────────────────────────────────────┐
│                   LimaCharlie MCP Server                    │
│                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Auth      │  │     Tools    │  │   SDK Cache  │     │
│  │   Context   │  │   Registry   │  │   (Thread-   │     │
│  │   Isolation │  │   (121)      │  │    Safe)     │     │
│  └─────────────┘  └──────────────┘  └──────────────┘     │
│                                                             │
└────────────────────────┬────────────────────────────────────┘
                         │ LimaCharlie REST API
┌────────────────────────▼────────────────────────────────────┐
│                  LimaCharlie Platform                       │
│   Sensors | Telemetry | Rules | Outputs | Integrations     │
└─────────────────────────────────────────────────────────────┘
```

### Security Architecture

**Credential Isolation** (Critical for Multi-Tenancy):

1. **Context-Based Storage**: All credentials stored in `context.Context`, never global
2. **Cache Key Hashing**: SHA-256 of (mode + oid + apiKey + uid + env)
3. **Thread-Safe Operations**: Mutex-protected SDK cache with TTL
4. **No User Input in Keys**: Cache keys never use raw user-provided strings
5. **Concurrent Testing**: 100+ concurrent requests verified in test suite

**UID Validation**: Automatically rejects suspicious UIDs that resemble tokens:
- JWT format patterns (three base64 segments with dots)
- Long hexadecimal strings (32+ characters)
- Base64-encoded secrets

### Project Structure

```
lc-mcp-server/
├── cmd/server/              # Main entry point
│   └── main.go              # Server initialization and startup
│
├── internal/
│   ├── auth/                # Authentication & credential management
│   │   ├── context.go       # Auth context storage and retrieval
│   │   ├── sdk_cache.go     # Thread-safe SDK instance caching
│   │   ├── validator.go     # UID and credential validation
│   │   └── auth_test.go     # Isolation and concurrency tests
│   │
│   ├── config/              # Configuration management
│   │   ├── config.go        # Environment variable loading
│   │   └── config_test.go   # Config validation tests
│   │
│   ├── server/              # MCP server implementation
│   │   ├── server.go        # Core server logic
│   │   └── server_test.go   # Server initialization tests
│   │
│   ├── http/                # HTTP transport (OAuth mode)
│   │   ├── server.go        # HTTP server and routes
│   │   └── middleware.go    # Auth and rate limiting middleware
│   │
│   ├── oauth/               # OAuth 2.1 implementation
│   │   ├── firebase/        # Firebase authentication
│   │   ├── state/           # OAuth state management
│   │   └── token/           # Token encryption and storage
│   │
│   └── tools/               # MCP tool implementations
│       ├── registry.go      # Tool registration system
│       ├── core/            # Core profile (6 tools)
│       ├── historical/      # Historical data profile (12 tools)
│       ├── investigation/   # Live investigation profile (18 tools)
│       ├── response/        # Threat response profile (8 tools)
│       ├── rules/           # Detection engineering tools
│       ├── ai/              # AI-powered generation (6 tools)
│       └── admin/           # Platform admin (44 tools)
│
├── prompts/                 # AI generation prompt templates
├── static/                  # Web UI assets (OAuth flow)
├── templates/               # HTML templates (OAuth flow)
│
├── Dockerfile               # Container build
├── docker-compose.yaml      # Local development setup
├── .env.example             # Configuration template
└── README.md                # This file
```

## Development

### Building

```bash
# Build binary
go build -o lc-mcp-server ./cmd/server

# Build with version info
VERSION=$(git describe --tags --always)
go build -ldflags "-X main.Version=$VERSION" -o lc-mcp-server ./cmd/server

# Build for multiple platforms
GOOS=linux GOARCH=amd64 go build -o lc-mcp-server-linux-amd64 ./cmd/server
GOOS=darwin GOARCH=arm64 go build -o lc-mcp-server-darwin-arm64 ./cmd/server
GOOS=windows GOARCH=amd64 go build -o lc-mcp-server-windows-amd64.exe ./cmd/server
```

### Testing

```bash
# Run all tests
go test ./internal/... -v

# Run with coverage
go test ./internal/... -cover

# Run authentication isolation tests (CRITICAL)
go test ./internal/auth/... -v -run TestCredentialIsolation

# Run specific package tests
go test ./internal/tools/core/... -v

# Generate coverage report
go test ./internal/... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

**Test Coverage Status**:
- ✅ Authentication: 100% (17/17 tests passing)
- ✅ Configuration: 100% (9/9 tests passing)
- ✅ Server: 100% (passing)
- 🔄 Tools: Implementation-specific (varies by tool)

### Adding New Tools

1. **Create tool file** in appropriate profile package (e.g., `internal/tools/myprofile/mytool.go`)

2. **Register the tool**:

```go
package myprofile

import (
    "context"
    "github.com/mark3labs/mcp-go/mcp"
    "github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
    RegisterMyTool()
}

func RegisterMyTool() {
    tools.RegisterTool(&tools.ToolRegistration{
        Name:        "my_tool",
        Description: "Does something useful",
        Profile:     "my_profile",
        RequiresOID: true,  // Set true for multi-org support
        Schema: mcp.NewTool("my_tool",
            mcp.WithDescription("Does something useful"),
            mcp.WithString("param1",
                mcp.Required(),
                mcp.Description("First parameter")),
        ),
        Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
            // Get organization SDK instance
            org, err := getOrganization(ctx)
            if err != nil {
                return tools.ErrorResult(err.Error()), nil
            }

            // Implement tool logic
            result := map[string]interface{}{
                "status": "success",
            }

            return tools.SuccessResult(result), nil
        },
    })
}
```

3. **Add to profile definition** in `internal/tools/registry.go`:

```go
var ProfileDefinitions = map[string][]string{
    "my_profile": {
        "my_tool",
        // ... other tools
    },
}
```

4. **Import package** in `cmd/server/main.go`:

```go
import (
    _ "github.com/refractionpoint/lc-mcp-go/internal/tools/myprofile"
)
```

5. **Write tests** in `internal/tools/myprofile/mytool_test.go`

### Code Audit Guidelines

When auditing this codebase, focus on:

1. **Credential Isolation** (`internal/auth/`):
   - Verify context-based credential storage
   - Check cache key generation (no user input)
   - Review concurrent access patterns

2. **Input Validation** (`internal/auth/validator.go`, tool handlers):
   - UID validation logic
   - Parameter sanitization
   - API response parsing

3. **Error Handling**:
   - No credentials in error messages
   - No credentials in logs
   - Proper error propagation

4. **Concurrency Safety**:
   - SDK cache mutex usage
   - Context cancellation handling
   - Goroutine lifecycle management

5. **OAuth Security** (`internal/oauth/`):
   - State parameter validation
   - Token encryption (AES-256-GCM)
   - PKCE implementation

## Deployment

### Docker

```bash
# Build image
docker build -t lc-mcp-server:latest .

# Run with environment variables
docker run -d \
  -e LC_OID="your-org-id" \
  -e LC_API_KEY="your-api-key" \
  -e MCP_MODE="http" \
  -e MCP_PROFILE="all" \
  -e PORT="8080" \
  -p 8080:8080 \
  lc-mcp-server:latest
```

### Docker Compose (with Redis for OAuth)

```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your credentials
nano .env

# Start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Binary Deployment

```bash
# Build optimized binary
CGO_ENABLED=0 go build -ldflags="-s -w" -o lc-mcp-server ./cmd/server

# Create systemd service
sudo tee /etc/systemd/system/lc-mcp-server.service > /dev/null <<EOF
[Unit]
Description=LimaCharlie MCP Server
After=network.target

[Service]
Type=simple
User=lc-mcp
WorkingDirectory=/opt/lc-mcp-server
Environment="LC_OID=your-org-id"
Environment="LC_API_KEY=your-api-key"
Environment="MCP_MODE=http"
Environment="MCP_PROFILE=all"
Environment="PORT=8080"
ExecStart=/opt/lc-mcp-server/lc-mcp-server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl enable lc-mcp-server
sudo systemctl start lc-mcp-server
```

### Google Cloud Run

```bash
# Build and push image
gcloud builds submit --config cloudbuild_release.yaml

# Deploy to Cloud Run
gcloud run deploy lc-mcp-server \
  --image gcr.io/YOUR-PROJECT/lc-mcp-server:latest \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars "MCP_MODE=http,MCP_PROFILE=all" \
  --set-secrets "LC_OID=lc-oid:latest,LC_API_KEY=lc-api-key:latest"
```

## Troubleshooting

### Server Won't Start

**Error**: `failed to load configuration`

**Solution**: Check that required environment variables are set:
```bash
echo $LC_OID
echo $LC_API_KEY
echo $MCP_MODE
```

### Tools Not Available

**Error**: Tool `xyz` not found

**Solution**: Check that the tool is in your selected profile:
```bash
export MCP_PROFILE="all"  # Use 'all' to get all tools
```

### Authentication Failures

**Error**: `failed to get organization: unauthorized`

**Solution**: Verify your credentials:
```bash
# Test API key manually
curl -H "Authorization: Bearer ${LC_API_KEY}" \
  "https://api.limacharlie.io/v1/${LC_OID}/sensors"
```

### Claude Code Not Detecting Server

**Solution**: Check MCP configuration file syntax:
```bash
# Validate JSON syntax
cat ~/.config/claude-code/mcp.json | jq .

# Check server logs
export LOG_LEVEL="debug"
/path/to/lc-mcp-server
```

### SDK Cache Issues

**Error**: Stale organization data

**Solution**: Lower cache TTL or clear cache by restarting:
```bash
export SDK_CACHE_TTL="1m"  # Reduce from default 5m
```

### AI-Powered Tools Not Working

**Error**: `AI tool failed: API key not set`

**Solution**: Set Google API key:
```bash
export GOOGLE_API_KEY="your-google-api-key"
```

Get a key from: https://makersuite.google.com/app/apikey

## Performance

- **Cold Start**: < 1 second
- **Binary Size**: ~55 MB (statically linked)
- **Memory Usage**: ~50 MB baseline, +10-20 MB per cached SDK instance
- **Request Latency**:
  - Cached: 50-200ms (SDK instance reuse)
  - Uncached: 200-500ms (new SDK instance)
- **Concurrent Requests**: Tested up to 100 concurrent requests with credential isolation

## API Examples

### STDIO Mode (Local)

```bash
# Start server in STDIO mode
export MCP_MODE="stdio"
export LC_OID="your-org-id"
export LC_API_KEY="your-api-key"
./lc-mcp-server
```

### HTTP Mode (Cloud)

```bash
# Start server in HTTP mode
export MCP_MODE="http"
export PORT="8080"
export LC_OID="your-org-id"
export LC_API_KEY="your-api-key"
./lc-mcp-server
```

Access via MCP over HTTP:
```bash
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${LC_API_KEY}" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "list_sensors",
      "arguments": {}
    }
  }'
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for new functionality
4. Ensure all tests pass (`go test ./internal/...`)
5. Run `go fmt ./...` and `go vet ./...`
6. Commit changes (`git commit -m 'Add amazing feature'`)
7. Push to branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

**Critical**: If your changes touch authentication or credential handling, ensure isolation tests pass:
```bash
go test ./internal/auth/... -v -run TestCredentialIsolation
```

## License

This project is licensed under the Apache License 2.0 - see below for details.

```
Copyright 2025 refractionPOINT

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Resources

- **LimaCharlie**: https://limacharlie.io/
- **LimaCharlie API Documentation**: https://doc.limacharlie.io/
- **Model Context Protocol**: https://modelcontextprotocol.io/
- **MCP Go Framework**: https://github.com/mark3labs/mcp-go
- **Go LimaCharlie SDK**: https://github.com/refractionPOINT/go-limacharlie

## Support

- **Issues**: https://github.com/refractionPOINT/lc-mcp-server/issues
- **LimaCharlie Community**: https://community.limacharlie.io/
- **Documentation**: https://doc.limacharlie.io/

---

**Built with ❤️ for the security community**
