# LimaCharlie MCP Server - Go Architecture Design

## Project Structure

```
lc-mcp-go/
├── cmd/
│   └── server/
│       └── main.go              # Main entry point
├── internal/
│   ├── auth/
│   │   ├── context.go           # Auth context management
│   │   ├── validator.go         # UID/credential validation
│   │   ├── sdk_cache.go         # Thread-safe SDK instance cache
│   │   └── auth_test.go         # Auth tests + isolation tests
│   ├── server/
│   │   ├── server.go            # MCP server setup
│   │   ├── profiles.go          # Profile definitions
│   │   ├── middleware.go        # Request middleware
│   │   └── server_test.go
│   ├── tools/
│   │   ├── core/                # Core profile tools
│   │   │   ├── sensor_info.go
│   │   │   ├── list_sensors.go
│   │   │   └── core_test.go
│   │   ├── historical/          # Historical data profile
│   │   │   ├── lcql.go
│   │   │   ├── events.go
│   │   │   └── historical_test.go
│   │   ├── investigation/       # Live investigation profile
│   │   │   ├── processes.go
│   │   │   ├── yara.go
│   │   │   └── investigation_test.go
│   │   ├── response/            # Threat response profile
│   │   │   ├── isolation.go
│   │   │   ├── tagging.go
│   │   │   └── response_test.go
│   │   ├── fleet/               # Fleet management profile
│   │   │   ├── installation_keys.go
│   │   │   ├── cloud_sensors.go
│   │   │   └── fleet_test.go
│   │   ├── detection/           # Detection engineering profile
│   │   │   ├── dr_rules.go
│   │   │   ├── yara_rules.go
│   │   │   └── detection_test.go
│   │   ├── admin/               # Platform admin profile
│   │   │   ├── outputs.go
│   │   │   ├── secrets.go
│   │   │   └── admin_test.go
│   │   └── registry.go          # Tool registration
│   └── config/
│       ├── config.go            # Configuration management
│       └── config_test.go
├── pkg/
│   └── types/
│       └── types.go             # Public types/interfaces
├── go.mod
├── go.sum
├── README.md
└── ARCHITECTURE.md
```

## Authentication Architecture

### Context-Based Credential Isolation

**Critical Requirement**: Multi-tenant server must NEVER cross credentials between requests.

```go
// Context keys (unexported for safety)
type contextKey string

const (
    sdkClientKey   contextKey = "lc_sdk_client"
    authModeKey    contextKey = "lc_auth_mode"
    currentOIDKey  contextKey = "lc_current_oid"
    userIDKey      contextKey = "lc_user_id"
)

// Authentication modes
type AuthMode int

const (
    AuthModeNormal AuthMode = iota  // Single org: OID + API Key
    AuthModeUIDKey                   // Multi-org: UID + API Key
    AuthModeUIDOAuth                 // Multi-org: UID + OAuth (future)
)

// Auth credentials stored in context
type AuthContext struct {
    Mode     AuthMode
    OID      string
    APIKey   string
    UID      string
    JWTToken string  // For OAuth mode
}
```

### HTTP Headers (Clean Separation)

**Python Implementation** (concatenated):
```
Authorization: Bearer-LC-{uid}:{api_key}  # Mixed format
```

**Go Implementation** (clean headers):
```
X-LC-OID: organization-id         # Single-org mode
X-LC-API-Key: api-key              # API key authentication
X-LC-UID: user-id                  # Multi-org mode
Authorization: Bearer <jwt-token>  # OAuth (future, standard)
```

### SDK Instance Caching

**Thread-safe cache with credential-based keying**:

```go
type SDKCache struct {
    mu     sync.RWMutex
    cache  map[string]*CachedSDK
    ttl    time.Duration
}

type CachedSDK struct {
    Client    *limacharlie.Client
    Org       *limacharlie.Organization
    CreatedAt time.Time
    LastUsed  time.Time
}

// Cache key generation (MUST be credential-specific)
func cacheKey(auth *AuthContext) string {
    // Hash credentials to prevent key collision attacks
    h := sha256.New()
    h.Write([]byte(auth.Mode.String()))
    h.Write([]byte(auth.OID))
    h.Write([]byte(auth.APIKey))
    h.Write([]byte(auth.UID))
    return hex.EncodeToString(h.Sum(nil))
}
```

**Critical safeguards**:
1. Cache key MUST include all credential components
2. Never use user-provided strings directly as keys
3. Implement cache expiration to force re-auth
4. Clear cache on credential changes

## Tool Implementation Pattern

### Tool Handler Signature

```go
type ToolHandler func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error)
```

### Tool Implementation Example

```go
func ListSensors(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
    // 1. Extract and validate auth from context
    auth, err := auth.FromContext(ctx)
    if err != nil {
        return mcp.NewToolResultError(fmt.Sprintf("authentication error: %v", err)), nil
    }

    // 2. Get or create SDK client
    org, err := auth.GetOrganization()
    if err != nil {
        return mcp.NewToolResultError(fmt.Sprintf("failed to get organization: %v", err)), nil
    }

    // 3. Parse arguments
    limit, _ := args["limit"].(float64)

    // 4. Call SDK
    sensors, err := org.ListSensors(&limacharlie.SensorListOptions{
        Limit: int(limit),
    })
    if err != nil {
        return mcp.NewToolResultError(fmt.Sprintf("failed to list sensors: %v", err)), nil
    }

    // 5. Format response
    result := map[string]interface{}{
        "sensors": sensors,
    }

    return mcp.NewToolResultText(toJSON(result)), nil
}
```

### Multi-Org Tool Wrapper

For tools that accept `oid` parameter in UID mode:

```go
func WithMultiOrg(handler ToolHandler) ToolHandler {
    return func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
        auth, _ := auth.FromContext(ctx)

        // If UID mode and oid parameter provided, switch context
        if auth.Mode != auth.AuthModeNormal {
            if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
                // Create new auth context with specified OID
                newAuth := auth.Clone()
                newAuth.OID = oidParam
                ctx = auth.WithContext(ctx, newAuth)
            }
        }

        return handler(ctx, args)
    }
}
```

## Profile System

```go
type Profile string

const (
    ProfileCore      Profile = "core"
    ProfileHistorical Profile = "historical_data"
    ProfileInvestigation Profile = "live_investigation"
    ProfileResponse  Profile = "threat_response"
    ProfileFleet     Profile = "fleet_management"
    ProfileDetection Profile = "detection_engineering"
    ProfileAdmin     Profile = "platform_admin"
    ProfileAll       Profile = "all"
)

// Profile to tool mapping
var ProfileTools = map[Profile][]string{
    ProfileCore: {
        "test_tool",
        "get_sensor_info",
        "list_sensors",
        "get_online_sensors",
        "is_online",
        "search_hosts",
    },
    // ... other profiles
}

// Tool registration
func RegisterTool(profile Profile, name string, handler ToolHandler, schema *mcp.Tool) {
    // Register in global registry
    toolRegistry[name] = ToolRegistration{
        Profile: profile,
        Handler: handler,
        Schema:  schema,
    }
}
```

## MCP Server Integration

```go
func CreateServer(profile Profile) (*server.MCPServer, error) {
    s := server.NewMCPServer(
        "LimaCharlie MCP Server",
        "1.0.0",
        server.WithToolCapabilities(false),
        server.WithRecovery(),
    )

    // Get tools for profile
    toolNames := getToolsForProfile(profile)

    // Register each tool
    for _, name := range toolNames {
        reg := toolRegistry[name]

        // Wrap handler with middleware
        wrappedHandler := wrapHandler(reg.Handler)

        s.AddTool(reg.Schema, wrappedHandler)
    }

    return s, nil
}

func wrapHandler(handler ToolHandler) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        // Extract args from request
        args := request.Arguments

        // Call handler
        return handler(ctx, args)
    }
}
```

## Configuration

```go
type Config struct {
    // Deployment
    Mode        string // "stdio" or "http"
    Profile     Profile
    LogLevel    string

    // Authentication (loaded from env or config file)
    OID         string
    APIKey      string
    UID         string
    Environment string

    // Optional features
    EnableAudit bool
    AuditLevel  string
}

func LoadConfig() (*Config, error) {
    // Priority: env vars > config file > defaults
    cfg := &Config{
        Mode:     getEnv("MCP_MODE", "stdio"),
        Profile:  Profile(getEnv("MCP_PROFILE", "all")),
        LogLevel: getEnv("LOG_LEVEL", "info"),
    }

    // Load LC credentials
    cfg.OID = os.Getenv("LC_OID")
    cfg.APIKey = os.Getenv("LC_API_KEY")
    cfg.UID = os.Getenv("LC_UID")
    cfg.Environment = os.Getenv("LC_CURRENT_ENV")

    return cfg, nil
}
```

## Testing Strategy

### 1. Credential Isolation Tests

**Critical**: Test that credentials NEVER leak between requests

```go
func TestCredentialIsolation(t *testing.T) {
    // Create two different auth contexts
    auth1 := &AuthContext{
        Mode:   AuthModeNormal,
        OID:    "org1",
        APIKey: "key1",
    }

    auth2 := &AuthContext{
        Mode:   AuthModeNormal,
        OID:    "org2",
        APIKey: "key2",
    }

    // Make concurrent requests
    var wg sync.WaitGroup
    results := make(chan string, 2)

    for i := 0; i < 2; i++ {
        wg.Add(1)
        go func(auth *AuthContext) {
            defer wg.Done()
            ctx := WithAuthContext(context.Background(), auth)

            // Call tool
            result, _ := SomeTool(ctx, nil)

            // Extract OID from result to verify correct auth was used
            oid := extractOID(result)
            results <- oid
        }(auth1)

        go func(auth *AuthContext) {
            defer wg.Done()
            ctx := WithAuthContext(context.Background(), auth)

            result, _ := SomeTool(ctx, nil)
            oid := extractOID(result)
            results <- oid
        }(auth2)
    }

    wg.Wait()
    close(results)

    // Verify both OIDs are present and correct
    oids := make(map[string]int)
    for oid := range results {
        oids[oid]++
    }

    assert.Equal(t, 2, oids["org1"], "org1 should be used exactly once")
    assert.Equal(t, 2, oids["org2"], "org2 should be used exactly once")
}
```

### 2. SDK Cache Tests

```go
func TestSDKCacheSafety(t *testing.T) {
    cache := NewSDKCache(5 * time.Minute)

    // Test: Same credentials should return cached instance
    // Test: Different credentials should return different instances
    // Test: Expired cache should create new instance
    // Test: Concurrent access should be safe
}
```

### 3. Tool Tests

```go
func TestListSensors(t *testing.T) {
    // Mock SDK
    mockOrg := &mockOrganization{
        sensors: []*limacharlie.Sensor{
            {SID: "test-sid-1"},
            {SID: "test-sid-2"},
        },
    }

    // Create context with auth
    ctx := createTestContext(mockOrg)

    // Call tool
    result, err := ListSensors(ctx, map[string]interface{}{})

    // Verify
    assert.NoError(t, err)
    assert.Contains(t, result.Content[0].Text, "test-sid-1")
}
```

### 4. Integration Tests

```go
func TestEndToEnd(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping integration test")
    }

    // Create real server
    server := CreateServer(ProfileCore)

    // Make tool call
    request := mcp.CallToolRequest{
        Name: "list_sensors",
        Arguments: map[string]interface{}{},
    }

    result, err := server.HandleToolCall(context.Background(), request)

    assert.NoError(t, err)
    assert.NotNil(t, result)
}
```

## Implementation Phases

### Phase 1: Core Framework (MVP)
- [ ] Project setup (go.mod, structure)
- [ ] Config management
- [ ] Auth context system
- [ ] SDK cache with safety
- [ ] MCP server integration
- [ ] Core profile tools (6 tools)
- [ ] Comprehensive auth tests

### Phase 2: Tool Implementation
- [ ] Historical data profile
- [ ] Live investigation profile
- [ ] Threat response profile
- [ ] Fleet management profile
- [ ] Detection engineering profile
- [ ] Platform admin profile
- [ ] Tool tests for each profile

### Phase 3: SDK Enhancements (if needed)
- [ ] Identify missing SDK features
- [ ] Create branch in go-limacharlie
- [ ] Implement missing features
- [ ] Submit PR

### Phase 4: Polish & Documentation
- [ ] Integration tests
- [ ] Performance tests
- [ ] Documentation
- [ ] Examples
- [ ] CI/CD setup

## Security Considerations

1. **Credential Isolation**: Use context.Context exclusively, no global variables
2. **Cache Key Safety**: Hash credentials, never use user input directly
3. **UID Validation**: Reject malformed UIDs, JWTs, hex strings
4. **Error Messages**: Never include credentials in errors
5. **Logging**: Never log API keys, tokens, or sensitive data
6. **Concurrent Safety**: All shared state must be protected by mutexes
7. **Cache Expiration**: Force re-authentication periodically

## Go Best Practices

1. **Error Handling**: Return errors, don't panic (except in init)
2. **Context Propagation**: Always pass context as first parameter
3. **Interface Usage**: Define small, focused interfaces
4. **Testing**: Use table-driven tests, mock external dependencies
5. **Documentation**: GoDoc comments on all exported types/functions
6. **Naming**: Follow Go conventions (camelCase, not snake_case)
7. **Package Organization**: Internal packages for private code
