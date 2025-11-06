package investigation

import (
	"context"
	"testing"
	"time"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockSensor implements a mock sensor for testing
type MockSensor struct {
	SID                string
	Hostname           string
	SimpleRequestFunc  func(commandName string, opts lc.SimpleRequestOptions) (lc.Dict, error)
}

func (m *MockSensor) SimpleRequest(commandName string, opts lc.SimpleRequestOptions) (lc.Dict, error) {
	if m.SimpleRequestFunc != nil {
		return m.SimpleRequestFunc(commandName, opts)
	}
	return lc.Dict{}, nil
}

// MockOrganization implements a mock organization for investigation tools
type MockOrganization struct {
	GetOIDFunc              func() string
	GetSensorFunc           func(sid string) *lc.Sensor
	WithInvestigationIDFunc func(invID string) *lc.Organization
}

func (m *MockOrganization) GetOID() string {
	if m.GetOIDFunc != nil {
		return m.GetOIDFunc()
	}
	return "test-org-id"
}

func (m *MockOrganization) GetSensor(sid string) *lc.Sensor {
	if m.GetSensorFunc != nil {
		return m.GetSensorFunc(sid)
	}
	return nil
}

func (m *MockOrganization) WithInvestigationID(invID string) *lc.Organization {
	if m.WithInvestigationIDFunc != nil {
		return m.WithInvestigationIDFunc(invID)
	}
	// Return self for chaining
	return &lc.Organization{}
}

// Implement minimal required methods
func (m *MockOrganization) GetInfo() (lc.OrganizationInformation, error) { return lc.OrganizationInformation{}, nil }
func (m *MockOrganization) GetUsageStats() (*lc.UsageStats, error)      { return nil, nil }
func (m *MockOrganization) GetSensors(sids []string) map[string]*lc.Sensor { return nil }
func (m *MockOrganization) ListSensors(options ...lc.ListSensorsOptions) (map[string]*lc.Sensor, error) {
	return nil, nil
}
func (m *MockOrganization) ActiveSensors(sids []string) (map[string]bool, error) { return nil, nil }
func (m *MockOrganization) GetTimeWhenSensorHasData(sid string, start, end int64) (*lc.SensorTimeData, error) {
	return nil, nil
}
func (m *MockOrganization) GetSensorsWithTag(tag string) (map[string][]string, error) { return nil, nil }
func (m *MockOrganization) GetAllTags() ([]string, error)                              { return nil, nil }
func (m *MockOrganization) DRRules(filters ...lc.DRRuleFilter) (map[string]lc.Dict, error) { return nil, nil }
func (m *MockOrganization) DRRuleAdd(name string, detection interface{}, response interface{}, opts ...lc.NewDRRuleOptions) error {
	return nil
}
func (m *MockOrganization) DRRuleDelete(name string, filters ...lc.DRRuleFilter) error { return nil }
func (m *MockOrganization) FPRules() (map[lc.FPRuleName]lc.FPRule, error)              { return nil, nil }
func (m *MockOrganization) FPRuleAdd(name lc.FPRuleName, detection interface{}, opts ...lc.FPRuleOptions) error {
	return nil
}
func (m *MockOrganization) FPRuleDelete(name lc.FPRuleName) error                     { return nil }
func (m *MockOrganization) YaraListRules() (lc.YaraRules, error)                      { return lc.YaraRules{}, nil }
func (m *MockOrganization) YaraGetSource(sourceName string) (string, error)           { return "", nil }
func (m *MockOrganization) YaraSourceAdd(sourceName string, source lc.YaraSource) error { return nil }
func (m *MockOrganization) YaraSourceDelete(sourceName string) error                  { return nil }
func (m *MockOrganization) GetHistoricEvents(sensorID string, req lc.HistoricEventsRequest) (chan lc.IteratedEvent, func(), error) {
	ch := make(chan lc.IteratedEvent)
	close(ch)
	return ch, func() {}, nil
}
func (m *MockOrganization) Query(req lc.QueryRequest) (*lc.QueryResponse, error) { return nil, nil }
func (m *MockOrganization) QueryAll(req lc.QueryRequest) (*lc.QueryIterator, error) { return nil, nil }
func (m *MockOrganization) QueryAllWithContext(ctx context.Context, req lc.QueryRequest) (*lc.QueryIterator, error) {
	return nil, nil
}
func (m *MockOrganization) QueryWithContext(ctx context.Context, req lc.QueryRequest) (*lc.QueryResponse, error) {
	return nil, nil
}
func (m *MockOrganization) HistoricalDetections(detectionReq lc.HistoricalDetectionsRequest) (lc.HistoricalDetectionsResponse, error) {
	return lc.HistoricalDetectionsResponse{}, nil
}
func (m *MockOrganization) InsightObjects(insightReq lc.InsightObjectsRequest) (lc.InsightObjectsResponse, error) {
	return lc.InsightObjectsResponse{}, nil
}
func (m *MockOrganization) InsightObjectsBatch(insightReq lc.InsightObjectsBatchRequest) (lc.InsightObjectBatchResponse, error) {
	return lc.InsightObjectBatchResponse{}, nil
}
func (m *MockOrganization) ExportArtifact(artifactID string, deadline time.Time) error { return nil }
func (m *MockOrganization) Outputs() (lc.OutputsByName, error)                         { return nil, nil }
func (m *MockOrganization) OutputAdd(output lc.OutputConfig) (lc.OutputConfig, error) {
	return lc.OutputConfig{}, nil
}
func (m *MockOrganization) OutputDel(name string) (lc.GenericJSON, error)               { return nil, nil }
func (m *MockOrganization) InstallationKeys() ([]lc.InstallationKey, error)             { return nil, nil }
func (m *MockOrganization) InstallationKey(iid string) (*lc.InstallationKey, error)     { return nil, nil }
func (m *MockOrganization) AddInstallationKey(k lc.InstallationKey) (string, error)     { return "", nil }
func (m *MockOrganization) DelInstallationKey(iid string) error                         { return nil }
func (m *MockOrganization) GetAPIKeys() ([]lc.APIKeyInfo, error)                        { return nil, nil }
func (m *MockOrganization) CreateAPIKey(name string, permissions []string) (*lc.APIKeyCreate, error) {
	return nil, nil
}
func (m *MockOrganization) DeleteAPIKey(keyHash string) error                           { return nil }
func (m *MockOrganization) GetSchema(name string) (*lc.SchemaResponse, error)           { return nil, nil }
func (m *MockOrganization) GetSchemas() (*lc.Schemas, error)                            { return nil, nil }
func (m *MockOrganization) GetSchemasForPlatform(platform string) (*lc.Schemas, error)  { return nil, nil }
func (m *MockOrganization) GetPlatformNames() ([]string, error)                         { return nil, nil }
func (m *MockOrganization) Extensions() ([]lc.ExtensionName, error)                     { return nil, nil }
func (m *MockOrganization) SubscribeToExtension(name lc.ExtensionName) error            { return nil }
func (m *MockOrganization) UnsubscribeFromExtension(name lc.ExtensionName) error        { return nil }
func (m *MockOrganization) GetOrgErrors() ([]lc.OrgError, error)                        { return nil, nil }
func (m *MockOrganization) DismissOrgError(component string) error                      { return nil }
func (m *MockOrganization) ListUserOrgs(offset, limit *int, filter, sortBy, sortOrder *string, withNames bool) ([]lc.UserOrgInfo, error) {
	return nil, nil
}
func (m *MockOrganization) CreateOrganization(location, name string, template ...interface{}) (lc.NewOrganizationResponse, error) {
	return lc.NewOrganizationResponse{}, nil
}
func (m *MockOrganization) GetBillingOrgDetails() (*lc.BillingOrgDetails, error) { return nil, nil }
func (m *MockOrganization) GetBillingInvoiceURL(year, month int, format string) (map[string]interface{}, error) {
	return nil, nil
}
func (m *MockOrganization) GetMITREReport() (*lc.MITREReport, error)                      { return nil, nil }
func (m *MockOrganization) GenericGETRequest(path string, query lc.Dict, response interface{}) error { return nil }
func (m *MockOrganization) GenericPOSTRequest(path string, data lc.Dict, response interface{}) error {
	return nil
}

// createTestContext creates a test context with auth
func createTestContext(t *testing.T) context.Context {

// getTextContent extracts text from MCP Content interface
func getTextContent(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	require.NotNil(t, result)
	require.NotEmpty(t, result.Content)

	textContent, ok := mcp.AsTextContent(result.Content[0])
	require.True(t, ok, "Content should be TextContent")
	return textContent.Text
}
	t.Helper()

	cache := auth.NewSDKCache(5*time.Minute, nil)

	authCtx := &auth.AuthContext{
		Mode:   auth.AuthModeNormal,
		OID:    "test-org-id",
		APIKey: "test-key-1234567890abcdef",
	}

	ctx := context.Background()
	ctx = auth.WithAuthContext(ctx, authCtx)
	ctx = auth.WithSDKCache(ctx, cache)

	return ctx
}

// Test Get Processes
func TestGetProcesses(t *testing.T) {
	t.Run("retrieves process list from sensor", func(t *testing.T) {
		commandCalled := false
		mockProcessData := lc.Dict{
			"processes": []interface{}{
				map[string]interface{}{"pid": 1, "name": "init"},
				map[string]interface{}{"pid": 2, "name": "systemd"},
			},
		}

		mockSensor := &lc.Sensor{
			SID:      "test-sid",
			Hostname: "test-host",
		}
		mockSensor.SimpleRequestFunc = func(commandName string, opts lc.SimpleRequestOptions) (lc.Dict, error) {
			commandCalled = true
			assert.Equal(t, "os_processes", commandName)
			return mockProcessData, nil
		}

		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return mockSensor
			},
		}

		ctx := createTestContext(t)

		reg, ok := tools.GetTool("get_processes")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "test-sid",
		}

		result, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.False(t, result.IsError)
		assert.True(t, commandCalled)

		content := getTextContent(t, result)
		assert.Contains(t, content, "processes")
		assert.Contains(t, content, "init")
	})

	t.Run("returns error with missing SID", func(t *testing.T) {
		ctx := createTestContext(t)

		reg, ok := tools.GetTool("get_processes")
		require.True(t, ok)

		args := map[string]interface{}{}

		result, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
		content := getTextContent(t, result)
		assert.Contains(t, content, "sid parameter is required")
	})

	t.Run("returns error when sensor not found", func(t *testing.T) {
		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return nil
			},
		}

		ctx := createTestContext(t)

		reg, ok := tools.GetTool("get_processes")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "nonexistent-sid",
		}

		result, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
		content := getTextContent(t, result)
		assert.Contains(t, content, "sensor not found")
	})
}

// Test Get Network Connections
func TestGetNetworkConnections(t *testing.T) {
	t.Run("retrieves network connections from sensor", func(t *testing.T) {
		commandCalled := false
		mockNetworkData := lc.Dict{
			"connections": []interface{}{
				map[string]interface{}{"local": "192.168.1.100:80", "remote": "203.0.113.1:443"},
			},
		}

		mockSensor := &lc.Sensor{
			SID:      "test-sid",
			Hostname: "test-host",
		}
		mockSensor.SimpleRequestFunc = func(commandName string, opts lc.SimpleRequestOptions) (lc.Dict, error) {
			commandCalled = true
			assert.Equal(t, "netstat", commandName) // Python uses "netstat"
			return mockNetworkData, nil
		}

		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return mockSensor
			},
		}

		ctx := createTestContext(t)

		reg, ok := tools.GetTool("get_network_connections")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "test-sid",
		}

		result, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.False(t, result.IsError)
		assert.True(t, commandCalled)

		content := getTextContent(t, result)
		assert.Contains(t, content, "connections")
	})
}

// Test Get OS Version
func TestGetOSVersion(t *testing.T) {
	t.Run("retrieves OS version from sensor", func(t *testing.T) {
		commandCalled := false
		mockOSData := lc.Dict{
			"os": map[string]interface{}{
				"name":    "Ubuntu",
				"version": "22.04",
			},
		}

		mockSensor := &lc.Sensor{
			SID:      "test-sid",
			Hostname: "test-host",
		}
		mockSensor.SimpleRequestFunc = func(commandName string, opts lc.SimpleRequestOptions) (lc.Dict, error) {
			commandCalled = true
			assert.Equal(t, "os_version", commandName)
			return mockOSData, nil
		}

		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return mockSensor
			},
		}

		ctx := createTestContext(t)

		reg, ok := tools.GetTool("get_os_version")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "test-sid",
		}

		result, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.False(t, result.IsError)
		assert.True(t, commandCalled)

		content := getTextContent(t, result)
		assert.Contains(t, content, "Ubuntu")
		assert.Contains(t, content, "22.04")
	})

	t.Run("validates SID format", func(t *testing.T) {
		ctx := createTestContext(t)

		reg, ok := tools.GetTool("get_os_version")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "invalid-sid", // Not a UUID
		}

		result, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})
}

// Test Tool Registration
func TestInvestigationToolsRegistration(t *testing.T) {
	expectedTools := []string{
		"get_processes",
		"get_network_connections",
		"get_os_version",
	}

	for _, toolName := range expectedTools {
		t.Run(toolName, func(t *testing.T) {
			tool, ok := tools.GetTool(toolName)
			assert.True(t, ok, "Tool %s should be registered", toolName)
			if ok {
				assert.Equal(t, toolName, tool.Name)
				assert.NotEmpty(t, tool.Description)
				assert.NotNil(t, tool.Handler)
				assert.Equal(t, "live_investigation", tool.Profile)
				assert.True(t, tool.RequiresOID) // Investigation tools require OID
			}
		})
	}
}

// Test Investigation ID Generation
func TestInvestigationIDGeneration(t *testing.T) {
	t.Run("generates unique investigation ID per request", func(t *testing.T) {
		invIDCalled := false

		mockSensor := &lc.Sensor{
			SID:      "test-sid",
			Hostname: "test-host",
		}
		mockSensor.SimpleRequestFunc = func(commandName string, opts lc.SimpleRequestOptions) (lc.Dict, error) {
			return lc.Dict{}, nil
		}

		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return mockSensor
			},
			WithInvestigationIDFunc: func(invID string) *lc.Organization {
				invIDCalled = true
				assert.NotEmpty(t, invID, "Investigation ID should not be empty")
				// Return a mock org that implements the interface
				return &lc.Organization{}
			},
		}

		ctx := createTestContext(t)

		reg, ok := tools.GetTool("get_processes")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "test-sid",
		}

		_, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, invIDCalled, "WithInvestigationID should be called")
	})
}

// Table-driven test for all investigation tools
func TestInvestigationToolsTableDriven(t *testing.T) {
	tests := []struct {
		toolName        string
		expectedCommand string
	}{
		{"get_processes", "os_processes"},
		{"get_network_connections", "netstat"},
		{"get_os_version", "os_version"},
	}

	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			commandCalled := ""

			mockSensor := &lc.Sensor{
				SID:      "test-sid",
				Hostname: "test-host",
			}
			mockSensor.SimpleRequestFunc = func(commandName string, opts lc.SimpleRequestOptions) (lc.Dict, error) {
				commandCalled = commandName
				return lc.Dict{"data": "test"}, nil
			}

			mockOrg := &MockOrganization{
				GetSensorFunc: func(sid string) *lc.Sensor {
					return mockSensor
				},
			}

			ctx := createTestContext(t)

			reg, ok := tools.GetTool(tt.toolName)
			require.True(t, ok)

			args := map[string]interface{}{
				"sid": "test-sid",
			}

			result, err := reg.Handler(ctx, args)

			require.NoError(t, err)
			assert.False(t, result.IsError)
			assert.Equal(t, tt.expectedCommand, commandCalled)
		})
	}
}

// Test timeout handling
func TestInvestigationToolsTimeout(t *testing.T) {
	t.Run("uses 30 second timeout for sensor commands", func(t *testing.T) {
		var capturedTimeout time.Duration

		mockSensor := &lc.Sensor{
			SID:      "test-sid",
			Hostname: "test-host",
		}
		mockSensor.SimpleRequestFunc = func(commandName string, opts lc.SimpleRequestOptions) (lc.Dict, error) {
			capturedTimeout = opts.Timeout
			return lc.Dict{}, nil
		}

		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return mockSensor
			},
		}

		ctx := createTestContext(t)

		reg, ok := tools.GetTool("get_processes")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "test-sid",
		}

		_, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.Equal(t, 30*time.Second, capturedTimeout)
	})
}
