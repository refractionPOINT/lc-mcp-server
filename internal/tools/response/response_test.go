package response

import (
	"context"
	"fmt"
	"testing"
	"time"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockSensor implements a mock sensor for response testing
type MockSensor struct {
	SID                    string
	Hostname               string
	IsIsolated             bool
	LastError              error
	IsolateFromNetworkFunc func() error
	RejoinNetworkFunc      func() error
	UpdateFunc             func() *lc.Sensor
	AddTagFunc             func(tag string, ttl time.Duration) error
	RemoveTagFunc          func(tag string) error
}

func (m *MockSensor) IsolateFromNetwork() error {
	if m.IsolateFromNetworkFunc != nil {
		return m.IsolateFromNetworkFunc()
	}
	m.IsIsolated = true
	return nil
}

func (m *MockSensor) RejoinNetwork() error {
	if m.RejoinNetworkFunc != nil {
		return m.RejoinNetworkFunc()
	}
	m.IsIsolated = false
	return nil
}

func (m *MockSensor) Update() *lc.Sensor {
	if m.UpdateFunc != nil {
		return m.UpdateFunc()
	}
	return m
}

func (m *MockSensor) AddTag(tag string, ttl time.Duration) error {
	if m.AddTagFunc != nil {
		return m.AddTagFunc(tag, ttl)
	}
	return nil
}

func (m *MockSensor) RemoveTag(tag string) error {
	if m.RemoveTagFunc != nil {
		return m.RemoveTagFunc(tag)
	}
	return nil
}

// MockOrganization implements a mock organization for response tools
type MockOrganization struct {
	GetOIDFunc              func() string
	GetSensorFunc           func(sid string) *lc.Sensor
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
func (m *MockOrganization) WithInvestigationID(invID string) *lc.Organization { return nil }

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

// Test Isolate Network
func TestIsolateNetwork(t *testing.T) {
	t.Run("isolates sensor from network", func(t *testing.T) {
		isolateCalled := false

		mockSensor := &MockSensor{
			SID:      "test-sid",
			Hostname: "test-host",
			IsolateFromNetworkFunc: func() error {
				isolateCalled = true
				return nil
			},
		}

		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				// Convert MockSensor to *lc.Sensor
				sensor := &lc.Sensor{
					SID:      mockSensor.SID,
					Hostname: mockSensor.Hostname,
				}
				sensor.IsolateFromNetworkFunc = mockSensor.IsolateFromNetworkFunc
				return sensor
			},
		}

		ctx := createTestContext(t)

		reg, ok := tools.GetTool("isolate_network")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "test-sid",
		}

		result, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.False(t, result.IsError)
		assert.True(t, isolateCalled)

		content := getTextContent(t, result)
		assert.Contains(t, content, "success")
		assert.Contains(t, content, "isolated")
	})

	t.Run("returns error when sensor not found", func(t *testing.T) {
		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return nil
			},
		}

		ctx := createTestContext(t)

		reg, ok := tools.GetTool("isolate_network")
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

	t.Run("returns error when isolation fails", func(t *testing.T) {
		mockSensor := &lc.Sensor{
			SID:      "test-sid",
			Hostname: "test-host",
		}
		mockSensor.IsolateFromNetworkFunc = func() error {
			return fmt.Errorf("isolation failed")
		}

		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return mockSensor
			},
		}

		ctx := createTestContext(t)

		reg, ok := tools.GetTool("isolate_network")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "test-sid",
		}

		result, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
		content := getTextContent(t, result)
		assert.Contains(t, content, "failed to isolate sensor")
	})
}

// Test Rejoin Network
func TestRejoinNetwork(t *testing.T) {
	t.Run("removes network isolation from sensor", func(t *testing.T) {
		rejoinCalled := false

		mockSensor := &lc.Sensor{
			SID:        "test-sid",
			Hostname:   "test-host",
			IsIsolated: true,
		}
		mockSensor.RejoinNetworkFunc = func() error {
			rejoinCalled = true
			return nil
		}

		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return mockSensor
			},
		}

		ctx := createTestContext(t)

		reg, ok := tools.GetTool("rejoin_network")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "test-sid",
		}

		result, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.False(t, result.IsError)
		assert.True(t, rejoinCalled)

		content := getTextContent(t, result)
		assert.Contains(t, content, "success")
		assert.Contains(t, content, "rejoined")
	})
}

// Test Is Isolated
func TestIsIsolated(t *testing.T) {
	t.Run("checks isolation status - isolated", func(t *testing.T) {
		mockSensor := &lc.Sensor{
			SID:        "test-sid",
			Hostname:   "test-host",
			IsIsolated: true,
		}
		mockSensor.UpdateFunc = func() *lc.Sensor {
			return mockSensor
		}

		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return mockSensor
			},
		}

		ctx := createTestContext(t)

		reg, ok := tools.GetTool("is_isolated")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "test-sid",
		}

		result, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.False(t, result.IsError)

		content := getTextContent(t, result)
		assert.Contains(t, content, "is_isolated")
		assert.Contains(t, content, "true")
	})

	t.Run("checks isolation status - not isolated", func(t *testing.T) {
		mockSensor := &lc.Sensor{
			SID:        "test-sid",
			Hostname:   "test-host",
			IsIsolated: false,
		}
		mockSensor.UpdateFunc = func() *lc.Sensor {
			return mockSensor
		}

		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return mockSensor
			},
		}

		ctx := createTestContext(t)

		reg, ok := tools.GetTool("is_isolated")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "test-sid",
		}

		result, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.False(t, result.IsError)

		content := getTextContent(t, result)
		assert.Contains(t, content, "is_isolated")
		assert.Contains(t, content, "false")
	})
}

// Test Add Tag
func TestAddTag(t *testing.T) {
	t.Run("adds tag to sensor with TTL", func(t *testing.T) {
		addTagCalled := false
		var capturedTag string
		var capturedTTL time.Duration

		mockSensor := &lc.Sensor{
			SID:      "test-sid",
			Hostname: "test-host",
		}
		mockSensor.AddTagFunc = func(tag string, ttl time.Duration) error {
			addTagCalled = true
			capturedTag = tag
			capturedTTL = ttl
			return nil
		}

		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return mockSensor
			},
		}

		ctx := createTestContext(t)

		reg, ok := tools.GetTool("add_tag")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "test-sid",
			"tag": "test-tag",
			"ttl": float64(3600), // 1 hour in seconds
		}

		result, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.False(t, result.IsError)
		assert.True(t, addTagCalled)
		assert.Equal(t, "test-tag", capturedTag)
		assert.Equal(t, time.Duration(3600)*time.Second, capturedTTL)

		content := getTextContent(t, result)
		assert.Contains(t, content, "success")
		assert.Contains(t, content, "test-tag")
	})

	t.Run("adds permanent tag with TTL 0", func(t *testing.T) {
		var capturedTTL time.Duration

		mockSensor := &lc.Sensor{
			SID:      "test-sid",
			Hostname: "test-host",
		}
		mockSensor.AddTagFunc = func(tag string, ttl time.Duration) error {
			capturedTTL = ttl
			return nil
		}

		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return mockSensor
			},
		}

		ctx := createTestContext(t)

		reg, ok := tools.GetTool("add_tag")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "test-sid",
			"tag": "permanent-tag",
			"ttl": float64(0), // Permanent
		}

		result, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.False(t, result.IsError)
		assert.Equal(t, time.Duration(0), capturedTTL)
	})

	t.Run("returns error with missing parameters", func(t *testing.T) {
		ctx := createTestContext(t)

		reg, ok := tools.GetTool("add_tag")
		require.True(t, ok)

		// Missing tag
		args := map[string]interface{}{
			"sid": "test-sid",
			"ttl": float64(3600),
		}

		result, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
		content := getTextContent(t, result)
		assert.Contains(t, content, "tag parameter is required")
	})
}

// Test Remove Tag
func TestRemoveTag(t *testing.T) {
	t.Run("removes tag from sensor", func(t *testing.T) {
		removeTagCalled := false
		var capturedTag string

		mockSensor := &lc.Sensor{
			SID:      "test-sid",
			Hostname: "test-host",
		}
		mockSensor.RemoveTagFunc = func(tag string) error {
			removeTagCalled = true
			capturedTag = tag
			return nil
		}

		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return mockSensor
			},
		}

		ctx := createTestContext(t)

		reg, ok := tools.GetTool("remove_tag")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "test-sid",
			"tag": "test-tag",
		}

		result, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.False(t, result.IsError)
		assert.True(t, removeTagCalled)
		assert.Equal(t, "test-tag", capturedTag)

		content := getTextContent(t, result)
		assert.Contains(t, content, "success")
		assert.Contains(t, content, "removed")
	})
}

// Test Tool Registration
func TestResponseToolsRegistration(t *testing.T) {
	expectedTools := []string{
		"isolate_network",
		"rejoin_network",
		"is_isolated",
		"add_tag",
		"remove_tag",
	}

	for _, toolName := range expectedTools {
		t.Run(toolName, func(t *testing.T) {
			tool, ok := tools.GetTool(toolName)
			assert.True(t, ok, "Tool %s should be registered", toolName)
			if ok {
				assert.Equal(t, toolName, tool.Name)
				assert.NotEmpty(t, tool.Description)
				assert.NotNil(t, tool.Handler)
				assert.Equal(t, "threat_response", tool.Profile)
				assert.True(t, tool.RequiresOID) // Response tools require OID
			}
		})
	}
}

// Table-driven test for SID validation
func TestResponseToolsSIDValidation(t *testing.T) {
	tools := []string{
		"isolate_network",
		"rejoin_network",
		"is_isolated",
	}

	for _, toolName := range tools {
		t.Run(toolName, func(t *testing.T) {
			ctx := createTestContext(t)

			reg, ok := tools.GetTool(toolName)
			require.True(t, ok)

			// Test with missing SID
			args := map[string]interface{}{}

			result, err := reg.Handler(ctx, args)

			require.NoError(t, err)
			assert.True(t, result.IsError)
		})
	}
}

// Test error handling for tag operations
func TestTagOperationsErrorHandling(t *testing.T) {
	t.Run("add_tag handles errors", func(t *testing.T) {
		mockSensor := &lc.Sensor{
			SID:      "test-sid",
			Hostname: "test-host",
		}
		mockSensor.AddTagFunc = func(tag string, ttl time.Duration) error {
			return fmt.Errorf("tag already exists")
		}

		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return mockSensor
			},
		}

		ctx := createTestContext(t)

		reg, ok := tools.GetTool("add_tag")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "test-sid",
			"tag": "existing-tag",
			"ttl": float64(3600),
		}

		result, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
		content := getTextContent(t, result)
		assert.Contains(t, content, "failed to add tag")
	})

	t.Run("remove_tag handles errors", func(t *testing.T) {
		mockSensor := &lc.Sensor{
			SID:      "test-sid",
			Hostname: "test-host",
		}
		mockSensor.RemoveTagFunc = func(tag string) error {
			return fmt.Errorf("tag not found")
		}

		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return mockSensor
			},
		}

		ctx := createTestContext(t)

		reg, ok := tools.GetTool("remove_tag")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "test-sid",
			"tag": "nonexistent-tag",
		}

		result, err := reg.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
		content := getTextContent(t, result)
		assert.Contains(t, content, "failed to remove tag")
	})
}
