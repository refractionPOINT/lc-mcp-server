package core

import (
	"context"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockOrganization implements tools.OrganizationClient for testing
type MockOrganization struct {
	GetOIDFunc            func() string
	GetSensorFunc         func(sid string) *lc.Sensor
	ListSensorsFunc       func(options ...lc.ListSensorsOptions) (map[string]*lc.Sensor, error)
	ActiveSensorsFunc     func(sids []string) (map[string]bool, error)
	GetInfoFunc           func() (lc.OrganizationInformation, error)
	GetUsageStatsFunc     func() (*lc.UsageStats, error)
	GetSensorsFunc        func(sids []string) map[string]*lc.Sensor
	GetTimeWhenSensorHasDataFunc func(sid string, start, end int64) (*lc.SensorTimeData, error)
	GetSensorsWithTagFunc func(tag string) (map[string][]string, error)
	GetAllTagsFunc        func() ([]string, error)
	DRRulesFunc           func(filters ...lc.DRRuleFilter) (map[string]lc.Dict, error)
	DRRuleAddFunc         func(name string, detection interface{}, response interface{}, opts ...lc.NewDRRuleOptions) error
	DRRuleDeleteFunc      func(name string, filters ...lc.DRRuleFilter) error
	FPRulesFunc           func() (map[lc.FPRuleName]lc.FPRule, error)
	FPRuleAddFunc         func(name lc.FPRuleName, detection interface{}, opts ...lc.FPRuleOptions) error
	FPRuleDeleteFunc      func(name lc.FPRuleName) error
	YaraListRulesFunc     func() (lc.YaraRules, error)
	YaraGetSourceFunc     func(sourceName string) (string, error)
	YaraSourceAddFunc     func(sourceName string, source lc.YaraSource) error
	YaraSourceDeleteFunc  func(sourceName string) error
	GetHistoricEventsFunc func(sensorID string, req lc.HistoricEventsRequest) (chan lc.IteratedEvent, func(), error)
	QueryFunc             func(req lc.QueryRequest) (*lc.QueryResponse, error)
	QueryAllFunc          func(req lc.QueryRequest) (*lc.QueryIterator, error)
	QueryAllWithContextFunc func(ctx context.Context, req lc.QueryRequest) (*lc.QueryIterator, error)
	QueryWithContextFunc  func(ctx context.Context, req lc.QueryRequest) (*lc.QueryResponse, error)
	HistoricalDetectionsFunc func(detectionReq lc.HistoricalDetectionsRequest) (lc.HistoricalDetectionsResponse, error)
	InsightObjectsFunc    func(insightReq lc.InsightObjectsRequest) (lc.InsightObjectsResponse, error)
	InsightObjectsBatchFunc func(insightReq lc.InsightObjectsBatchRequest) (lc.InsightObjectBatchResponse, error)
	ExportArtifactFunc    func(artifactID string, deadline time.Time) error
	OutputsFunc           func() (lc.OutputsByName, error)
	OutputAddFunc         func(output lc.OutputConfig) (lc.OutputConfig, error)
	OutputDelFunc         func(name string) (lc.GenericJSON, error)
	InstallationKeysFunc  func() ([]lc.InstallationKey, error)
	InstallationKeyFunc   func(iid string) (*lc.InstallationKey, error)
	AddInstallationKeyFunc func(k lc.InstallationKey) (string, error)
	DelInstallationKeyFunc func(iid string) error
	GetAPIKeysFunc        func() ([]lc.APIKeyInfo, error)
	CreateAPIKeyFunc      func(name string, permissions []string) (*lc.APIKeyCreate, error)
	DeleteAPIKeyFunc      func(keyHash string) error
	GetSchemaFunc         func(name string) (*lc.SchemaResponse, error)
	GetSchemasFunc        func() (*lc.Schemas, error)
	GetSchemasForPlatformFunc func(platform string) (*lc.Schemas, error)
	GetPlatformNamesFunc  func() ([]string, error)
	ExtensionsFunc        func() ([]lc.ExtensionName, error)
	SubscribeToExtensionFunc func(name lc.ExtensionName) error
	UnsubscribeFromExtensionFunc func(name lc.ExtensionName) error
	GetOrgErrorsFunc      func() ([]lc.OrgError, error)
	DismissOrgErrorFunc   func(component string) error
	ListUserOrgsFunc      func(offset, limit *int, filter, sortBy, sortOrder *string, withNames bool) ([]lc.UserOrgInfo, error)
	CreateOrganizationFunc func(location, name string, template ...interface{}) (lc.NewOrganizationResponse, error)
	GetBillingOrgDetailsFunc func() (*lc.BillingOrgDetails, error)
	GetBillingInvoiceURLFunc func(year, month int, format string) (map[string]interface{}, error)
	GetMITREReportFunc    func() (*lc.MITREReport, error)
	GenericGETRequestFunc func(path string, query lc.Dict, response interface{}) error
	GenericPOSTRequestFunc func(path string, data lc.Dict, response interface{}) error
	WithInvestigationIDFunc func(invID string) *lc.Organization
}

// Implement all methods of tools.OrganizationClient interface
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

func (m *MockOrganization) ListSensors(options ...lc.ListSensorsOptions) (map[string]*lc.Sensor, error) {
	if m.ListSensorsFunc != nil {
		return m.ListSensorsFunc(options...)
	}
	return make(map[string]*lc.Sensor), nil
}

func (m *MockOrganization) ActiveSensors(sids []string) (map[string]bool, error) {
	if m.ActiveSensorsFunc != nil {
		return m.ActiveSensorsFunc(sids)
	}
	return make(map[string]bool), nil
}

// Additional interface methods - minimal implementations for compilation
func (m *MockOrganization) GetInfo() (lc.OrganizationInformation, error) {
	if m.GetInfoFunc != nil {
		return m.GetInfoFunc()
	}
	return lc.OrganizationInformation{}, nil
}

func (m *MockOrganization) GetUsageStats() (*lc.UsageStats, error) {
	if m.GetUsageStatsFunc != nil {
		return m.GetUsageStatsFunc()
	}
	return nil, nil
}

func (m *MockOrganization) GetSensors(sids []string) map[string]*lc.Sensor {
	if m.GetSensorsFunc != nil {
		return m.GetSensorsFunc(sids)
	}
	return make(map[string]*lc.Sensor)
}

func (m *MockOrganization) GetTimeWhenSensorHasData(sid string, start, end int64) (*lc.SensorTimeData, error) {
	if m.GetTimeWhenSensorHasDataFunc != nil {
		return m.GetTimeWhenSensorHasDataFunc(sid, start, end)
	}
	return nil, nil
}

func (m *MockOrganization) GetSensorsWithTag(tag string) (map[string][]string, error) {
	if m.GetSensorsWithTagFunc != nil {
		return m.GetSensorsWithTagFunc(tag)
	}
	return make(map[string][]string), nil
}

func (m *MockOrganization) GetAllTags() ([]string, error) {
	if m.GetAllTagsFunc != nil {
		return m.GetAllTagsFunc()
	}
	return []string{}, nil
}

func (m *MockOrganization) DRRules(filters ...lc.DRRuleFilter) (map[string]lc.Dict, error) {
	if m.DRRulesFunc != nil {
		return m.DRRulesFunc(filters...)
	}
	return make(map[string]lc.Dict), nil
}

func (m *MockOrganization) DRRuleAdd(name string, detection interface{}, response interface{}, opts ...lc.NewDRRuleOptions) error {
	if m.DRRuleAddFunc != nil {
		return m.DRRuleAddFunc(name, detection, response, opts...)
	}
	return nil
}

func (m *MockOrganization) DRRuleDelete(name string, filters ...lc.DRRuleFilter) error {
	if m.DRRuleDeleteFunc != nil {
		return m.DRRuleDeleteFunc(name, filters...)
	}
	return nil
}

func (m *MockOrganization) FPRules() (map[lc.FPRuleName]lc.FPRule, error) {
	if m.FPRulesFunc != nil {
		return m.FPRulesFunc()
	}
	return make(map[lc.FPRuleName]lc.FPRule), nil
}

func (m *MockOrganization) FPRuleAdd(name lc.FPRuleName, detection interface{}, opts ...lc.FPRuleOptions) error {
	if m.FPRuleAddFunc != nil {
		return m.FPRuleAddFunc(name, detection, opts...)
	}
	return nil
}

func (m *MockOrganization) FPRuleDelete(name lc.FPRuleName) error {
	if m.FPRuleDeleteFunc != nil {
		return m.FPRuleDeleteFunc(name)
	}
	return nil
}

func (m *MockOrganization) YaraListRules() (lc.YaraRules, error) {
	if m.YaraListRulesFunc != nil {
		return m.YaraListRulesFunc()
	}
	return lc.YaraRules{}, nil
}

func (m *MockOrganization) YaraGetSource(sourceName string) (string, error) {
	if m.YaraGetSourceFunc != nil {
		return m.YaraGetSourceFunc(sourceName)
	}
	return "", nil
}

func (m *MockOrganization) YaraSourceAdd(sourceName string, source lc.YaraSource) error {
	if m.YaraSourceAddFunc != nil {
		return m.YaraSourceAddFunc(sourceName, source)
	}
	return nil
}

func (m *MockOrganization) YaraSourceDelete(sourceName string) error {
	if m.YaraSourceDeleteFunc != nil {
		return m.YaraSourceDeleteFunc(sourceName)
	}
	return nil
}

func (m *MockOrganization) GetHistoricEvents(sensorID string, req lc.HistoricEventsRequest) (chan lc.IteratedEvent, func(), error) {
	if m.GetHistoricEventsFunc != nil {
		return m.GetHistoricEventsFunc(sensorID, req)
	}
	ch := make(chan lc.IteratedEvent)
	close(ch)
	return ch, func() {}, nil
}

func (m *MockOrganization) Query(req lc.QueryRequest) (*lc.QueryResponse, error) {
	if m.QueryFunc != nil {
		return m.QueryFunc(req)
	}
	return nil, nil
}

func (m *MockOrganization) QueryAll(req lc.QueryRequest) (*lc.QueryIterator, error) {
	if m.QueryAllFunc != nil {
		return m.QueryAllFunc(req)
	}
	return nil, nil
}

func (m *MockOrganization) QueryAllWithContext(ctx context.Context, req lc.QueryRequest) (*lc.QueryIterator, error) {
	if m.QueryAllWithContextFunc != nil {
		return m.QueryAllWithContextFunc(ctx, req)
	}
	return nil, nil
}

func (m *MockOrganization) QueryWithContext(ctx context.Context, req lc.QueryRequest) (*lc.QueryResponse, error) {
	if m.QueryWithContextFunc != nil {
		return m.QueryWithContextFunc(ctx, req)
	}
	return nil, nil
}

func (m *MockOrganization) HistoricalDetections(detectionReq lc.HistoricalDetectionsRequest) (lc.HistoricalDetectionsResponse, error) {
	if m.HistoricalDetectionsFunc != nil {
		return m.HistoricalDetectionsFunc(detectionReq)
	}
	return lc.HistoricalDetectionsResponse{}, nil
}

func (m *MockOrganization) InsightObjects(insightReq lc.InsightObjectsRequest) (lc.InsightObjectsResponse, error) {
	if m.InsightObjectsFunc != nil {
		return m.InsightObjectsFunc(insightReq)
	}
	return lc.InsightObjectsResponse{}, nil
}

func (m *MockOrganization) InsightObjectsBatch(insightReq lc.InsightObjectsBatchRequest) (lc.InsightObjectBatchResponse, error) {
	if m.InsightObjectsBatchFunc != nil {
		return m.InsightObjectsBatchFunc(insightReq)
	}
	return lc.InsightObjectBatchResponse{}, nil
}

func (m *MockOrganization) ExportArtifact(artifactID string, deadline time.Time) error {
	if m.ExportArtifactFunc != nil {
		return m.ExportArtifactFunc(artifactID, deadline)
	}
	return nil
}

func (m *MockOrganization) Outputs() (lc.OutputsByName, error) {
	if m.OutputsFunc != nil {
		return m.OutputsFunc()
	}
	return make(lc.OutputsByName), nil
}

func (m *MockOrganization) OutputAdd(output lc.OutputConfig) (lc.OutputConfig, error) {
	if m.OutputAddFunc != nil {
		return m.OutputAddFunc(output)
	}
	return lc.OutputConfig{}, nil
}

func (m *MockOrganization) OutputDel(name string) (lc.GenericJSON, error) {
	if m.OutputDelFunc != nil {
		return m.OutputDelFunc(name)
	}
	return lc.GenericJSON{}, nil
}

func (m *MockOrganization) InstallationKeys() ([]lc.InstallationKey, error) {
	if m.InstallationKeysFunc != nil {
		return m.InstallationKeysFunc()
	}
	return []lc.InstallationKey{}, nil
}

func (m *MockOrganization) InstallationKey(iid string) (*lc.InstallationKey, error) {
	if m.InstallationKeyFunc != nil {
		return m.InstallationKeyFunc(iid)
	}
	return nil, nil
}

func (m *MockOrganization) AddInstallationKey(k lc.InstallationKey) (string, error) {
	if m.AddInstallationKeyFunc != nil {
		return m.AddInstallationKeyFunc(k)
	}
	return "", nil
}

func (m *MockOrganization) DelInstallationKey(iid string) error {
	if m.DelInstallationKeyFunc != nil {
		return m.DelInstallationKeyFunc(iid)
	}
	return nil
}

func (m *MockOrganization) GetAPIKeys() ([]lc.APIKeyInfo, error) {
	if m.GetAPIKeysFunc != nil {
		return m.GetAPIKeysFunc()
	}
	return []lc.APIKeyInfo{}, nil
}

func (m *MockOrganization) CreateAPIKey(name string, permissions []string) (*lc.APIKeyCreate, error) {
	if m.CreateAPIKeyFunc != nil {
		return m.CreateAPIKeyFunc(name, permissions)
	}
	return nil, nil
}

func (m *MockOrganization) DeleteAPIKey(keyHash string) error {
	if m.DeleteAPIKeyFunc != nil {
		return m.DeleteAPIKeyFunc(keyHash)
	}
	return nil
}

func (m *MockOrganization) GetSchema(name string) (*lc.SchemaResponse, error) {
	if m.GetSchemaFunc != nil {
		return m.GetSchemaFunc(name)
	}
	return nil, nil
}

func (m *MockOrganization) GetSchemas() (*lc.Schemas, error) {
	if m.GetSchemasFunc != nil {
		return m.GetSchemasFunc()
	}
	return nil, nil
}

func (m *MockOrganization) GetSchemasForPlatform(platform string) (*lc.Schemas, error) {
	if m.GetSchemasForPlatformFunc != nil {
		return m.GetSchemasForPlatformFunc(platform)
	}
	return nil, nil
}

func (m *MockOrganization) GetPlatformNames() ([]string, error) {
	if m.GetPlatformNamesFunc != nil {
		return m.GetPlatformNamesFunc()
	}
	return []string{}, nil
}

func (m *MockOrganization) Extensions() ([]lc.ExtensionName, error) {
	if m.ExtensionsFunc != nil {
		return m.ExtensionsFunc()
	}
	return []lc.ExtensionName{}, nil
}

func (m *MockOrganization) SubscribeToExtension(name lc.ExtensionName) error {
	if m.SubscribeToExtensionFunc != nil {
		return m.SubscribeToExtensionFunc(name)
	}
	return nil
}

func (m *MockOrganization) UnsubscribeFromExtension(name lc.ExtensionName) error {
	if m.UnsubscribeFromExtensionFunc != nil {
		return m.UnsubscribeFromExtensionFunc(name)
	}
	return nil
}

func (m *MockOrganization) GetOrgErrors() ([]lc.OrgError, error) {
	if m.GetOrgErrorsFunc != nil {
		return m.GetOrgErrorsFunc()
	}
	return []lc.OrgError{}, nil
}

func (m *MockOrganization) DismissOrgError(component string) error {
	if m.DismissOrgErrorFunc != nil {
		return m.DismissOrgErrorFunc(component)
	}
	return nil
}

func (m *MockOrganization) ListUserOrgs(offset, limit *int, filter, sortBy, sortOrder *string, withNames bool) ([]lc.UserOrgInfo, error) {
	if m.ListUserOrgsFunc != nil {
		return m.ListUserOrgsFunc(offset, limit, filter, sortBy, sortOrder, withNames)
	}
	return []lc.UserOrgInfo{}, nil
}

func (m *MockOrganization) CreateOrganization(location, name string, template ...interface{}) (lc.NewOrganizationResponse, error) {
	if m.CreateOrganizationFunc != nil {
		return m.CreateOrganizationFunc(location, name, template...)
	}
	return lc.NewOrganizationResponse{}, nil
}

func (m *MockOrganization) GetBillingOrgDetails() (*lc.BillingOrgDetails, error) {
	if m.GetBillingOrgDetailsFunc != nil {
		return m.GetBillingOrgDetailsFunc()
	}
	return nil, nil
}

func (m *MockOrganization) GetBillingInvoiceURL(year, month int, format string) (map[string]interface{}, error) {
	if m.GetBillingInvoiceURLFunc != nil {
		return m.GetBillingInvoiceURLFunc(year, month, format)
	}
	return make(map[string]interface{}), nil
}

func (m *MockOrganization) GetMITREReport() (*lc.MITREReport, error) {
	if m.GetMITREReportFunc != nil {
		return m.GetMITREReportFunc()
	}
	return nil, nil
}

func (m *MockOrganization) GenericGETRequest(path string, query lc.Dict, response interface{}) error {
	if m.GenericGETRequestFunc != nil {
		return m.GenericGETRequestFunc(path, query, response)
	}
	return nil
}

func (m *MockOrganization) GenericPOSTRequest(path string, data lc.Dict, response interface{}) error {
	if m.GenericPOSTRequestFunc != nil {
		return m.GenericPOSTRequestFunc(path, data, response)
	}
	return nil
}

func (m *MockOrganization) WithInvestigationID(invID string) *lc.Organization {
	if m.WithInvestigationIDFunc != nil {
		return m.WithInvestigationIDFunc(invID)
	}
	return nil
}

// createTestContext creates a context with auth and SDK cache for testing
func createTestContext(t *testing.T, mockOrg *MockOrganization) context.Context {
	t.Helper()

	// Create SDK cache
	cache := auth.NewSDKCache(5*time.Minute, nil)

	// Create auth context
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

// getTextContent extracts text from MCP Content interface
func getTextContent(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	require.NotNil(t, result)
	require.NotEmpty(t, result.Content)

	textContent, ok := mcp.AsTextContent(result.Content[0])
	require.True(t, ok, "Content should be TextContent")
	return textContent.Text
}

// Integration Tests

func TestTestToolIntegration(t *testing.T) {
	t.Run("returns success with proper MCP format", func(t *testing.T) {
		mockOrg := &MockOrganization{}
		ctx := createTestContext(t, mockOrg)

		// Get test_tool registration
		reg, ok := tools.GetTool("test_tool")
		require.True(t, ok, "test_tool should be registered")

		// Call handler
		result, err := reg.Handler(ctx, map[string]interface{}{})

		// Verify
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.False(t, result.IsError)
		assert.NotEmpty(t, result.Content)

		// Verify content contains expected fields
		content := getTextContent(t, result)
		assert.Contains(t, content, "status")
		assert.Contains(t, content, "message")
	})
}

func TestGetSensorInfoIntegration(t *testing.T) {
	t.Run("returns sensor info with valid SID", func(t *testing.T) {
		// Setup mock with valid UUID format SID
		validSID := "12345678-1234-1234-1234-123456789012"
		mockSensor := &lc.Sensor{
			SID:          validSID,
			Hostname:     "test-host",
			Platform:     1, // Linux platform ID
			Architecture: 1, // x86_64 architecture ID
			AliveTS:      "1234567890",
			EnrollTS:     "1234567890",
			InternalIP:   "192.168.1.100",
			ExternalIP:   "203.0.113.1",
			OID:          "test-org-id",
			IsIsolated:   false,
		}

		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				if sid == validSID {
					return mockSensor
				}
				return nil
			},
		}

		ctx := createTestContext(t, mockOrg)

		// Get tool registration
		reg, ok := tools.GetTool("get_sensor_info")
		require.True(t, ok)

		// Call handler
		args := map[string]interface{}{
			"sid": validSID,
		}
		result, err := reg.Handler(ctx, args)

		// Verify
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.False(t, result.IsError)

		// Verify content contains sensor fields
		content := getTextContent(t, result)
		assert.Contains(t, content, validSID)
		assert.Contains(t, content, "test-host")
	})

	t.Run("returns error with invalid SID", func(t *testing.T) {
		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return nil
			},
		}

		ctx := createTestContext(t, mockOrg)

		reg, ok := tools.GetTool("get_sensor_info")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "invalid-sid",
		}
		result, err := reg.Handler(ctx, args)

		// Verify error response
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.IsError)
	})

	t.Run("returns error with missing SID", func(t *testing.T) {
		mockOrg := &MockOrganization{}
		ctx := createTestContext(t, mockOrg)

		reg, ok := tools.GetTool("get_sensor_info")
		require.True(t, ok)

		args := map[string]interface{}{}
		result, err := reg.Handler(ctx, args)

		// Verify error response
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.IsError)
	})
}

func TestListSensorsIntegration(t *testing.T) {
	t.Run("returns list of sensors", func(t *testing.T) {
		mockSensors := map[string]*lc.Sensor{
			"sid-1": {
				SID:        "sid-1",
				Hostname:   "host-1",
				Platform:   1, // Linux
				InternalIP: "192.168.1.1",
			},
			"sid-2": {
				SID:        "sid-2",
				Hostname:   "host-2",
				Platform:   2, // Windows
				InternalIP: "192.168.1.2",
			},
		}

		mockOrg := &MockOrganization{
			ListSensorsFunc: func(options ...lc.ListSensorsOptions) (map[string]*lc.Sensor, error) {
				return mockSensors, nil
			},
		}

		ctx := createTestContext(t, mockOrg)

		reg, ok := tools.GetTool("list_sensors")
		require.True(t, ok)

		result, err := reg.Handler(ctx, map[string]interface{}{})

		// Verify
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.False(t, result.IsError)

		content := getTextContent(t, result)
		assert.Contains(t, content, "sid-1")
		assert.Contains(t, content, "sid-2")
		assert.Contains(t, content, "host-1")
		assert.Contains(t, content, "host-2")
	})

	t.Run("filters by hostname prefix", func(t *testing.T) {
		mockSensors := map[string]*lc.Sensor{
			"sid-1": {SID: "sid-1", Hostname: "web-server-1"},
			"sid-2": {SID: "sid-2", Hostname: "db-server-1"},
			"sid-3": {SID: "sid-3", Hostname: "web-server-2"},
		}

		mockOrg := &MockOrganization{
			ListSensorsFunc: func(options ...lc.ListSensorsOptions) (map[string]*lc.Sensor, error) {
				return mockSensors, nil
			},
		}

		ctx := createTestContext(t, mockOrg)

		reg, ok := tools.GetTool("list_sensors")
		require.True(t, ok)

		args := map[string]interface{}{
			"with_hostname_prefix": "web",
		}
		result, err := reg.Handler(ctx, args)

		// Verify
		require.NoError(t, err)
		assert.False(t, result.IsError)

		content := getTextContent(t, result)
		assert.Contains(t, content, "web-server-1")
		assert.Contains(t, content, "web-server-2")
		assert.NotContains(t, content, "db-server-1")
	})
}

func TestSearchHostsIntegration(t *testing.T) {
	t.Run("searches with wildcard pattern", func(t *testing.T) {
		mockSensors := map[string]*lc.Sensor{
			"sid-1": {SID: "sid-1", Hostname: "web-prod-1"},
			"sid-2": {SID: "sid-2", Hostname: "web-prod-2"},
			"sid-3": {SID: "sid-3", Hostname: "db-prod-1"},
			"sid-4": {SID: "sid-4", Hostname: "web-dev-1"},
		}

		mockOrg := &MockOrganization{
			ListSensorsFunc: func(options ...lc.ListSensorsOptions) (map[string]*lc.Sensor, error) {
				return mockSensors, nil
			},
		}

		ctx := createTestContext(t, mockOrg)

		reg, ok := tools.GetTool("search_hosts")
		require.True(t, ok)

		args := map[string]interface{}{
			"hostname_expr": "web-prod-*",
		}
		result, err := reg.Handler(ctx, args)

		// Verify
		require.NoError(t, err)
		assert.False(t, result.IsError)

		content := getTextContent(t, result)
		assert.Contains(t, content, "web-prod-1")
		assert.Contains(t, content, "web-prod-2")
		assert.NotContains(t, content, "db-prod-1")
		assert.NotContains(t, content, "web-dev-1")
	})
}

func TestIsOnlineIntegration(t *testing.T) {
	t.Run("checks sensor online status", func(t *testing.T) {
		// Note: IsOnline makes an actual API call, so we test that the tool
		// properly handles a sensor object. Full functionality requires
		// a real API connection or more complex mocking.

		mockOrg := &MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				// Return nil to simulate sensor not found
				return nil
			},
		}

		ctx := createTestContext(t, mockOrg)

		reg, ok := tools.GetTool("is_online")
		require.True(t, ok)

		args := map[string]interface{}{
			"sid": "test-sid",
		}
		result, err := reg.Handler(ctx, args)

		// Verify - should return sensor not found error
		require.NoError(t, err)
		assert.True(t, result.IsError)

		content := getTextContent(t, result)
		assert.Contains(t, content, "sensor not found")
	})
}

func TestMCPResultFormatting(t *testing.T) {
	t.Run("success result has correct format", func(t *testing.T) {
		data := map[string]interface{}{
			"status": "ok",
			"count":  5,
		}

		result := tools.SuccessResult(data)

		assert.NotNil(t, result)
		assert.False(t, result.IsError)
		assert.Len(t, result.Content, 1)

		content := getTextContent(t, result)
		assert.Contains(t, content, "status")
		assert.Contains(t, content, "ok")
	})

	t.Run("error result has correct format", func(t *testing.T) {
		result := tools.ErrorResult("test error message")

		assert.NotNil(t, result)
		assert.True(t, result.IsError)
		assert.Len(t, result.Content, 1)

		content := getTextContent(t, result)
		assert.Contains(t, content, "test error message")
	})
}
