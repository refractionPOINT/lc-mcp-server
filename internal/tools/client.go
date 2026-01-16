// This file defines the OrganizationClient interface for LimaCharlie organization operations.
//
// IMPORTANT: This is infrastructure for future use. Do NOT refactor existing code to use
// this interface yet. The interface is provided to enable:
//   - Writing unit tests with mocks instead of real API calls
//   - Dependency injection for better testability
//   - Easier testing of tool logic without LC credentials
//
// The actual *lc.Organization type automatically implements this interface (verified by
// the compile-time check at the bottom of this file).
package tools

import (
	"context"
	"io"
	"time"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

// OrganizationClient defines the interface for interacting with LimaCharlie organizations.
// This interface enables mocking for testing and provides a clean abstraction layer.
//
// The interface includes the most commonly used methods from lc.Organization.
// Not all Organization methods are included - only those actively used by the MCP server tools.
// Additional methods can be added as needed when new tools are developed.
//
// Usage in Tests:
//
// To create a mock implementation for testing, define a struct with function fields:
//
//	type MockOrganization struct {
//	    GetSensorFunc      func(sid string) *lc.Sensor
//	    ListSensorsFunc    func(opts ...lc.ListSensorsOptions) (map[string]*lc.Sensor, error)
//	    DRRulesFunc        func(filters ...lc.DRRuleFilter) (map[string]lc.Dict, error)
//	    // ... other methods as needed
//	}
//
//	func (m *MockOrganization) GetSensor(sid string) *lc.Sensor {
//	    if m.GetSensorFunc != nil {
//	        return m.GetSensorFunc(sid)
//	    }
//	    return nil
//	}
//
//	func (m *MockOrganization) ListSensors(opts ...lc.ListSensorsOptions) (map[string]*lc.Sensor, error) {
//	    if m.ListSensorsFunc != nil {
//	        return m.ListSensorsFunc(opts...)
//	    }
//	    return nil, nil
//	}
//
// Then use the mock in your tests:
//
//	mock := &MockOrganization{
//	    GetSensorFunc: func(sid string) *lc.Sensor {
//	        return &lc.Sensor{/* test data */}
//	    },
//	}
//
// Note: The actual *lc.Organization type automatically implements this interface.
// The compile-time check at the bottom of this file ensures compatibility.
type OrganizationClient interface {
	// Core Organization Info
	GetOID() string
	GetInfo() (lc.OrganizationInformation, error)
	GetUsageStats() (lc.Dict, error)

	// Sensor Operations
	GetSensor(sid string) *lc.Sensor
	GetSensors(sids []string) map[string]*lc.Sensor
	ListSensors(options ...lc.ListSensorsOptions) (map[string]*lc.Sensor, error)
	ActiveSensors(sids []string) (map[string]bool, error)
	GetTimeWhenSensorHasData(sid string, start, end int64) (*lc.SensorTimeData, error)
	GetSensorsWithTag(tag string) (map[string][]string, error)
	GetAllTags() ([]string, error)

	// Detection & Response Rules
	DRRules(filters ...lc.DRRuleFilter) (map[string]lc.Dict, error)
	DRRuleAdd(name string, detection interface{}, response interface{}, opts ...lc.NewDRRuleOptions) error
	DRRuleDelete(name string, filters ...lc.DRRuleFilter) error

	// D&R Rule Replay and Validation
	ReplayDRRule(req lc.ReplayDRRuleRequest) (*lc.ReplayDRRuleResponse, error)
	ValidateDRRule(rule lc.Dict) (*lc.ValidationResponse, error)

	// False Positive Rules
	FPRules() (map[lc.FPRuleName]lc.FPRule, error)
	FPRuleAdd(name lc.FPRuleName, detection interface{}, opts ...lc.FPRuleOptions) error
	FPRuleDelete(name lc.FPRuleName) error

	// YARA Rules
	YaraListRules() (lc.YaraRules, error)
	YaraGetSource(sourceName string) (string, error)
	YaraSourceAdd(sourceName string, source lc.YaraSource) error
	YaraSourceDelete(sourceName string) error

	// Historical Data & Queries
	GetHistoricEvents(sensorID string, req lc.HistoricEventsRequest) (chan lc.IteratedEvent, func(), error)
	Query(req lc.QueryRequest) (*lc.QueryResponse, error)
	QueryAll(req lc.QueryRequest) (*lc.QueryIterator, error)
	QueryAllWithContext(ctx context.Context, req lc.QueryRequest) (*lc.QueryIterator, error)
	QueryWithContext(ctx context.Context, req lc.QueryRequest) (*lc.QueryResponse, error)
	HistoricalDetections(detectionReq lc.HistoricalDetectionsRequest) (lc.HistoricalDetectionsResponse, error)
	InsightObjects(insightReq lc.InsightObjectsRequest) (lc.InsightObjectsResponse, error)
	InsightObjectsBatch(insightReq lc.InsightObjectsBatchRequest) (lc.InsightObjectBatchResponse, error)
	ValidateLCQLQuery(query string) (*lc.ValidationResponse, error)
	EstimateLCQLQueryBilling(query string) (*lc.BillingEstimate, error)
	ValidateAndEstimateLCQLQuery(query string) (*lc.QueryValidationResult, error)

	// Artifacts
	ExportArtifact(artifactID string, deadline time.Time) (io.ReadCloser, error)

	// Outputs
	Outputs() (lc.OutputsByName, error)
	OutputAdd(output lc.OutputConfig) (lc.OutputConfig, error)
	OutputDel(name string) (lc.GenericJSON, error)

	// Installation Keys
	InstallationKeys() ([]lc.InstallationKey, error)
	InstallationKey(iid string) (*lc.InstallationKey, error)
	AddInstallationKey(k lc.InstallationKey) (string, error)
	DelInstallationKey(iid string) error

	// API Keys
	GetAPIKeys() ([]lc.APIKeyInfo, error)
	CreateAPIKey(name string, permissions []string) (*lc.APIKeyCreate, error)
	DeleteAPIKey(keyHash string) error

	// Schemas
	GetSchema(name string) (*lc.SchemaResponse, error)
	GetSchemas() (*lc.Schemas, error)
	GetSchemasForPlatform(platform string) (*lc.Schemas, error)
	GetPlatformNames() ([]string, error)

	// Extensions
	Extensions() ([]lc.ExtensionName, error)
	SubscribeToExtension(name lc.ExtensionName) error
	UnsubscribeFromExtension(name lc.ExtensionName) error

	// Organization Management
	GetOrgErrors() ([]lc.OrgError, error)
	DismissOrgError(component string) error
	ListUserOrgs(offset, limit *int, filter, sortBy, sortOrder *string, withNames bool) ([]lc.UserOrgInfo, error)
	CreateOrganization(location, name string, template ...interface{}) (lc.NewOrganizationResponse, error)

	// Billing
	GetBillingOrgDetails() (*lc.BillingOrgDetails, error)
	GetBillingInvoiceURL(year, month int, format string) (map[string]interface{}, error)

	// MITRE ATT&CK
	GetMITREReport() (*lc.MITREReport, error)

	// Generic Requests (for operations not covered by specific methods)
	GenericGETRequest(path string, query lc.Dict, response interface{}) error
	GenericPOSTRequest(path string, data lc.Dict, response interface{}) error

	// Investigation Context
	WithInvestigationID(invID string) *lc.Organization
}

// Compile-time check to ensure *lc.Organization implements OrganizationClient.
// This will cause a compilation error if the interface becomes incompatible with
// the actual Organization type, alerting developers to interface changes.
var _ OrganizationClient = (*lc.Organization)(nil)
