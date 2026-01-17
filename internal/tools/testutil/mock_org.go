package testutil

import (
	"context"
	"io"
	"time"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

// MockOrganization is a mock implementation of tools.OrganizationClient for testing
// It allows tests to specify behavior for each method via function fields
type MockOrganization struct {
	// Core Organization Info
	GetOIDFunc        func() string
	GetInfoFunc       func() (lc.OrganizationInformation, error)
	GetUsageStatsFunc func() (lc.Dict, error)

	// Sensor Operations
	GetSensorFunc                func(sid string) *lc.Sensor
	GetSensorsFunc               func(sids []string) map[string]*lc.Sensor
	ListSensorsFunc              func(options ...lc.ListSensorsOptions) (map[string]*lc.Sensor, error)
	ActiveSensorsFunc            func(sids []string) (map[string]bool, error)
	GetTimeWhenSensorHasDataFunc func(sid string, start, end int64) (*lc.SensorTimeData, error)
	GetSensorsWithTagFunc        func(tag string) (map[string][]string, error)
	GetAllTagsFunc               func() ([]string, error)

	// Detection & Response Rules
	DRRulesFunc      func(filters ...lc.DRRuleFilter) (map[string]lc.Dict, error)
	DRRuleAddFunc    func(name string, detection interface{}, response interface{}, opts ...lc.NewDRRuleOptions) error
	DRRuleDeleteFunc func(name string, filters ...lc.DRRuleFilter) error

	// D&R Rule Replay and Validation
	ReplayDRRuleFunc   func(req lc.ReplayDRRuleRequest) (*lc.ReplayDRRuleResponse, error)
	ValidateDRRuleFunc func(rule lc.Dict) (*lc.ValidationResponse, error)

	// False Positive Rules
	FPRulesFunc      func() (map[lc.FPRuleName]lc.FPRule, error)
	FPRuleAddFunc    func(name lc.FPRuleName, detection interface{}, opts ...lc.FPRuleOptions) error
	FPRuleDeleteFunc func(name lc.FPRuleName) error

	// YARA Rules
	YaraListRulesFunc    func() (lc.YaraRules, error)
	YaraGetSourceFunc    func(sourceName string) (string, error)
	YaraSourceAddFunc    func(sourceName string, source lc.YaraSource) error
	YaraSourceDeleteFunc func(sourceName string) error

	// Historical Data & Queries
	GetHistoricEventsFunc            func(sensorID string, req lc.HistoricEventsRequest) (chan lc.IteratedEvent, func(), error)
	QueryFunc                        func(req lc.QueryRequest) (*lc.QueryResponse, error)
	QueryAllFunc                     func(req lc.QueryRequest) (*lc.QueryIterator, error)
	QueryAllWithContextFunc          func(ctx context.Context, req lc.QueryRequest) (*lc.QueryIterator, error)
	QueryWithContextFunc             func(ctx context.Context, req lc.QueryRequest) (*lc.QueryResponse, error)
	HistoricalDetectionsFunc         func(detectionReq lc.HistoricalDetectionsRequest) (lc.HistoricalDetectionsResponse, error)
	InsightObjectsFunc               func(insightReq lc.InsightObjectsRequest) (lc.InsightObjectsResponse, error)
	InsightObjectsBatchFunc          func(insightReq lc.InsightObjectsBatchRequest) (lc.InsightObjectBatchResponse, error)
	ValidateLCQLQueryFunc            func(query string) (*lc.ValidationResponse, error)
	EstimateLCQLQueryBillingFunc     func(query string) (*lc.BillingEstimate, error)
	ValidateAndEstimateLCQLQueryFunc func(query string) (*lc.QueryValidationResult, error)

	// Artifacts
	ExportArtifactFunc func(artifactID string, deadline time.Time) (io.ReadCloser, error)

	// Outputs
	OutputsFunc   func() (lc.OutputsByName, error)
	OutputAddFunc func(output lc.OutputConfig) (lc.OutputConfig, error)
	OutputDelFunc func(name string) (lc.GenericJSON, error)

	// Installation Keys
	InstallationKeysFunc   func() ([]lc.InstallationKey, error)
	InstallationKeyFunc    func(iid string) (*lc.InstallationKey, error)
	AddInstallationKeyFunc func(k lc.InstallationKey) (string, error)
	DelInstallationKeyFunc func(iid string) error

	// API Keys
	GetAPIKeysFunc              func() ([]lc.APIKeyInfo, error)
	CreateAPIKeyFunc            func(name string, permissions []string) (*lc.APIKeyCreate, error)
	CreateAPIKeyWithOptionsFunc func(name string, permissions []string, allowedIPRange string) (*lc.APIKeyCreate, error)
	DeleteAPIKeyFunc            func(keyHash string) error

	// User Management
	GetUsersFunc             func() ([]string, error)
	AddUserFunc              func(email string, inviteMissing bool, role string) (*lc.AddUserResponse, error)
	RemoveUserFunc           func(email string) error
	GetUsersPermissionsFunc  func() (*lc.OrgUsersPermissions, error)
	AddUserPermissionFunc    func(email, perm string) error
	RemoveUserPermissionFunc func(email, perm string) error
	SetUserRoleFunc          func(email, role string) (*lc.SetUserRoleResponse, error)

	// Schemas
	GetSchemaFunc             func(name string) (*lc.SchemaResponse, error)
	GetSchemasFunc            func() (*lc.Schemas, error)
	GetSchemasForPlatformFunc func(platform string) (*lc.Schemas, error)
	GetPlatformNamesFunc      func() ([]string, error)

	// Extensions
	ExtensionsFunc               func() ([]lc.ExtensionName, error)
	SubscribeToExtensionFunc     func(name lc.ExtensionName) error
	UnsubscribeFromExtensionFunc func(name lc.ExtensionName) error

	// Organization Management
	GetOrgErrorsFunc       func() ([]lc.OrgError, error)
	DismissOrgErrorFunc    func(component string) error
	ListUserOrgsFunc       func(offset, limit *int, filter, sortBy, sortOrder *string, withNames bool) ([]lc.UserOrgInfo, error)
	CreateOrganizationFunc func(location, name string, template ...interface{}) (lc.NewOrganizationResponse, error)

	// Billing
	GetBillingOrgDetailsFunc func() (*lc.BillingOrgDetails, error)
	GetBillingInvoiceURLFunc func(year, month int, format string) (map[string]interface{}, error)

	// MITRE ATT&CK
	GetMITREReportFunc func() (*lc.MITREReport, error)

	// Generic Requests
	GenericGETRequestFunc  func(path string, query lc.Dict, response interface{}) error
	GenericPOSTRequestFunc func(path string, data lc.Dict, response interface{}) error

	// Investigation Context
	WithInvestigationIDFunc func(invID string) *lc.Organization
}

// Core Organization Info
func (m *MockOrganization) GetOID() string {
	if m.GetOIDFunc != nil {
		return m.GetOIDFunc()
	}
	return "test-org-id"
}

func (m *MockOrganization) GetInfo() (lc.OrganizationInformation, error) {
	if m.GetInfoFunc != nil {
		return m.GetInfoFunc()
	}
	return lc.OrganizationInformation{}, nil
}

func (m *MockOrganization) GetUsageStats() (lc.Dict, error) {
	if m.GetUsageStatsFunc != nil {
		return m.GetUsageStatsFunc()
	}
	return nil, nil
}

// Sensor Operations
func (m *MockOrganization) GetSensor(sid string) *lc.Sensor {
	if m.GetSensorFunc != nil {
		return m.GetSensorFunc(sid)
	}
	return nil
}

func (m *MockOrganization) GetSensors(sids []string) map[string]*lc.Sensor {
	if m.GetSensorsFunc != nil {
		return m.GetSensorsFunc(sids)
	}
	return nil
}

func (m *MockOrganization) ListSensors(options ...lc.ListSensorsOptions) (map[string]*lc.Sensor, error) {
	if m.ListSensorsFunc != nil {
		return m.ListSensorsFunc(options...)
	}
	return nil, nil
}

func (m *MockOrganization) ActiveSensors(sids []string) (map[string]bool, error) {
	if m.ActiveSensorsFunc != nil {
		return m.ActiveSensorsFunc(sids)
	}
	return nil, nil
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
	return nil, nil
}

func (m *MockOrganization) GetAllTags() ([]string, error) {
	if m.GetAllTagsFunc != nil {
		return m.GetAllTagsFunc()
	}
	return nil, nil
}

// Detection & Response Rules
func (m *MockOrganization) DRRules(filters ...lc.DRRuleFilter) (map[string]lc.Dict, error) {
	if m.DRRulesFunc != nil {
		return m.DRRulesFunc(filters...)
	}
	return nil, nil
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

// D&R Rule Replay and Validation
func (m *MockOrganization) ReplayDRRule(req lc.ReplayDRRuleRequest) (*lc.ReplayDRRuleResponse, error) {
	if m.ReplayDRRuleFunc != nil {
		return m.ReplayDRRuleFunc(req)
	}
	return nil, nil
}

func (m *MockOrganization) ValidateDRRule(rule lc.Dict) (*lc.ValidationResponse, error) {
	if m.ValidateDRRuleFunc != nil {
		return m.ValidateDRRuleFunc(rule)
	}
	return nil, nil
}

// False Positive Rules
func (m *MockOrganization) FPRules() (map[lc.FPRuleName]lc.FPRule, error) {
	if m.FPRulesFunc != nil {
		return m.FPRulesFunc()
	}
	return nil, nil
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

// YARA Rules
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

// Historical Data & Queries
func (m *MockOrganization) GetHistoricEvents(sensorID string, req lc.HistoricEventsRequest) (chan lc.IteratedEvent, func(), error) {
	if m.GetHistoricEventsFunc != nil {
		return m.GetHistoricEventsFunc(sensorID, req)
	}
	return nil, nil, nil
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

func (m *MockOrganization) ValidateLCQLQuery(query string) (*lc.ValidationResponse, error) {
	if m.ValidateLCQLQueryFunc != nil {
		return m.ValidateLCQLQueryFunc(query)
	}
	return &lc.ValidationResponse{Success: true}, nil
}

func (m *MockOrganization) EstimateLCQLQueryBilling(query string) (*lc.BillingEstimate, error) {
	if m.EstimateLCQLQueryBillingFunc != nil {
		return m.EstimateLCQLQueryBillingFunc(query)
	}
	return &lc.BillingEstimate{}, nil
}

func (m *MockOrganization) ValidateAndEstimateLCQLQuery(query string) (*lc.QueryValidationResult, error) {
	if m.ValidateAndEstimateLCQLQueryFunc != nil {
		return m.ValidateAndEstimateLCQLQueryFunc(query)
	}
	return &lc.QueryValidationResult{
		Validation:      &lc.ValidationResponse{Success: true},
		BillingEstimate: &lc.BillingEstimate{},
	}, nil
}

// Artifacts
func (m *MockOrganization) ExportArtifact(artifactID string, deadline time.Time) (io.ReadCloser, error) {
	if m.ExportArtifactFunc != nil {
		return m.ExportArtifactFunc(artifactID, deadline)
	}
	return nil, nil
}

// Outputs
func (m *MockOrganization) Outputs() (lc.OutputsByName, error) {
	if m.OutputsFunc != nil {
		return m.OutputsFunc()
	}
	return nil, nil
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
	return nil, nil
}

// Installation Keys
func (m *MockOrganization) InstallationKeys() ([]lc.InstallationKey, error) {
	if m.InstallationKeysFunc != nil {
		return m.InstallationKeysFunc()
	}
	return nil, nil
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

// API Keys
func (m *MockOrganization) GetAPIKeys() ([]lc.APIKeyInfo, error) {
	if m.GetAPIKeysFunc != nil {
		return m.GetAPIKeysFunc()
	}
	return nil, nil
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

func (m *MockOrganization) CreateAPIKeyWithOptions(name string, permissions []string, allowedIPRange string) (*lc.APIKeyCreate, error) {
	if m.CreateAPIKeyWithOptionsFunc != nil {
		return m.CreateAPIKeyWithOptionsFunc(name, permissions, allowedIPRange)
	}
	return nil, nil
}

// User Management
func (m *MockOrganization) GetUsers() ([]string, error) {
	if m.GetUsersFunc != nil {
		return m.GetUsersFunc()
	}
	return nil, nil
}

func (m *MockOrganization) AddUser(email string, inviteMissing bool, role string) (*lc.AddUserResponse, error) {
	if m.AddUserFunc != nil {
		return m.AddUserFunc(email, inviteMissing, role)
	}
	return nil, nil
}

func (m *MockOrganization) RemoveUser(email string) error {
	if m.RemoveUserFunc != nil {
		return m.RemoveUserFunc(email)
	}
	return nil
}

func (m *MockOrganization) GetUsersPermissions() (*lc.OrgUsersPermissions, error) {
	if m.GetUsersPermissionsFunc != nil {
		return m.GetUsersPermissionsFunc()
	}
	return nil, nil
}

func (m *MockOrganization) AddUserPermission(email, perm string) error {
	if m.AddUserPermissionFunc != nil {
		return m.AddUserPermissionFunc(email, perm)
	}
	return nil
}

func (m *MockOrganization) RemoveUserPermission(email, perm string) error {
	if m.RemoveUserPermissionFunc != nil {
		return m.RemoveUserPermissionFunc(email, perm)
	}
	return nil
}

func (m *MockOrganization) SetUserRole(email, role string) (*lc.SetUserRoleResponse, error) {
	if m.SetUserRoleFunc != nil {
		return m.SetUserRoleFunc(email, role)
	}
	return nil, nil
}

// Schemas
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
	return nil, nil
}

// Extensions
func (m *MockOrganization) Extensions() ([]lc.ExtensionName, error) {
	if m.ExtensionsFunc != nil {
		return m.ExtensionsFunc()
	}
	return nil, nil
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

// Organization Management
func (m *MockOrganization) GetOrgErrors() ([]lc.OrgError, error) {
	if m.GetOrgErrorsFunc != nil {
		return m.GetOrgErrorsFunc()
	}
	return nil, nil
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
	return nil, nil
}

func (m *MockOrganization) CreateOrganization(location, name string, template ...interface{}) (lc.NewOrganizationResponse, error) {
	if m.CreateOrganizationFunc != nil {
		return m.CreateOrganizationFunc(location, name, template...)
	}
	return lc.NewOrganizationResponse{}, nil
}

// Billing
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
	return nil, nil
}

// MITRE ATT&CK
func (m *MockOrganization) GetMITREReport() (*lc.MITREReport, error) {
	if m.GetMITREReportFunc != nil {
		return m.GetMITREReportFunc()
	}
	return nil, nil
}

// Generic Requests
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

// Investigation Context
func (m *MockOrganization) WithInvestigationID(invID string) *lc.Organization {
	if m.WithInvestigationIDFunc != nil {
		return m.WithInvestigationIDFunc(invID)
	}
	return nil
}
