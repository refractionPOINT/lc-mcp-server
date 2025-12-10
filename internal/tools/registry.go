package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/gcs"
)

// ToolHandler is the function signature for MCP tool handlers
type ToolHandler func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error)

// ToolRegistration holds a tool's metadata and handler.
// It supports both interface-based tools (via Tool field) and legacy struct-based tools
// (via individual fields). This dual support maintains backward compatibility while
// enabling migration to the cleaner interface-based architecture.
//
// When Tool is set, it takes precedence and the individual fields are ignored.
// Otherwise, the legacy fields are used for backward compatibility.
type ToolRegistration struct {
	// Tool is the interface-based tool implementation (preferred)
	// If set, this takes precedence over the legacy fields below
	Tool Tool

	// Legacy struct fields (kept for backward compatibility)
	// These are used when Tool is nil
	Name        string
	Description string
	Handler     ToolHandler
	Schema      mcp.Tool
	Profile     string
	RequiresOID bool // Whether tool requires an OID parameter in UID mode
}

// Global tool registry
var registry = make(map[string]*ToolRegistration)

// Profile definitions matching Python implementation
var ProfileDefinitions = map[string][]string{
	"core": {
		"test_tool",
		"get_sensor_info",
		"list_sensors",
		"get_online_sensors",
		"is_online",
		"search_hosts",
		"list_sensor_tags",
	},
	"historical_data": {
		"run_lcql_query",
		"get_historic_events",
		"get_historic_detections",
		"search_iocs",
		"batch_search_iocs",
		"get_time_when_sensor_has_data",
		// Saved queries
		"list_saved_queries",
		"get_saved_query",
		"run_saved_query",
		"set_saved_query",
		"delete_saved_query",
		// Event schemas
		"get_event_schema",
		"get_event_schemas_batch",
		"get_event_types_with_schemas",
		"get_event_types_with_schemas_for_platform",
		// Platform info
		"get_platform_names",
		"list_with_platform",
	},
	"historical_data_readonly": {
		// Same as historical_data but conceptually read-only
		"run_lcql_query",
		"get_historic_events",
		"get_historic_detections",
		"search_iocs",
		"batch_search_iocs",
		"get_time_when_sensor_has_data",
		// Saved queries (read-only - excludes set/delete)
		"list_saved_queries",
		"get_saved_query",
		"run_saved_query",
		// Event schemas (read-only)
		"get_event_schema",
		"get_event_schemas_batch",
		"get_event_types_with_schemas",
		"get_event_types_with_schemas_for_platform",
		// Platform info (read-only)
		"get_platform_names",
		"list_with_platform",
	},
	"live_investigation": {
		"get_processes",
		"get_process_modules",
		"get_process_strings",
		"yara_scan_process",
		"yara_scan_file",
		"yara_scan_directory",
		"yara_scan_memory",
		"get_network_connections",
		"get_os_version",
		"get_users",
		"get_services",
		"get_drivers",
		"get_autoruns",
		"get_packages",
		"get_registry_keys",
		"find_strings",
		"dir_list",
		"dir_find_hash",
		// Velociraptor DFIR
		"list_velociraptor_artifacts",
		"show_velociraptor_artifact",
		"collect_velociraptor_artifact",
		// Artifacts
		"list_artifacts",
		"get_artifact",
	},
	"threat_response": {
		"isolate_network",
		"rejoin_network",
		"is_isolated",
		"add_tag",
		"remove_tag",
		"delete_sensor",
		"reliable_tasking",
		"list_reliable_tasks",
	},
	"fleet_management": {
		"list_installation_keys",
		"create_installation_key",
		"delete_installation_key",
		"list_cloud_sensors",
		"get_cloud_sensor",
		"set_cloud_sensor",
		"delete_cloud_sensor",
		// Platform info
		"get_platform_names",
		"list_with_platform",
	},
	"detection_engineering": {
		"get_detection_rules",
		"get_historic_detections",
		// D&R General Rules
		"list_dr_general_rules",
		"get_dr_general_rule",
		"set_dr_general_rule",
		"delete_dr_general_rule",
		// D&R Managed Rules
		"list_dr_managed_rules",
		"get_dr_managed_rule",
		"set_dr_managed_rule",
		"delete_dr_managed_rule",
		// D&R validation
		"validate_dr_rule_components",
		// YARA Rules
		"list_yara_rules",
		"get_yara_rule",
		"set_yara_rule",
		"delete_yara_rule",
		"validate_yara_rule",
		// False Positive Rules
		"get_fp_rules",
		"get_fp_rule",
		"set_fp_rule",
		"delete_fp_rule",
		// MITRE ATT&CK
		"get_mitre_report",
		// Event schemas (for rule creation)
		"get_event_schema",
		"get_event_schemas_batch",
		"get_event_types_with_schemas",
		"get_event_types_with_schemas_for_platform",
	},
	"platform_admin": {
		// Organization Management
		"get_org_info",
		"get_usage_stats",
		"get_billing_details",
		"get_org_errors",
		"dismiss_org_error",
		"get_org_invoice_url",
		"get_sku_definitions",
		"create_org",
		"list_user_orgs",
		// Outputs
		"list_outputs",
		"add_output",
		"delete_output",
		// Secrets
		"list_secrets",
		"get_secret",
		"set_secret",
		"delete_secret",
		// Lookups
		"list_lookups",
		"get_lookup",
		"set_lookup",
		"delete_lookup",
		"query_lookup",
		// Playbooks
		"list_playbooks",
		"get_playbook",
		"set_playbook",
		"delete_playbook",
		// External Adapters
		"list_external_adapters",
		"get_external_adapter",
		"set_external_adapter",
		"delete_external_adapter",
		// Extensions
		"list_extension_configs",
		"get_extension_config",
		"set_extension_config",
		"delete_extension_config",
		"subscribe_to_extension",
		"unsubscribe_from_extension",
		// Hive Rules
		"list_rules",
		"get_rule",
		"set_rule",
		"delete_rule",
		// Saved Queries
		"list_saved_queries",
		"get_saved_query",
		"run_saved_query",
		"set_saved_query",
		"delete_saved_query",
		// API Keys
		"list_api_keys",
		"create_api_key",
		"delete_api_key",
		// Payloads
		"list_payloads",
		"create_payload",
		"get_payload",
		"delete_payload",
	},
	"ai_powered": {
		// AI-powered generation tools (to be implemented)
		"generate_lcql_query",
		"generate_dr_rule_detection",
		"generate_dr_rule_respond",
		"generate_sensor_selector",
		"generate_python_playbook",
		"generate_detection_summary",
	},
	"api_access": {
		// Meta-tool for calling other tools
		"lc_call_tool",
	},
	"timeline_management": {
		// Timeline tools for incident response investigations
		"expand_timeline",
		"list_timelines",
		"get_timeline",
		"set_timeline",
		"delete_timeline",
	},
}

// RegisterTool adds a tool to the registry
func RegisterTool(reg *ToolRegistration) {
	registry[reg.Name] = reg
}

// GetTool retrieves a tool from the registry
func GetTool(name string) (*ToolRegistration, bool) {
	tool, ok := registry[name]
	return tool, ok
}

// GetToolsForProfile returns all tool names for a given profile
func GetToolsForProfile(profile string) []string {
	if profile == "all" {
		// Return all tools from all profiles
		allTools := make(map[string]bool)
		for _, tools := range ProfileDefinitions {
			for _, tool := range tools {
				allTools[tool] = true
			}
		}
		result := make([]string, 0, len(allTools))
		for tool := range allTools {
			result = append(result, tool)
		}
		return result
	}

	tools, ok := ProfileDefinitions[profile]
	if !ok {
		return []string{}
	}
	return tools
}

// ValidateToolNames checks if all provided tool names exist in the registry
// Returns error with list of invalid tools if any are found
func ValidateToolNames(toolNames []string) error {
	var invalidTools []string
	for _, name := range toolNames {
		if _, exists := registry[name]; !exists {
			invalidTools = append(invalidTools, name)
		}
	}
	if len(invalidTools) > 0 {
		return fmt.Errorf("invalid tool names: %s", strings.Join(invalidTools, ", "))
	}
	return nil
}

// IsUIDMode checks if the auth mode supports OID switching
func IsUIDMode(authMode auth.AuthMode) bool {
	return authMode == auth.AuthModeUIDKey || authMode == auth.AuthModeUIDOAuth
}

// AddOIDToToolSchema adds the OID parameter to a tool's input schema
// This function creates a deep copy of the schema to avoid modifying shared state
// If the tool's base schema already defines "oid" as optional (in properties but not required),
// that choice is respected. Otherwise, "oid" is added as a required parameter.
func AddOIDToToolSchema(tool mcp.Tool) mcp.Tool {
	schema := tool.InputSchema

	// Check if OID was already in the original schema's required list
	oidInOriginalRequired := false
	for _, req := range schema.Required {
		if req == "oid" {
			oidInOriginalRequired = true
			break
		}
	}

	// Check if OID exists in original properties
	_, oidInOriginalProperties := schema.Properties["oid"]

	// Deep copy Properties map to avoid modifying the original
	newProperties := make(map[string]any, len(schema.Properties)+1)
	for k, v := range schema.Properties {
		newProperties[k] = v
	}

	// Add OID parameter if not already present in properties
	if !oidInOriginalProperties {
		newProperties["oid"] = map[string]any{
			"type":        "string",
			"description": "Organization ID",
		}
	}

	// Deep copy Required slice to avoid modifying the original
	newRequired := make([]string, len(schema.Required))
	copy(newRequired, schema.Required)

	// Determine if we should add "oid" to required list:
	// - If oid was in original required → keep it required
	// - If oid was in original properties but NOT required → keep it optional (tool's choice)
	// - If oid was NOT in original schema at all → add as required (default behavior)
	shouldAddOIDToRequired := oidInOriginalRequired || !oidInOriginalProperties

	if shouldAddOIDToRequired {
		// Check if "oid" is not already in the new required list
		oidAlreadyInNewRequired := false
		for _, req := range newRequired {
			if req == "oid" {
				oidAlreadyInNewRequired = true
				break
			}
		}
		if !oidAlreadyInNewRequired {
			newRequired = append(newRequired, "oid")
		}
	}

	// Create new schema with copied data
	newSchema := schema
	newSchema.Properties = newProperties
	newSchema.Required = newRequired

	// Return new tool with modified schema
	newTool := tool
	newTool.InputSchema = newSchema
	return newTool
}

// AddToolsToServer adds all tools for a profile to an MCP server.
// It supports both interface-based and legacy struct-based tools.
func AddToolsToServer(s *server.MCPServer, profile string, authMode auth.AuthMode) error {
	toolNames := GetToolsForProfile(profile)
	isUIDMode := IsUIDMode(authMode)

	for _, name := range toolNames {
		reg, ok := GetTool(name)
		if !ok {
			// Tool not implemented yet - skip silently
			continue
		}

		// Get schema from either interface or legacy fields
		var schema mcp.Tool
		var requiresOID bool

		if reg.Tool != nil {
			// Use interface-based tool
			schema = reg.Tool.Schema()
			requiresOID = reg.Tool.RequiresOID()
		} else {
			// Use legacy struct fields
			schema = reg.Schema
			requiresOID = reg.RequiresOID
		}

		// Dynamically add OID parameter if tool requires it and we're in UID mode
		if requiresOID && isUIDMode {
			schema = AddOIDToToolSchema(schema)
		}

		// Wrap handler to convert between MCP request and our handler signature
		wrappedHandler := wrapHandler(reg, isUIDMode)

		// Add tool to server
		s.AddTool(schema, wrappedHandler)
	}

	return nil
}

// wrapHandler converts our ToolHandler to mcp-go's expected signature,
// handles OID switching for tools that require it, and wraps large results with GCS if available.
// It supports both interface-based and legacy struct-based tools.
func wrapHandler(reg *ToolRegistration, isUIDMode bool) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract arguments using the method
		args := request.GetArguments()

		// Determine if tool requires OID from either interface or legacy fields
		var requiresOID bool
		var toolName string

		if reg.Tool != nil {
			requiresOID = reg.Tool.RequiresOID()
			toolName = reg.Tool.Name()
		} else {
			requiresOID = reg.RequiresOID
			toolName = reg.Name
		}

		// Automatically handle OID switching for tools that require it in UID mode
		if requiresOID && isUIDMode {
			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				// Pass nil logger - WithOID will use slog.Default() as fallback
				ctx, err = auth.WithOID(ctx, oidParam, nil)
				if err != nil {
					return mcp.NewToolResultError(fmt.Sprintf("failed to switch OID: %v", err)), nil
				}
			}
		}

		// Call the appropriate handler (interface or legacy)
		var result *mcp.CallToolResult
		var err error

		if reg.Tool != nil {
			// Use interface-based tool
			result, err = reg.Tool.Handle(ctx, args)
		} else {
			// Use legacy handler
			result, err = reg.Handler(ctx, args)
		}

		if err != nil {
			return result, err
		}

		// Try to wrap large results with GCS
		wrappedResult := gcs.WrapMCPResult(ctx, result, toolName)

		// Type assert back to *mcp.CallToolResult
		if mcpResult, ok := wrappedResult.(*mcp.CallToolResult); ok {
			return mcpResult, nil
		}

		// If type assertion fails, return original
		return result, nil
	}
}

// Helper functions for creating tool results

// ToJSON converts a value to compact JSON string without HTML escaping
func ToJSON(v interface{}) string {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false) // Prevent &, <, > from being escaped as \u0026, \u003c, \u003e

	if err := encoder.Encode(v); err != nil {
		return fmt.Sprintf("{\"error\": \"failed to marshal JSON: %v\"}", err)
	}

	// encoder.Encode() adds a trailing newline, trim it
	return strings.TrimSuffix(buf.String(), "\n")
}

// SuccessResult creates a successful tool result
func SuccessResult(data interface{}) *mcp.CallToolResult {
	return mcp.NewToolResultText(ToJSON(data))
}

// ErrorResult creates an error tool result
func ErrorResult(message string) *mcp.CallToolResult {
	return mcp.NewToolResultError(message)
}

// ErrorResultf creates an error tool result with formatting
func ErrorResultf(format string, args ...interface{}) *mcp.CallToolResult {
	return mcp.NewToolResultError(fmt.Sprintf(format, args...))
}

// ValidateToolParameters validates parameters against a tool's schema.
// It checks that all required parameters are present and that parameter types match.
// Returns nil if validation passes, or an error describing what's wrong.
func ValidateToolParameters(schema mcp.Tool, params map[string]interface{}) error {
	inputSchema := schema.InputSchema

	// Check required parameters
	for _, required := range inputSchema.Required {
		if _, ok := params[required]; !ok {
			return fmt.Errorf("missing required parameter: %s", required)
		}
	}

	// Validate parameter types
	for paramName, paramValue := range params {
		propDef, ok := inputSchema.Properties[paramName]
		if !ok {
			// Parameter not in schema - allow extra parameters for flexibility
			continue
		}

		// Extract type from property definition
		propMap, ok := propDef.(map[string]any)
		if !ok {
			continue // Can't validate if property definition is not a map
		}

		expectedType, ok := propMap["type"].(string)
		if !ok {
			continue // No type specified, skip validation
		}

		// Validate type
		if err := validateParameterType(paramName, paramValue, expectedType); err != nil {
			return err
		}
	}

	return nil
}

// GetUnknownParameters returns a list of parameter names that are not defined in the schema.
// Returns nil if all parameters are valid.
func GetUnknownParameters(schema mcp.Tool, params map[string]interface{}) []string {
	var unknown []string
	inputSchema := schema.InputSchema

	for paramName := range params {
		if _, ok := inputSchema.Properties[paramName]; !ok {
			unknown = append(unknown, paramName)
		}
	}

	return unknown
}

// validateParameterType checks if a parameter value matches the expected JSON Schema type
func validateParameterType(name string, value interface{}, expectedType string) error {
	if value == nil {
		return nil // nil is valid for any type (represents absence)
	}

	switch expectedType {
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("parameter %q must be a string, got %T", name, value)
		}
	case "number":
		switch value.(type) {
		case float64, float32, int, int64, int32:
			// Valid number types
		default:
			return fmt.Errorf("parameter %q must be a number, got %T", name, value)
		}
	case "integer":
		switch value.(type) {
		case int, int64, int32, float64: // JSON numbers come as float64
			// Valid integer types
		default:
			return fmt.Errorf("parameter %q must be an integer, got %T", name, value)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("parameter %q must be a boolean, got %T", name, value)
		}
	case "object":
		if _, ok := value.(map[string]interface{}); !ok {
			return fmt.Errorf("parameter %q must be an object, got %T", name, value)
		}
	case "array":
		if _, ok := value.([]interface{}); !ok {
			return fmt.Errorf("parameter %q must be an array, got %T", name, value)
		}
	}

	return nil
}

// CallTool is the core function for calling a registered tool by name.
// It handles tool lookup, parameter validation, OID switching, and GCS wrapping.
// This function provides a unified code path for internal tool calls.
//
// Parameters:
//   - ctx: Context containing auth information
//   - toolName: Name of the registered tool to call
//   - args: Parameters to pass to the tool
//
// Returns the tool result or an error. Note that validation errors are returned
// as error results (IsError=true) rather than Go errors.
func CallTool(ctx context.Context, toolName string, args map[string]interface{}) (*mcp.CallToolResult, error) {
	// Look up the tool
	reg, ok := GetTool(toolName)
	if !ok {
		return ErrorResultf("tool %q not found", toolName), nil
	}

	// Get schema from either interface or legacy fields
	var schema mcp.Tool
	var requiresOID bool
	var handler ToolHandler

	if reg.Tool != nil {
		schema = reg.Tool.Schema()
		requiresOID = reg.Tool.RequiresOID()
		handler = reg.Tool.Handle
	} else {
		schema = reg.Schema
		requiresOID = reg.RequiresOID
		handler = reg.Handler
	}

	// Validate parameters against schema
	if err := ValidateToolParameters(schema, args); err != nil {
		return ErrorResultf("parameter validation failed: %v", err), nil
	}

	// Handle OID switching if tool requires it
	if requiresOID {
		if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
			var err error
			ctx, err = auth.WithOID(ctx, oidParam, nil)
			if err != nil {
				return ErrorResultf("failed to switch OID: %v", err), nil
			}
		}
	}

	// Call the handler
	result, err := handler(ctx, args)
	if err != nil {
		return result, err
	}

	// Wrap large results with GCS
	wrappedResult := gcs.WrapMCPResult(ctx, result, toolName)
	if mcpResult, ok := wrappedResult.(*mcp.CallToolResult); ok {
		return mcpResult, nil
	}

	return result, nil
}
