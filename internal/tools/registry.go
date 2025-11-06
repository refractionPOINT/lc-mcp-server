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

// ToolRegistration holds a tool's metadata and handler
type ToolRegistration struct {
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

// IsUIDMode checks if the auth mode supports OID switching
func IsUIDMode(authMode auth.AuthMode) bool {
	return authMode == auth.AuthModeUIDKey || authMode == auth.AuthModeUIDOAuth
}

// AddOIDToToolSchema adds the OID parameter to a tool's input schema
// This function creates a deep copy of the schema to avoid modifying shared state
func AddOIDToToolSchema(tool mcp.Tool) mcp.Tool {
	schema := tool.InputSchema

	// Deep copy Properties map to avoid modifying the original
	newProperties := make(map[string]any, len(schema.Properties)+1)
	for k, v := range schema.Properties {
		newProperties[k] = v
	}

	// Only add OID parameter if not already present
	if _, exists := newProperties["oid"]; !exists {
		newProperties["oid"] = map[string]any{
			"type":        "string",
			"description": "Organization ID",
		}
	}

	// Deep copy Required slice to avoid modifying the original
	newRequired := make([]string, len(schema.Required), len(schema.Required)+1)
	copy(newRequired, schema.Required)

	// Only append "oid" if not already in Required list
	hasOID := false
	for _, req := range newRequired {
		if req == "oid" {
			hasOID = true
			break
		}
	}
	if !hasOID {
		newRequired = append(newRequired, "oid")
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

// AddToolsToServer adds all tools for a profile to an MCP server
func AddToolsToServer(s *server.MCPServer, profile string, authMode auth.AuthMode) error {
	toolNames := GetToolsForProfile(profile)
	isUIDMode := IsUIDMode(authMode)

	for _, name := range toolNames {
		reg, ok := GetTool(name)
		if !ok {
			// Tool not implemented yet - skip silently
			continue
		}

		schema := reg.Schema

		// Dynamically add OID parameter if tool requires it and we're in UID mode
		if reg.RequiresOID && isUIDMode {
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
// handles OID switching for tools that require it, and wraps large results with GCS if available
func wrapHandler(reg *ToolRegistration, isUIDMode bool) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract arguments using the method
		args := request.GetArguments()

		// Automatically handle OID switching for tools that require it in UID mode
		if reg.RequiresOID && isUIDMode {
			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				// Pass nil logger - WithOID will use slog.Default() as fallback
				ctx, err = auth.WithOID(ctx, oidParam, nil)
				if err != nil {
					return mcp.NewToolResultError(fmt.Sprintf("failed to switch OID: %v", err)), nil
				}
			}
		}

		// Call the actual handler
		result, err := reg.Handler(ctx, args)
		if err != nil {
			return result, err
		}

		// Try to wrap large results with GCS by working with JSON representation
		// Marshal the result to JSON to inspect its structure
		resultJSON, err := json.Marshal(result)
		if err != nil {
			// Can't marshal - return as-is
			return result, nil
		}

		// Parse as map to extract text content
		var resultMap map[string]interface{}
		if err := json.Unmarshal(resultJSON, &resultMap); err != nil {
			return result, nil
		}

		// Check if this is an error result
		if isError, ok := resultMap["isError"].(bool); ok && isError {
			return result, nil
		}

		// Try to extract text from content
		if contentList, ok := resultMap["content"].([]interface{}); ok && len(contentList) > 0 {
			if contentItem, ok := contentList[0].(map[string]interface{}); ok {
				if text, ok := contentItem["text"].(string); ok {
					// Parse the JSON text
					var data interface{}
					if err := json.Unmarshal([]byte(text), &data); err != nil {
						// Not JSON or can't parse - return as-is
						return result, nil
					}

					// Try to wrap with GCS
					wrappedData, err := gcs.MaybeWrapResult(ctx, data, reg.Name)
					if err != nil {
						// If wrapping fails, return original
						return result, nil
					}

					// Re-encode and create new result
					return mcp.NewToolResultText(ToJSON(wrappedData)), nil
				}
			}
		}

		return result, nil
	}
}

// Helper functions for creating tool results

// ToJSON converts a value to JSON string without HTML escaping
func ToJSON(v interface{}) string {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "  ")
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
