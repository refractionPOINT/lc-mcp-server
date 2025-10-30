package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
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
	},
	"detection_engineering": {
		"get_detection_rules",
		"list_dr_general_rules",
		"get_dr_general_rule",
		"set_dr_general_rule",
		"delete_dr_general_rule",
		"list_yara_rules",
		"get_yara_rule",
		"set_yara_rule",
		"delete_yara_rule",
		"validate_yara_rule",
		"get_fp_rules",
		"get_fp_rule",
		"set_fp_rule",
		"delete_fp_rule",
		"get_mitre_report",
	},
	"platform_admin": {
		"get_org_info",
		"get_usage_stats",
		"get_billing_details",
		"create_org",
		"list_user_orgs",
		"list_outputs",
		"add_output",
		"delete_output",
		"list_secrets",
		"get_secret",
		"set_secret",
		"delete_secret",
		"list_lookups",
		"get_lookup",
		"set_lookup",
		"delete_lookup",
		"query_lookup",
		"list_api_keys",
		"create_api_key",
		"delete_api_key",
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

// AddToolsToServer adds all tools for a profile to an MCP server
func AddToolsToServer(s *server.MCPServer, profile string) error {
	toolNames := GetToolsForProfile(profile)

	for _, name := range toolNames {
		reg, ok := GetTool(name)
		if !ok {
			// Tool not implemented yet - skip silently
			continue
		}

		// Wrap handler to convert between MCP request and our handler signature
		wrappedHandler := wrapHandler(reg)

		// Add tool to server
		s.AddTool(reg.Schema, wrappedHandler)
	}

	return nil
}

// wrapHandler converts our ToolHandler to mcp-go's expected signature
func wrapHandler(reg *ToolRegistration) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract arguments using the method
		args := request.GetArguments()

		// Call the actual handler
		return reg.Handler(ctx, args)
	}
}

// Helper functions for creating tool results

// ToJSON converts a value to JSON string
func ToJSON(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("{\"error\": \"failed to marshal JSON: %v\"}", err)
	}
	return string(b)
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
