package api

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	RegisterLCCallTool()
}

// RegisterLCCallTool registers the lc_call_tool meta-tool
func RegisterLCCallTool() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name: "lc_call_tool",
		Description: "Call any registered LimaCharlie MCP tool locally. " +
			"Provides unified access to all LimaCharlie tools with parameter validation. " +
			"IMPORTANT: This tool should only be called when explicitly instructed to do so by a SKILL. " +
			"The LLM should have its own tool documentation to use this tool effectively.",
		Profile:     "api_access",
		RequiresOID: false, // OID is passed through to the target tool
		Schema: mcp.NewTool("lc_call_tool",
			mcp.WithDescription("Call any registered LimaCharlie MCP tool locally. "+
				"Provides unified access to all LimaCharlie tools with parameter validation. "+
				"IMPORTANT: This tool should only be called when explicitly instructed to do so by a SKILL. "+
				"The LLM should have its own tool documentation to use this tool effectively."),
			mcp.WithString("tool_name",
				mcp.Required(),
				mcp.Description("Name of the MCP tool to call (e.g., 'get_sensor_info', 'run_lcql_query')")),
			mcp.WithObject("parameters",
				mcp.Required(),
				mcp.Description("Parameters to pass to the tool as a dictionary")),
		),
		Handler: handleLCCallTool,
	})
}

func handleLCCallTool(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	// Extract tool name
	toolName, ok := args["tool_name"].(string)
	if !ok || toolName == "" {
		return tools.ErrorResult("tool_name parameter is required and must be a string"), nil
	}

	// Prevent recursive calls
	if toolName == "lc_call_tool" {
		return tools.ErrorResult("cannot call lc_call_tool recursively"), nil
	}

	// Check meta-tool filter (X-LC-ALLOW-META-TOOLS / X-LC-DENY-META-TOOLS headers)
	if filter := auth.GetMetaToolFilter(ctx); filter != nil {
		if !auth.IsToolAllowed(filter, toolName) {
			return tools.ErrorResultf("tool %q is not allowed by meta-tool filter", toolName), nil
		}
	}

	// Extract parameters
	params, ok := args["parameters"].(map[string]interface{})
	if !ok {
		return tools.ErrorResult("parameters must be an object"), nil
	}

	// Look up target tool to validate parameters against its schema
	reg, ok := tools.GetTool(toolName)
	if !ok {
		return tools.ErrorResultf("tool %q not found", toolName), nil
	}

	// Get schema from the tool, enhanced with OID if required
	var schema mcp.Tool
	var requiresOID bool
	if reg.Tool != nil {
		schema = reg.Tool.Schema()
		requiresOID = reg.Tool.RequiresOID()
	} else {
		schema = reg.Schema
		requiresOID = reg.RequiresOID
	}

	// If tool requires OID, use enhanced schema that includes the oid parameter
	if requiresOID {
		schema = tools.AddOIDToToolSchema(schema)
	}

	// Check for unknown parameters (strict validation for lc_call_tool)
	if unknown := tools.GetUnknownParameters(schema, params); len(unknown) > 0 {
		return tools.ErrorResultf("unknown parameter(s) for tool %q: %v", toolName, unknown), nil
	}

	// Use the shared CallTool function which handles:
	// - Tool lookup (already done above, but CallTool rechecks)
	// - Parameter validation against schema
	// - OID switching for tools that require it
	// - GCS wrapping for large results
	return tools.CallTool(ctx, toolName, params)
}
