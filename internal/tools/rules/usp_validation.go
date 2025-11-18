package rules

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register USP validation tools
	RegisterValidateUSPMapping()
}

// RegisterValidateUSPMapping registers the validate_usp_mapping tool
func RegisterValidateUSPMapping() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "validate_usp_mapping",
		Description: "Validate USP adapter mapping configuration",
		Profile:     "detection_engineering",
		RequiresOID: true, // Requires organization context for API call
		Schema: mcp.NewTool("validate_usp_mapping",
			mcp.WithDescription("Validate USP (Universal Sensor Protocol) adapter mapping configuration by testing it against sample input data"),
			mcp.WithString("platform",
				mcp.Required(),
				mcp.Description("Parser platform type (e.g., 'text', 'json', 'cef', 'gcp', 'aws')")),
			mcp.WithObject("mapping",
				mcp.Description("Single mapping descriptor (mutually exclusive with mappings)")),
			mcp.WithArray("mappings",
				mcp.Description("Multiple mapping descriptors for multi-mapping selection (mutually exclusive with mapping)")),
			mcp.WithArray("indexing",
				mcp.Description("Indexing rules to apply to parsed events")),
			mcp.WithString("text_input",
				mcp.Description("Newline-separated text input to parse (mutually exclusive with json_input)")),
			mcp.WithArray("json_input",
				mcp.Description("Pre-parsed JSON input array (mutually exclusive with text_input)")),
			mcp.WithString("hostname",
				mcp.Description("Default hostname for sensors (defaults to 'validation-test')")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract platform (required)
			platform, ok := args["platform"].(string)
			if !ok || platform == "" {
				return tools.ErrorResult("platform parameter is required"), nil
			}

			// Build the validation request
			req := lc.USPMappingValidationRequest{
				Platform: platform,
			}

			// Extract optional hostname
			if hostname, ok := args["hostname"].(string); ok && hostname != "" {
				req.Hostname = hostname
			}

			// Extract mapping (single)
			if mapping, ok := args["mapping"].(map[string]interface{}); ok {
				req.Mapping = lc.Dict(mapping)
			}

			// Extract mappings (multiple)
			if mappings, ok := args["mappings"].([]interface{}); ok {
				req.Mappings = make([]lc.Dict, 0, len(mappings))
				for i, m := range mappings {
					if mDict, ok := m.(map[string]interface{}); ok {
						req.Mappings = append(req.Mappings, lc.Dict(mDict))
					} else {
						return tools.ErrorResultf("mappings[%d] must be an object", i), nil
					}
				}
			}

			// Extract indexing
			if indexing, ok := args["indexing"].([]interface{}); ok {
				req.Indexing = make([]lc.Dict, 0, len(indexing))
				for i, idx := range indexing {
					if idxDict, ok := idx.(map[string]interface{}); ok {
						req.Indexing = append(req.Indexing, lc.Dict(idxDict))
					} else {
						return tools.ErrorResultf("indexing[%d] must be an object", i), nil
					}
				}
			}

			// Extract text_input
			if textInput, ok := args["text_input"].(string); ok && textInput != "" {
				req.TextInput = textInput
			}

			// Extract json_input
			if jsonInput, ok := args["json_input"].([]interface{}); ok {
				req.JSONInput = make([]lc.Dict, 0, len(jsonInput))
				for i, j := range jsonInput {
					if jDict, ok := j.(map[string]interface{}); ok {
						req.JSONInput = append(req.JSONInput, lc.Dict(jDict))
					} else {
						return tools.ErrorResultf("json_input[%d] must be an object", i), nil
					}
				}
			}

			// Validate that we have either mapping or mappings
			if req.Mapping == nil && len(req.Mappings) == 0 {
				return tools.ErrorResult("either 'mapping' or 'mappings' parameter is required"), nil
			}

			// Validate that we have either text_input or json_input
			if req.TextInput == "" && len(req.JSONInput) == 0 {
				return tools.ErrorResult("either 'text_input' or 'json_input' parameter is required"), nil
			}

			// Get the organization from context
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Call the validation API
			resp, err := org.ValidateUSPMappingWithContext(ctx, req)
			if err != nil {
				return tools.ErrorResultf("USP mapping validation failed: %v", err), nil
			}

			// Build the response
			result := map[string]interface{}{
				"valid": len(resp.Errors) == 0,
			}

			if len(resp.Errors) > 0 {
				result["errors"] = resp.Errors
				result["message"] = fmt.Sprintf("USP mapping validation failed with %d error(s)", len(resp.Errors))
			} else {
				result["message"] = "USP mapping is valid"
			}

			if len(resp.Results) > 0 {
				// Convert []lc.Dict to []map[string]interface{} for JSON serialization
				results := make([]map[string]interface{}, 0, len(resp.Results))
				for _, r := range resp.Results {
					results = append(results, map[string]interface{}(r))
				}
				result["results"] = results
				result["parsed_events_count"] = len(resp.Results)
			}

			return tools.SuccessResult(result), nil
		},
	})
}
