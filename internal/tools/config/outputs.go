package config

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register output configuration tools
	RegisterListOutputs()
	RegisterAddOutput()
	RegisterDeleteOutput()
}

// outputModules is the set of destination modules the backend accepts; it
// rejects anything else (legion_manager-go service/output_config.go).
var outputModules = []string{
	"s3", "gcs", "scp", "sftp", "slack", "syslog", "webhook", "webhook_bulk",
	"smtp", "humio", "kafka", "pubsub", "bigquery", "azure_storage_blob",
	"azure_event_hub", "elastic", "opensearch", "websocket", "tines", "torq",
	"datadog", "telegram", "ms_teams",
}

// outputStreams is the set of streams an output can be attached to.
var outputStreams = []string{
	"event", "detect", "audit", "deployment", "file", "log", "artifact",
	"tailored", "billing",
}

// RegisterListOutputs registers the list_outputs tool
func RegisterListOutputs() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_outputs",
		Description: "List all configured outputs in the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_outputs",
			mcp.WithDescription("List all configured outputs in the organization"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get all outputs
			outputs, err := org.Outputs()
			if err != nil {
				return tools.ErrorResultf("failed to list outputs: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"outputs": outputs,
				"count":   len(outputs),
			}), nil
		},
	})
}

// RegisterAddOutput registers the add_output tool
func RegisterAddOutput() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "add_output",
		Description: "Create a new output configuration",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("add_output",
			mcp.WithDescription("Create a new output configuration"),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name for the output")),
			mcp.WithString("module",
				mcp.Required(),
				mcp.Enum(outputModules...),
				mcp.Description("Destination module. Anything outside this list is rejected by the backend.")),
			mcp.WithString("output_type",
				mcp.Required(),
				mcp.Enum(outputStreams...),
				mcp.Description("Stream to send. Note that the low-throughput modules (webhook, smtp, slack, telegram, ms_teams, tines, torq) cannot be attached to the 'event' stream.")),
			mcp.WithObject("config",
				mcp.Description("Additional configuration parameters specific to the module, e.g. {\"bucket\": \"my-bucket\", \"is_indexing\": true, \"sec_per_file\": 60}. Booleans and numbers are accepted as-is.")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			name, ok := args["name"].(string)
			if !ok || name == "" {
				return tools.ErrorResult("name parameter is required"), nil
			}

			module, ok := args["module"].(string)
			if !ok || module == "" {
				return tools.ErrorResult("module parameter is required"), nil
			}

			outputType, ok := args["output_type"].(string)
			if !ok || outputType == "" {
				return tools.ErrorResult("output_type parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Build a combined config map with all parameters
			// This ensures all module-specific fields are passed through
			combinedConfig := map[string]interface{}{
				"name":   name,
				"module": module,
				"type":   outputType,
			}

			// Merge all config fields into the combined config. Every boolean
			// and numeric field of lc.OutputConfig carries the `,string` JSON
			// option, so encoding/json refuses to decode an unquoted value into
			// them: coerce scalars to their string form first, otherwise the
			// natural {"is_indexing": true} fails to parse.
			if config, ok := args["config"].(map[string]interface{}); ok {
				for k, v := range config {
					switch t := v.(type) {
					case bool:
						combinedConfig[k] = strconv.FormatBool(t)
					case float64:
						combinedConfig[k] = strconv.FormatFloat(t, 'f', -1, 64)
					case json.Number:
						combinedConfig[k] = t.String()
					default:
						combinedConfig[k] = v
					}
				}
			}

			// Convert to OutputConfig via JSON marshaling
			// This automatically maps all fields with matching JSON tags
			jsonBytes, err := json.Marshal(combinedConfig)
			if err != nil {
				return tools.ErrorResultf("failed to marshal config: %v", err), nil
			}

			var outputConfig lc.OutputConfig
			if err := json.Unmarshal(jsonBytes, &outputConfig); err != nil {
				return tools.ErrorResultf("failed to unmarshal config: %v", err), nil
			}

			// Add output
			result, err := org.OutputAdd(outputConfig)
			if err != nil {
				return tools.ErrorResultf("failed to add output: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created output '%s'", name),
				"output":  result,
			}), nil
		},
	})
}

// RegisterDeleteOutput registers the delete_output tool
func RegisterDeleteOutput() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_output",
		Description: "Delete an output configuration",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_output",
			mcp.WithDescription("Delete an output configuration"),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name of the output to delete")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			name, ok := args["name"].(string)
			if !ok || name == "" {
				return tools.ErrorResult("name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Delete output
			_, err = org.OutputDel(name)
			if err != nil {
				return tools.ErrorResultf("failed to delete output: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted output '%s'", name),
			}), nil
		},
	})
}
