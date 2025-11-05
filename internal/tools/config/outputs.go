package config

import (
	"context"
	"fmt"

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

// RegisterListOutputs registers the list_outputs tool
func RegisterListOutputs() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_outputs",
		Description: "List all configured outputs in the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_outputs",
			mcp.WithDescription("List all configured outputs in the organization"),
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
				mcp.Description("Module to use (e.g., 'logging', 's3', 'syslog')")),
			mcp.WithString("output_type",
				mcp.Required(),
				mcp.Description("Type of output (e.g., 'event', 'detect', 'audit')")),
			mcp.WithObject("config",
				mcp.Description("Additional configuration parameters specific to the module")),
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

			// Build output config
			outputConfig := lc.OutputConfig{
				Name:   name,
				Module: lc.OutputModuleType(module),
				Type:   lc.OutputDataType(outputType),
			}

			// Apply additional config if provided
			if config, ok := args["config"].(map[string]interface{}); ok {
				// Map config fields to OutputConfig struct
				// This is a simplified approach - in production you'd want proper field mapping
				if destHost, ok := config["dest_host"].(string); ok {
					outputConfig.DestinationHost = destHost
				}
				if bucket, ok := config["bucket"].(string); ok {
					outputConfig.Bucket = bucket
				}
				if username, ok := config["username"].(string); ok {
					outputConfig.UserName = username
				}
				if password, ok := config["password"].(string); ok {
					outputConfig.Password = password
				}
				if tag, ok := config["tag"].(string); ok {
					outputConfig.Tag = tag
				}
				if sid, ok := config["sid"].(string); ok {
					outputConfig.SensorID = sid
				}
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
