package response

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register tasking tools
	RegisterReliableTasking()
	RegisterListReliableTasks()
	RegisterDeleteSensor()
}

// Note: getOrganization is defined in response.go

// RegisterReliableTasking registers the reliable_tasking tool
func RegisterReliableTasking() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "reliable_tasking",
		Description: "Send a persistent task to sensors with retry",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("reliable_tasking",
			mcp.WithDescription("Send a persistent task to sensors with retry"),
			mcp.WithString("command",
				mcp.Required(),
				mcp.Description("Command to execute on sensors")),
			mcp.WithString("investigation_id",
				mcp.Description("Investigation ID to associate with task")),
			mcp.WithString("sensor_selector",
				mcp.Description("Sensor selector expression")),
			mcp.WithNumber("retention_seconds",
				mcp.Description("How long to keep the task active (default: 86400)")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			command, ok := args["command"].(string)
			if !ok {
				return tools.ErrorResult("command parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Build task parameters
			params := lc.Dict{
				"command": command,
			}

			if invID, ok := args["investigation_id"].(string); ok {
				params["investigation_id"] = invID
			}

			if selector, ok := args["sensor_selector"].(string); ok {
				params["sensor_selector"] = selector
			}

			if retention, ok := args["retention_seconds"].(float64); ok {
				params["retention"] = int(retention)
			} else {
				params["retention"] = 86400 // Default 24 hours
			}

			// Submit reliable task using GenericPOSTRequest
			resp := lc.Dict{}
			if err := org.GenericPOSTRequest("reliable_tasking", params, &resp); err != nil {
				return tools.ErrorResultf("failed to create reliable task: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterListReliableTasks registers the list_reliable_tasks tool
func RegisterListReliableTasks() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_reliable_tasks",
		Description: "List pending reliable tasks",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("list_reliable_tasks",
			mcp.WithDescription("List pending reliable tasks"),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// List reliable tasks using GenericGETRequest
			resp := lc.Dict{}
			if err := org.GenericGETRequest("reliable_tasking", nil, &resp); err != nil {
				return tools.ErrorResultf("failed to list reliable tasks: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterDeleteSensor registers the delete_sensor tool
func RegisterDeleteSensor() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_sensor",
		Description: "Permanently delete a sensor from the organization",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_sensor",
			mcp.WithDescription("Permanently delete a sensor from the organization"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID) to delete")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, ok := args["sid"].(string)
			if !ok {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get sensor and delete it
			sensor := org.GetSensor(sid)
			if sensor == nil {
				return tools.ErrorResultf("sensor not found: %s", sid), nil
			}

			// Use GenericDELETERequest to delete the sensor
			resp := lc.Dict{}
			if err := org.GenericDELETERequest(sid, &resp); err != nil {
				return tools.ErrorResultf("failed to delete sensor: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"status":  "success",
				"message": fmt.Sprintf("Sensor %s deleted successfully", sid),
				"details": resp,
			}), nil
		},
	})
}
