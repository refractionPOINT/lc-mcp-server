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
	RegisterDeleteReliableTask()
	RegisterDeleteSensor()
}

// Note: getOrganization is defined in response.go

// RegisterReliableTasking registers the reliable_tasking tool
// This tool sends persistent tasks to sensors via the ext-reliable-tasking extension
func RegisterReliableTasking() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "reliable_tasking",
		Description: "Send a persistent task to sensors with retry. Tasks are queued and delivered when sensors come online.",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("reliable_tasking",
			mcp.WithDescription("Send a persistent task to sensors with retry. Tasks are queued and delivered when sensors come online."),
			mcp.WithString("task",
				mcp.Required(),
				mcp.Description("Command to execute on sensors (e.g., 'os_version', 'mem_map --pid 4', 'run --shell-command whoami')")),
			mcp.WithString("selector",
				mcp.Description("Sensor selector expression (e.g., 'plat==windows', 'production in tags'). If omitted, targets all sensors.")),
			mcp.WithString("context",
				mcp.Description("Context identifier reflected in investigation_id of response events. Useful for D&R rule matching.")),
			mcp.WithNumber("ttl",
				mcp.Description("Time-to-live in seconds - how long to keep trying to deliver the task (default: 604800 = 1 week)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			task, ok := args["task"].(string)
			if !ok || task == "" {
				return tools.ErrorResult("task parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Build extension request data
			data := lc.Dict{
				"task": task,
			}

			if selector, ok := args["selector"].(string); ok && selector != "" {
				data["selector"] = selector
			}

			if context, ok := args["context"].(string); ok && context != "" {
				data["context"] = context
			}

			if ttl, ok := args["ttl"].(float64); ok {
				data["ttl"] = int(ttl)
			}

			// Submit reliable task via extension request
			resp := lc.Dict{}
			if err := org.ExtensionRequest(&resp, "ext-reliable-tasking", "task", data, false); err != nil {
				return tools.ErrorResultf("failed to create reliable task: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterListReliableTasks registers the list_reliable_tasks tool
// This tool lists pending reliable tasks via the ext-reliable-tasking extension
func RegisterListReliableTasks() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_reliable_tasks",
		Description: "List pending reliable tasks in the organization",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("list_reliable_tasks",
			mcp.WithDescription("List pending reliable tasks in the organization"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// List reliable tasks via extension request
			resp := lc.Dict{}
			if err := org.ExtensionRequest(&resp, "ext-reliable-tasking", "list", lc.Dict{}, false); err != nil {
				return tools.ErrorResultf("failed to list reliable tasks: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterDeleteReliableTask registers the delete_reliable_task tool
// This tool deletes/aborts pending reliable tasks via the ext-reliable-tasking extension
func RegisterDeleteReliableTask() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_reliable_task",
		Description: "Delete/abort pending reliable tasks. Can target specific tasks or all tasks matching criteria.",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_reliable_task",
			mcp.WithDescription("Delete/abort pending reliable tasks. Can target specific tasks or all tasks matching criteria."),
			mcp.WithString("task_id",
				mcp.Description("Specific task ID to delete. If omitted, deletes all tasks matching other criteria.")),
			mcp.WithString("selector",
				mcp.Description("Sensor selector expression to target tasks for specific sensors")),
			mcp.WithString("sid",
				mcp.Description("Specific sensor ID to delete tasks for")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Build extension request data
			data := lc.Dict{}

			if taskID, ok := args["task_id"].(string); ok && taskID != "" {
				data["task_id"] = taskID
			}

			if selector, ok := args["selector"].(string); ok && selector != "" {
				data["selector"] = selector
			}

			if sid, ok := args["sid"].(string); ok && sid != "" {
				data["sid"] = sid
			}

			// Delete reliable tasks via extension request (action: untask)
			resp := lc.Dict{}
			if err := org.ExtensionRequest(&resp, "ext-reliable-tasking", "untask", data, false); err != nil {
				return tools.ErrorResultf("failed to delete reliable task: %v", err), nil
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
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, ok := args["sid"].(string)
			if !ok {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get sensor and delete it
			sensor := org.GetSensor(sid)
			if sensor == nil {
				return tools.ErrorResultf("sensor not found: %s", sid), nil
			}

			// Delete the sensor using the SDK method
			if err := sensor.Delete(); err != nil {
				return tools.ErrorResultf("failed to delete sensor: %v", err), nil
			}

			resp := map[string]interface{}{}

			return tools.SuccessResult(map[string]interface{}{
				"status":  "success",
				"message": fmt.Sprintf("Sensor %s deleted successfully", sid),
				"details": resp,
			}), nil
		},
	})
}
