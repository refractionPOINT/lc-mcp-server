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

// addReliableTaskingTarget copies the sid/tag/selector target into data.
//
// Both the "task" and "untask" actions of ext-reliable-tasking declare
// Requirements {{"sid","tag","selector"}} with no default, and the extension
// manager enforces that one-of group before the extension is reached. Checking
// it here turns a remote "missing one of sid, tag, selector" into an immediate,
// actionable error.
func addReliableTaskingTarget(args map[string]interface{}, data lc.Dict) error {
	hasTarget := false
	for _, key := range []string{"sid", "tag", "selector"} {
		if v, ok := args[key].(string); ok && v != "" {
			data[key] = v
			hasTarget = true
		}
	}
	if !hasTarget {
		return fmt.Errorf("one of sid, tag or selector is required")
	}
	return nil
}

// RegisterReliableTasking registers the reliable_tasking tool
// This tool sends persistent tasks to sensors via the ext-reliable-tasking extension
func RegisterReliableTasking() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "reliable_tasking",
		Description: "Send a persistent task to sensors with retry. Tasks are queued and delivered when sensors come online.",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("reliable_tasking",
			mcp.WithDescription("Send a persistent task to sensors with retry. Tasks are queued and delivered when sensors come online. Exactly one target is required: sid, tag or selector - the extension rejects a request that carries none. Use selector='*' to target the whole fleet."),
			mcp.WithString("task",
				mcp.Required(),
				mcp.Description("Command to execute on sensors (e.g., 'os_version', 'mem_map --pid 4', 'run --shell-command whoami')")),
			mcp.WithString("sid",
				mcp.Description("Sensor ID (UUID) to target. One of sid, tag or selector is required.")),
			mcp.WithString("tag",
				mcp.Description("Target every sensor carrying this tag (e.g. 'linux'). One of sid, tag or selector is required.")),
			mcp.WithString("selector",
				mcp.Description("Sensor selector expression (e.g., 'plat==windows', 'production in tags'), or '*' for all sensors. One of sid, tag or selector is required.")),
			mcp.WithString("context",
				mcp.Description("Context identifier reflected in investigation_id of response events. Useful for D&R rule matching.")),
			mcp.WithNumber("ttl",
				mcp.Description("Time-to-live in seconds - how long to keep trying to deliver the task (default: 604800 = 1 week)")),
			mcp.WithDestructiveHintAnnotation(true),
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

			if err := addReliableTaskingTarget(args, data); err != nil {
				return tools.ErrorResult(err.Error()), nil
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
			mcp.WithReadOnlyHintAnnotation(true),
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
		Description: "Delete/abort pending reliable tasks for a sensor, tag or selector.",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_reliable_task",
			mcp.WithDescription("Delete/abort pending reliable tasks. Exactly one target is required: sid, tag or selector - the extension rejects a request that carries none, including a task_id-only call. Without task_id, ALL pending tasks for the target are deleted."),
			mcp.WithString("task_id",
				mcp.Description("Specific task ID to delete. If omitted, every pending task for the target is deleted.")),
			mcp.WithString("sid",
				mcp.Description("Delete tasks for this sensor ID (UUID). One of sid, tag or selector is required.")),
			mcp.WithString("tag",
				mcp.Description("Delete tasks for every sensor carrying this tag. One of sid, tag or selector is required.")),
			mcp.WithString("selector",
				mcp.Description("Delete tasks for sensors matching this selector expression, or '*' for all sensors. One of sid, tag or selector is required.")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Build extension request data
			data := lc.Dict{}

			if err := addReliableTaskingTarget(args, data); err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			if taskID, ok := args["task_id"].(string); ok && taskID != "" {
				data["task_id"] = taskID
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
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, err := tools.ExtractAndValidateSID(args)
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// GetSensor always returns a non-nil Sensor and fetches its record
			// inline, recording an unknown SID or API failure in LastError.
			sensor := org.GetSensor(sid)
			if sensor.LastError != nil {
				return tools.ErrorResultf("failed to look up sensor %s: %v", sid, sensor.LastError), nil
			}

			// Delete the sensor using the SDK method
			if err := sensor.Delete(); err != nil {
				return tools.ErrorResultf("failed to delete sensor: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"status":  "success",
				"message": fmt.Sprintf("Sensor %s deleted successfully", sid),
			}), nil
		},
	})
}
