package response

import (
	"context"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register sensor-response tools
	RegisterTaskSensor()
	RegisterMemoryDumpSensor()
	RegisterSealSensor()
	RegisterUnsealSensor()
	RegisterMassAddTag()
	RegisterMassRemoveTag()
}

// RegisterTaskSensor registers the task_sensor tool
func RegisterTaskSensor() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "task_sensor",
		Description: "Send an arbitrary live task to a sensor (sync optional)",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("task_sensor",
			mcp.WithDescription("Send an arbitrary live task to a sensor. Optionally wait synchronously for the response."),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID) to task")),
			mcp.WithString("task",
				mcp.Required(),
				mcp.Description("Command to execute on the sensor (e.g., 'os_version', 'mem_map --pid 4', 'run --shell-command whoami')")),
			mcp.WithBoolean("is_sync",
				mcp.Description("When true, wait synchronously for the sensor's response and return it. When false/omitted, fire-and-forget.")),
			mcp.WithNumber("timeout_sec",
				mcp.Description("Timeout in seconds when is_sync is true (default: 30)")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, err := tools.ExtractAndValidateSID(args)
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			task, ok := args["task"].(string)
			if !ok || task == "" {
				return tools.ErrorResult("task parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			sensor := org.GetSensor(sid)
			if sensor == nil {
				return tools.ErrorResultf("sensor not found: %s", sid), nil
			}

			isSync, _ := args["is_sync"].(bool)

			if isSync {
				timeout := 30 * time.Second
				if t, ok := args["timeout_sec"].(float64); ok && t > 0 {
					timeout = time.Duration(t) * time.Second
				}

				resp, err := sensor.SimpleRequest(task, lc.SimpleRequestOptions{Timeout: timeout})
				if err != nil {
					return tools.ErrorResultf("failed to task sensor (sync): %v", err), nil
				}

				return tools.SuccessResult(map[string]interface{}{
					"status":   "success",
					"sid":      sid,
					"task":     task,
					"sync":     true,
					"response": resp,
				}), nil
			}

			if err := sensor.Task(task); err != nil {
				return tools.ErrorResultf("failed to task sensor: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"status":  "success",
				"sid":     sid,
				"task":    task,
				"sync":    false,
				"message": fmt.Sprintf("Task '%s' sent to sensor %s", task, sid),
			}), nil
		},
	})
}

// RegisterMemoryDumpSensor registers the memory_dump_sensor tool
func RegisterMemoryDumpSensor() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "memory_dump_sensor",
		Description: "Trigger a full memory dump of a sensor",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("memory_dump_sensor",
			mcp.WithDescription("Trigger a full memory dump of a sensor via the dumper service"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID) to dump")),
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

			resp := lc.Dict{}
			if err := org.ServiceRequest(&resp, "dumper", lc.Dict{"sid": sid}, true); err != nil {
				return tools.ErrorResultf("failed to trigger memory dump: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"status":   "success",
				"sid":      sid,
				"response": resp,
			}), nil
		},
	})
}

// RegisterSealSensor registers the seal_sensor tool
func RegisterSealSensor() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "seal_sensor",
		Description: "Seal (lock down) a sensor via endpoint-policy",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("seal_sensor",
			mcp.WithDescription("Seal (lock down) a sensor, preventing uninstallation/configuration changes while it keeps operating"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID) to seal")),
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

			resp := lc.Dict{}
			if err := org.GenericPOSTRequest(fmt.Sprintf("%s/seal", sid), nil, &resp); err != nil {
				return tools.ErrorResultf("failed to seal sensor: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"status":   "success",
				"sid":      sid,
				"message":  fmt.Sprintf("Sensor %s is now sealed", sid),
				"response": resp,
			}), nil
		},
	})
}

// RegisterUnsealSensor registers the unseal_sensor tool
func RegisterUnsealSensor() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "unseal_sensor",
		Description: "Unseal a sensor",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("unseal_sensor",
			mcp.WithDescription("Remove the seal from a sensor, restoring the ability to modify/uninstall it"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID) to unseal")),
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

			resp := lc.Dict{}
			if err := org.GenericDELETERequest(fmt.Sprintf("%s/seal", sid), &resp); err != nil {
				return tools.ErrorResultf("failed to unseal sensor: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"status":   "success",
				"sid":      sid,
				"message":  fmt.Sprintf("Sensor %s seal removed", sid),
				"response": resp,
			}), nil
		},
	})
}

// RegisterMassAddTag registers the mass_add_tag tool
func RegisterMassAddTag() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "mass_add_tag",
		Description: "Add a tag to all sensors matching a selector",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("mass_add_tag",
			mcp.WithDescription("Add a tag to all sensors matching a selector expression"),
			mcp.WithString("selector",
				mcp.Required(),
				mcp.Description("Sensor selector expression (e.g., 'plat==windows', 'production in tags')")),
			mcp.WithString("tag",
				mcp.Required(),
				mcp.Description("Tag to add to matching sensors")),
			mcp.WithNumber("ttl",
				mcp.Description("Time-to-live for the tag in seconds (0 = no expiry)")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			selector, ok := args["selector"].(string)
			if !ok || selector == "" {
				return tools.ErrorResult("selector parameter is required"), nil
			}

			tag, ok := args["tag"].(string)
			if !ok || tag == "" {
				return tools.ErrorResult("tag parameter is required"), nil
			}

			ttl := 0
			if t, ok := args["ttl"].(float64); ok {
				ttl = int(t)
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			result, err := org.MassTag(selector, tag, ttl)
			if err != nil {
				return tools.ErrorResultf("failed to mass-add tag: %v", err), nil
			}

			return tools.SuccessResult(massTagResultToMap(result)), nil
		},
	})
}

// RegisterMassRemoveTag registers the mass_remove_tag tool
func RegisterMassRemoveTag() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "mass_remove_tag",
		Description: "Remove a tag from all sensors matching a selector",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("mass_remove_tag",
			mcp.WithDescription("Remove a tag from all sensors matching a selector expression"),
			mcp.WithString("selector",
				mcp.Required(),
				mcp.Description("Sensor selector expression (e.g., 'plat==windows', 'production in tags')")),
			mcp.WithString("tag",
				mcp.Required(),
				mcp.Description("Tag to remove from matching sensors")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			selector, ok := args["selector"].(string)
			if !ok || selector == "" {
				return tools.ErrorResult("selector parameter is required"), nil
			}

			tag, ok := args["tag"].(string)
			if !ok || tag == "" {
				return tools.ErrorResult("tag parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			result, err := org.MassUntag(selector, tag)
			if err != nil {
				return tools.ErrorResultf("failed to mass-remove tag: %v", err), nil
			}

			return tools.SuccessResult(massTagResultToMap(result)), nil
		},
	})
}

// massTagResultToMap converts a MassTagResult into a JSON-friendly map,
// flattening the per-sensor error map into string messages.
func massTagResultToMap(result lc.MassTagResult) map[string]interface{} {
	errs := make(map[string]string, len(result.Errors))
	for sid, err := range result.Errors {
		errs[sid] = err.Error()
	}
	return map[string]interface{}{
		"status":    "success",
		"selector":  result.Selector,
		"tag":       result.Tag,
		"matched":   result.Matched,
		"succeeded": result.Succeeded,
		"errors":    errs,
	}
}
