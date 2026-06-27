package core

import (
	"context"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register fleet-management tools
	RegisterFindSensorsByTag()
	RegisterWaitSensorOnline()
	RegisterExportSensors()
}

// RegisterFindSensorsByTag registers the find_sensors_by_tag tool
func RegisterFindSensorsByTag() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "find_sensors_by_tag",
		Description: "Find all sensors carrying a tag",
		Profile:     "fleet_management",
		RequiresOID: true,
		Schema: mcp.NewTool("find_sensors_by_tag",
			mcp.WithDescription("Find all sensors carrying a specific tag"),
			mcp.WithString("tag",
				mcp.Required(),
				mcp.Description("Tag to search for")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			tag, ok := args["tag"].(string)
			if !ok || tag == "" {
				return tools.ErrorResult("tag parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			sensors, err := org.GetSensorsWithTag(tag)
			if err != nil {
				return tools.ErrorResultf("failed to find sensors by tag '%s': %v", tag, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"tag":     tag,
				"sensors": sensors,
				"count":   len(sensors),
			}), nil
		},
	})
}

// RegisterWaitSensorOnline registers the wait_sensor_online tool
func RegisterWaitSensorOnline() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "wait_sensor_online",
		Description: "Block until a sensor is online or timeout",
		Profile:     "fleet_management",
		RequiresOID: true,
		Schema: mcp.NewTool("wait_sensor_online",
			mcp.WithDescription("Block (poll) until a sensor comes online or the timeout elapses. Returns the final online status."),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID) to wait for")),
			mcp.WithNumber("timeout_sec",
				mcp.Description("Maximum time to wait in seconds (default: 60, capped at 300)")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, err := tools.ExtractAndValidateSID(args)
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			// Default 60s, cap at 300s.
			timeoutSec := 60.0
			if t, ok := args["timeout_sec"].(float64); ok && t > 0 {
				timeoutSec = t
			}
			if timeoutSec > 300 {
				timeoutSec = 300
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			sensor := org.GetSensor(sid)
			if sensor == nil {
				return tools.ErrorResultf("sensor not found: %s", sid), nil
			}

			deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
			const pollInterval = 2 * time.Second

			isOnline := false
			for {
				online, err := sensor.IsOnline()
				if err != nil {
					return tools.ErrorResultf("failed to check online status: %v", err), nil
				}
				if online {
					isOnline = true
					break
				}

				if !time.Now().Add(pollInterval).Before(deadline) {
					// Next poll would land at/after the deadline; stop here.
					break
				}

				select {
				case <-ctx.Done():
					return tools.ErrorResultf("wait cancelled: %v", ctx.Err()), nil
				case <-time.After(pollInterval):
				}
			}

			return tools.SuccessResult(map[string]interface{}{
				"sid":         sid,
				"is_online":   isOnline,
				"timeout_sec": int(timeoutSec),
			}), nil
		},
	})
}

// RegisterExportSensors registers the export_sensors tool
func RegisterExportSensors() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "export_sensors",
		Description: "Export the full sensor manifest",
		Profile:     "fleet_management",
		RequiresOID: true,
		Schema: mcp.NewTool("export_sensors",
			mcp.WithDescription("Export the full sensor manifest for the organization"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := org.ExportSensors()
			if err != nil {
				return tools.ErrorResultf("failed to export sensors: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"sensors": resp,
			}), nil
		},
	})
}
