package investigation

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register live investigation tools
	RegisterGetProcesses()
	RegisterGetNetworkConnections()
	RegisterGetOSVersion()
}

// getSDKCache retrieves the SDK cache from context
func getSDKCache(ctx context.Context) (*auth.SDKCache, error) {
	return auth.GetSDKCache(ctx)
}

// getOrganization retrieves or creates an Organization instance from context
func getOrganization(ctx context.Context) (*lc.Organization, error) {
	cache, err := getSDKCache(ctx)
	if err != nil {
		return nil, err
	}

	return cache.GetFromContext(ctx)
}

// RegisterGetProcesses registers the get_processes tool
func RegisterGetProcesses() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_processes",
		Description: "Get the process list for a given sensor",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("get_processes",
			mcp.WithDescription("Get the process list for a given sensor"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract and validate SID
			sid, err := tools.ExtractAndValidateSID(args)
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			// Handle OID switching for UID mode
			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}
			}

			// Get organization
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get sensor (returns *Sensor)
			sensor := org.GetSensor(sid)
			if sensor == nil {
				return tools.ErrorResult("sensor not found"), nil
			}

			// TODO: Go SDK needs synchronous request method like Python's sensor.request()
			// For now, just send the task (fire-and-forget)
			err = sensor.Task("os_processes", lc.TaskingOptions{})
			if err != nil {
				return tools.ErrorResultf("failed to task sensor: %v", err), nil
			}

			result := map[string]interface{}{
				"status":  "task_sent",
				"message": "Task sent to sensor. Go SDK does not yet support synchronous task responses. Need to add sensor.Request() method.",
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterGetNetworkConnections registers the get_network_connections tool
func RegisterGetNetworkConnections() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_network_connections",
		Description: "Get network connections for a given sensor",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("get_network_connections",
			mcp.WithDescription("Get network connections for a given sensor"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract and validate SID
			sid, err := tools.ExtractAndValidateSID(args)
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			// Handle OID switching for UID mode
			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}
			}

			// Get organization
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get sensor (returns *Sensor)
			sensor := org.GetSensor(sid)
			if sensor == nil {
				return tools.ErrorResult("sensor not found"), nil
			}

			// TODO: Go SDK needs synchronous request method
			err = sensor.Task("os_network_connections", lc.TaskingOptions{})
			if err != nil {
				return tools.ErrorResultf("failed to task sensor: %v", err), nil
			}

			result := map[string]interface{}{
				"status":  "task_sent",
				"message": "Task sent to sensor. Go SDK does not yet support synchronous task responses.",
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterGetOSVersion registers the get_os_version tool
func RegisterGetOSVersion() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_os_version",
		Description: "Get OS version information for a given sensor",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("get_os_version",
			mcp.WithDescription("Get OS version information for a given sensor"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract and validate SID
			sid, err := tools.ExtractAndValidateSID(args)
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			// Handle OID switching for UID mode
			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}
			}

			// Get organization
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get sensor (returns *Sensor)
			sensor := org.GetSensor(sid)
			if sensor == nil {
				return tools.ErrorResult("sensor not found"), nil
			}

			// TODO: Go SDK needs synchronous request method
			err = sensor.Task("os_version", lc.TaskingOptions{})
			if err != nil {
				return tools.ErrorResultf("failed to task sensor: %v", err), nil
			}

			result := map[string]interface{}{
				"status":  "task_sent",
				"message": "Task sent to sensor. Go SDK does not yet support synchronous task responses.",
			}

			return tools.SuccessResult(result), nil
		},
	})
}
