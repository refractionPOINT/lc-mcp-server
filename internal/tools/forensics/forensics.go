package forensics

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register forensics tools
	RegisterGetProcessModules()
	RegisterGetProcessStrings()
	RegisterFindStrings()
	RegisterGetPackages()
	RegisterGetServices()
	RegisterGetAutoruns()
	RegisterGetDrivers()
	RegisterGetUsers()
	RegisterGetRegistryKeys()
	RegisterGetHistoricEvents()
}

// Note: getOrganization and getSensor are defined in common.go

// sendSensorCommand sends a command to a sensor and returns the response
func sendSensorCommand(ctx context.Context, sid string, command string, params map[string]interface{}) (interface{}, error) {
	sensor, err := getSensor(ctx, sid)
	if err != nil {
		return nil, fmt.Errorf("failed to get sensor: %w", err)
	}

	// Build command parameters
	req := lc.Dict{
		"command": command,
	}
	for k, v := range params {
		req[k] = v
	}

	// Use SimpleRequest with a 30-second timeout
	result, err := sensor.SimpleRequest(req)
	if err != nil {
		return nil, fmt.Errorf("sensor command failed: %w", err)
	}

	return result, nil
}

// RegisterGetProcessModules registers the get_process_modules tool
func RegisterGetProcessModules() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_process_modules",
		Description: "Get modules loaded by a specific process",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("get_process_modules",
			mcp.WithDescription("Get modules loaded by a specific process"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithNumber("pid",
				mcp.Required(),
				mcp.Description("Process ID")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, ok := args["sid"].(string)
			if !ok {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			pid, ok := args["pid"].(float64)
			if !ok {
				return tools.ErrorResult("pid parameter is required"), nil
			}

			resp, err := sendSensorCommand(ctx, sid, "os_processes", map[string]interface{}{
				"pid": int(pid),
			})
			if err != nil {
				return tools.ErrorResultf("failed to get process modules: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterGetProcessStrings registers the get_process_strings tool
func RegisterGetProcessStrings() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_process_strings",
		Description: "Get strings from process memory",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("get_process_strings",
			mcp.WithDescription("Get strings from process memory"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithNumber("pid",
				mcp.Required(),
				mcp.Description("Process ID")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, ok := args["sid"].(string)
			if !ok {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			pid, ok := args["pid"].(float64)
			if !ok {
				return tools.ErrorResult("pid parameter is required"), nil
			}

			resp, err := sendSensorCommand(ctx, sid, "mem_strings", map[string]interface{}{
				"pid": int(pid),
			})
			if err != nil {
				return tools.ErrorResultf("failed to get process strings: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterFindStrings registers the find_strings tool
func RegisterFindStrings() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "find_strings",
		Description: "Find specific strings in process memory",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("find_strings",
			mcp.WithDescription("Find specific strings in process memory"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithString("strings",
				mcp.Required(),
				mcp.Description("Comma-separated list of strings to find")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, ok := args["sid"].(string)
			if !ok {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			strings, ok := args["strings"].(string)
			if !ok {
				return tools.ErrorResult("strings parameter is required"), nil
			}

			resp, err := sendSensorCommand(ctx, sid, "mem_find_string", map[string]interface{}{
				"str": strings,
			})
			if err != nil {
				return tools.ErrorResultf("failed to find strings: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterGetPackages registers the get_packages tool
func RegisterGetPackages() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_packages",
		Description: "Get installed packages on a sensor",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("get_packages",
			mcp.WithDescription("Get installed packages on a sensor"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, ok := args["sid"].(string)
			if !ok {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			resp, err := sendSensorCommand(ctx, sid, "os_packages", map[string]interface{}{})
			if err != nil {
				return tools.ErrorResultf("failed to get packages: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterGetServices registers the get_services tool
func RegisterGetServices() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_services",
		Description: "Get running services on a sensor",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("get_services",
			mcp.WithDescription("Get running services on a sensor"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, ok := args["sid"].(string)
			if !ok {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			resp, err := sendSensorCommand(ctx, sid, "os_services", map[string]interface{}{})
			if err != nil {
				return tools.ErrorResultf("failed to get services: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterGetAutoruns registers the get_autoruns tool
func RegisterGetAutoruns() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_autoruns",
		Description: "Get autorun entries on a sensor",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("get_autoruns",
			mcp.WithDescription("Get autorun entries on a sensor"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, ok := args["sid"].(string)
			if !ok {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			resp, err := sendSensorCommand(ctx, sid, "os_autoruns", map[string]interface{}{})
			if err != nil {
				return tools.ErrorResultf("failed to get autoruns: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterGetDrivers registers the get_drivers tool
func RegisterGetDrivers() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_drivers",
		Description: "Get installed drivers on a sensor",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("get_drivers",
			mcp.WithDescription("Get installed drivers on a sensor"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, ok := args["sid"].(string)
			if !ok {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			resp, err := sendSensorCommand(ctx, sid, "os_drivers", map[string]interface{}{})
			if err != nil {
				return tools.ErrorResultf("failed to get drivers: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterGetUsers registers the get_users tool
func RegisterGetUsers() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_users",
		Description: "Get system users on a sensor",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("get_users",
			mcp.WithDescription("Get system users on a sensor"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, ok := args["sid"].(string)
			if !ok {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			resp, err := sendSensorCommand(ctx, sid, "os_users", map[string]interface{}{})
			if err != nil {
				return tools.ErrorResultf("failed to get users: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterGetRegistryKeys registers the get_registry_keys tool
func RegisterGetRegistryKeys() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_registry_keys",
		Description: "Get Windows registry keys (Windows only)",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("get_registry_keys",
			mcp.WithDescription("Get Windows registry keys (Windows only)"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("Registry path to query")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, ok := args["sid"].(string)
			if !ok {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			path, ok := args["path"].(string)
			if !ok {
				return tools.ErrorResult("path parameter is required"), nil
			}

			resp, err := sendSensorCommand(ctx, sid, "reg_list", map[string]interface{}{
				"reg": path,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get registry keys: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterGetHistoricEvents registers the get_historic_events tool
func RegisterGetHistoricEvents() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_historic_events",
		Description: "Get historical events for a sensor between timestamps",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("get_historic_events",
			mcp.WithDescription("Get historical events for a sensor between timestamps"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithNumber("start",
				mcp.Required(),
				mcp.Description("Start timestamp (Unix epoch in seconds)")),
			mcp.WithNumber("end",
				mcp.Required(),
				mcp.Description("End timestamp (Unix epoch in seconds)")),
			mcp.WithNumber("limit",
				mcp.Description("Maximum number of events to return (default: 1000)")),
			mcp.WithString("event_type",
				mcp.Description("Filter by event type")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, ok := args["sid"].(string)
			if !ok {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			start, ok := args["start"].(float64)
			if !ok {
				return tools.ErrorResult("start parameter is required"), nil
			}

			end, ok := args["end"].(float64)
			if !ok {
				return tools.ErrorResult("end parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Build query parameters
			params := lc.Dict{
				"sid":   sid,
				"start": int64(start),
				"end":   int64(end),
			}

			if limit, ok := args["limit"].(float64); ok {
				params["limit"] = int(limit)
			} else {
				params["limit"] = 1000
			}

			if eventType, ok := args["event_type"].(string); ok {
				params["event_type"] = eventType
			}

			// Get historic events using the SDK method
			req := lc.HistoricEventsRequest{
				Start: int64(start),
				End:   int64(end),
			}

			if limit, ok := params["limit"].(int); ok {
				limitPtr := limit
				req.Limit = &limitPtr
			}

			if eventType, ok := params["event_type"].(string); ok {
				req.EventType = eventType
			}

			eventChan, closeFunc, err := org.GetHistoricEvents(sid, req)
			if err != nil {
				return tools.ErrorResultf("failed to get historic events: %v", err), nil
			}
			defer closeFunc()

			// Collect events from channel
			events := []lc.IteratedEvent{}
			for event := range eventChan {
				events = append(events, event)
			}

			return tools.SuccessResult(events), nil
		},
	})
}
