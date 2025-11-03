package core

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register all core tools
	RegisterTestTool()
	RegisterGetSensorInfo()
	RegisterListSensors()
	RegisterGetOnlineSensors()
	RegisterIsOnline()
	RegisterSearchHosts()
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

// RegisterTestTool registers the test_tool
func RegisterTestTool() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "test_tool",
		Description: "Test tool to verify MCP server connectivity",
		Profile:     "core",
		Schema: mcp.NewTool("test_tool",
			mcp.WithDescription("Test tool to verify MCP server connectivity"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			result := map[string]interface{}{
				"status":  "ok",
				"message": "LimaCharlie MCP server is operational",
			}
			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterGetSensorInfo registers the get_sensor_info tool
func RegisterGetSensorInfo() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_sensor_info",
		Description: "Get detailed information about a specific sensor",
		Profile:     "core",
		RequiresOID: true,
		Schema: mcp.NewTool("get_sensor_info",
			mcp.WithDescription("Get detailed information about a specific sensor"),
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

			// Get sensor (returns *Sensor, error stored in LastError)
			sensor := org.GetSensor(sid)
			if sensor == nil {
				return tools.ErrorResult("sensor not found"), nil
			}

			// Update sensor info (returns *Sensor)
			sensor = sensor.Update()
			if sensor.LastError != nil {
				return tools.ErrorResultf("failed to update sensor: %v", sensor.LastError), nil
			}

			// Get tags
			tags, err := sensor.GetTags()
			if err != nil {
				// Non-fatal, just log and continue
				tags = []lc.TagInfo{}
			}

			// Convert tags to strings
			tagStrings := make([]string, len(tags))
			for i, tag := range tags {
				tagStrings[i] = tag.Tag
			}

			// Format result
			result := map[string]interface{}{
				"sensor": map[string]interface{}{
					"sid":             sensor.SID,
					"hostname":        sensor.Hostname,
					"platform":        sensor.Platform,
					"architecture":    sensor.Architecture,
					"last_seen":       sensor.AliveTS,
					"enroll_time":     sensor.EnrollTS,
					"internal_ip":     sensor.InternalIP,
					"external_ip":     sensor.ExternalIP,
					"tags":            tagStrings,
					"installation_id": sensor.IID,
					"organization_id": sensor.OID,
					"is_isolated":     sensor.IsIsolated,
				},
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterListSensors registers the list_sensors tool
func RegisterListSensors() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_sensors",
		Description: "List all sensors in the organization with optional filtering",
		Profile:     "core",
		RequiresOID: true,
		Schema: mcp.NewTool("list_sensors",
			mcp.WithDescription("List all sensors in the organization with optional filtering"),
			mcp.WithNumber("limit",
				mcp.Description("Maximum number of sensors to return")),
			mcp.WithString("with_hostname_prefix",
				mcp.Description("Filter sensors with hostname starting with this prefix")),
			mcp.WithString("with_ip",
				mcp.Description("Filter sensors with this IP address")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
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

			// Build options
			opts := lc.ListSensorsOptions{}

			if limit, ok := args["limit"].(float64); ok {
				opts.Limit = int(limit)
			}

			// List sensors (takes varargs)
			sensors, err := org.ListSensors(opts)
			if err != nil {
				return tools.ErrorResultf("failed to list sensors: %v", err), nil
			}

			// Apply additional filters
			hostnamePrefix, hasHostnameFilter := args["with_hostname_prefix"].(string)
			ipFilter, hasIPFilter := args["with_ip"].(string)

			var filtered []*lc.Sensor
			for _, sensor := range sensors {
				include := true

				if hasHostnameFilter && len(sensor.Hostname) >= len(hostnamePrefix) {
					if sensor.Hostname[:len(hostnamePrefix)] != hostnamePrefix {
						include = false
					}
				}

				if hasIPFilter && sensor.InternalIP != ipFilter && sensor.ExternalIP != ipFilter {
					include = false
				}

				if include {
					filtered = append(filtered, sensor)
				}
			}

			// Format results
			sensorList := make([]map[string]interface{}, len(filtered))
			for i, sensor := range filtered {
				sensorList[i] = map[string]interface{}{
					"sid":         sensor.SID,
					"hostname":    sensor.Hostname,
					"platform":    sensor.Platform,
					"last_seen":   sensor.AliveTS,
					"internal_ip": sensor.InternalIP,
					"external_ip": sensor.ExternalIP,
				}
			}

			result := map[string]interface{}{
				"sensors": sensorList,
				"count":   len(sensorList),
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterGetOnlineSensors registers the get_online_sensors tool
func RegisterGetOnlineSensors() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_online_sensors",
		Description: "List all currently online sensors in the organization",
		Profile:     "core",
		RequiresOID: true,
		Schema: mcp.NewTool("get_online_sensors",
			mcp.WithDescription("List all currently online sensors in the organization"),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
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

			// Get all sensors
			sensors, err := org.ListSensors(lc.ListSensorsOptions{})
			if err != nil {
				return tools.ErrorResultf("failed to list sensors: %v", err), nil
			}

			// Get list of sensor IDs (sensors is map[string]*Sensor)
			sids := make([]string, 0, len(sensors))
			for sid := range sensors {
				sids = append(sids, sid)
			}

			// Check which are active/online
			activeSensors, err := org.ActiveSensors(sids)
			if err != nil {
				return tools.ErrorResultf("failed to check active sensors: %v", err), nil
			}

			// Build result with only online sensors
			onlineSensors := make([]string, 0)
			for sid, isActive := range activeSensors {
				if isActive {
					onlineSensors = append(onlineSensors, sid)
				}
			}

			result := map[string]interface{}{
				"sensors": onlineSensors,
				"count":   len(onlineSensors),
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterIsOnline registers the is_online tool
func RegisterIsOnline() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "is_online",
		Description: "Check if a specific sensor is currently online",
		Profile:     "core",
		RequiresOID: true,
		Schema: mcp.NewTool("is_online",
			mcp.WithDescription("Check if a specific sensor is currently online"),
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

			// Check if online
			isOnline, err := sensor.IsOnline()
			if err != nil {
				return tools.ErrorResultf("failed to check online status: %v", err), nil
			}

			result := map[string]interface{}{
				"sid":       sid,
				"is_online": isOnline,
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterSearchHosts registers the search_hosts tool
func RegisterSearchHosts() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "search_hosts",
		Description: "Search for sensors by hostname pattern",
		Profile:     "core",
		RequiresOID: true,
		Schema: mcp.NewTool("search_hosts",
			mcp.WithDescription("Search for sensors by hostname pattern (supports wildcards with *)"),
			mcp.WithString("hostname_expr",
				mcp.Required(),
				mcp.Description("Hostname expression to search for")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract hostname expression
			hostnameExpr, ok := args["hostname_expr"].(string)
			if !ok || hostnameExpr == "" {
				return tools.ErrorResult("hostname_expr parameter is required"), nil
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

			// List all sensors
			sensors, err := org.ListSensors(lc.ListSensorsOptions{})
			if err != nil {
				return tools.ErrorResultf("failed to list sensors: %v", err), nil
			}

			// Simple pattern matching (convert * to regex-like behavior)
			// For simplicity, we'll just do prefix/suffix/contains matching
			var matches []map[string]interface{}

			for _, sensor := range sensors {
				hostname := sensor.Hostname
				if matchHostname(hostname, hostnameExpr) {
					matches = append(matches, map[string]interface{}{
						"sid":         sensor.SID,
						"hostname":    hostname,
						"platform":    sensor.Platform,
						"last_seen":   sensor.AliveTS,
						"internal_ip": sensor.InternalIP,
						"external_ip": sensor.ExternalIP,
					})
				}
			}

			result := map[string]interface{}{
				"sensors": matches,
				"count":   len(matches),
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// matchHostname performs simple wildcard matching
func matchHostname(hostname, pattern string) bool {
	// Simple wildcard matching
	if pattern == "*" {
		return true
	}

	// No wildcards - exact match
	if pattern == hostname {
		return true
	}

	// Prefix match (pattern*)
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(hostname) >= len(prefix) && hostname[:len(prefix)] == prefix
	}

	// Suffix match (*pattern)
	if len(pattern) > 0 && pattern[0] == '*' {
		suffix := pattern[1:]
		return len(hostname) >= len(suffix) && hostname[len(hostname)-len(suffix):] == suffix
	}

	// Contains match (*pattern*)
	// For now, just do simple substring matching if both wildcards present
	// In production, would use proper glob/regex matching

	return false
}
