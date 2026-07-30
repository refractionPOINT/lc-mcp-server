package core

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
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
	RegisterListSensorTags()
}

// RegisterTestTool registers the test_tool
func RegisterTestTool() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "test_tool",
		Description: "Test tool to verify MCP server connectivity",
		Profile:     "core",
		Schema: mcp.NewTool("test_tool",
			mcp.WithDescription("Test tool to verify MCP server connectivity"),
			mcp.WithReadOnlyHintAnnotation(true),
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
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract and validate SID
			sid, err := tools.ExtractAndValidateSID(args)
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			// Get organization
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
			info := map[string]interface{}{
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
			}

			// Isolation is not readable from the sensor record (see
			// tools.GetSensorIsolation); a failure here is non-fatal, the rest
			// of the record is still worth returning.
			if isolation, err := tools.GetSensorIsolation(org, sid); err == nil {
				info["is_isolated"] = isolation.IsIsolated
				info["should_isolate"] = isolation.ShouldIsolate
			} else {
				info["isolation_error"] = err.Error()
			}

			return tools.SuccessResult(map[string]interface{}{"sensor": info}), nil
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
			mcp.WithString("selector",
				mcp.Description("Sensor selector expression using bexpr syntax. Examples: 'plat == `windows`', '`test` in tags', 'hostname matches `^web-`', 'int_ip == `10.0.0.1`'. Available fields: sid, oid, plat, arch, hostname, int_ip, ext_ip, alive, tags, etc.")),
			mcp.WithBoolean("online_only",
				mcp.Description("When true, return only online sensors. When false or omitted, return all sensors (no online/offline filtering). This is server-side filtering.")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {

			// Get organization
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Extract filter parameters
			selector, _ := args["selector"].(string)
			onlineOnly, _ := args["online_only"].(bool)

			// Build ListSensorsOptions for server-side filtering
			options := lc.ListSensorsOptions{
				Selector:   selector,
				OnlineOnly: onlineOnly,
			}

			// List sensors - SDK handles pagination internally using continuation tokens
			sensors, err := org.ListSensors(options)
			if err != nil {
				return tools.ErrorResultf("failed to list sensors: %v", err), nil
			}

			// Format results
			sensorList := make([]map[string]interface{}, 0, len(sensors))
			for _, sensor := range sensors {
				sensorList = append(sensorList, map[string]interface{}{
					"sid":         sensor.SID,
					"hostname":    sensor.Hostname,
					"platform":    sensor.Platform,
					"last_seen":   sensor.AliveTS,
					"internal_ip": sensor.InternalIP,
					"external_ip": sensor.ExternalIP,
				})
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
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {

			// Get organization
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Filter server-side rather than listing the whole fleet and then
			// POSTing every SID back to the online endpoint.
			sensors, err := org.ListSensors(lc.ListSensorsOptions{OnlineOnly: true})
			if err != nil {
				return tools.ErrorResultf("failed to list online sensors: %v", err), nil
			}

			onlineSensors := make([]map[string]interface{}, 0, len(sensors))
			for _, sensor := range sensors {
				onlineSensors = append(onlineSensors, map[string]interface{}{
					"sid":         sensor.SID,
					"hostname":    sensor.Hostname,
					"platform":    sensor.Platform,
					"internal_ip": sensor.InternalIP,
					"external_ip": sensor.ExternalIP,
				})
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
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract and validate SID
			sid, err := tools.ExtractAndValidateSID(args)
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			// OID handling is now automatic via wrapHandler			// Get organization
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
			mcp.WithDescription("Search for sensors by hostname pattern. Matching is case-insensitive and supports the wildcards * (any run of characters), ? (one character) and [...] character classes; every other character, backslashes included, is matched literally."),
			mcp.WithString("hostname_expr",
				mcp.Required(),
				mcp.Description("Hostname pattern to match, e.g. 'web-*', '*-prod', 'db-0?'. Use '*' to match every host.")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract hostname expression
			hostnameExpr, ok := args["hostname_expr"].(string)
			if !ok || hostnameExpr == "" {
				return tools.ErrorResult("hostname_expr parameter is required"), nil
			}

			// Get organization
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// List all sensors
			sensors, err := org.ListSensors(lc.ListSensorsOptions{})
			if err != nil {
				return tools.ErrorResultf("failed to list sensors: %v", err), nil
			}

			matches := make([]map[string]interface{}, 0)
			for _, sensor := range sensors {
				if !matchHostname(sensor.Hostname, hostnameExpr) {
					continue
				}
				matches = append(matches, map[string]interface{}{
					"sid":         sensor.SID,
					"hostname":    sensor.Hostname,
					"platform":    sensor.Platform,
					"last_seen":   sensor.AliveTS,
					"internal_ip": sensor.InternalIP,
					"external_ip": sensor.ExternalIP,
				})
			}

			result := map[string]interface{}{
				"sensors": matches,
				"count":   len(matches),
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// matchHostname performs case-insensitive glob matching of a hostname against a
// pattern supporting *, ? and [...].
//
// Backslashes in the pattern are doubled before matching: filepath.Match reads a
// lone '\' as an escape character, so a Windows-style pattern would otherwise
// lose it, and '\\' is how filepath.Match spells a literal backslash. Hostnames
// are compared case-insensitively, matching how the platform's own hostname
// index is keyed.
func matchHostname(hostname, pattern string) bool {
	escaped := strings.ToLower(strings.ReplaceAll(pattern, `\`, `\\`))
	matched, err := filepath.Match(escaped, strings.ToLower(hostname))
	if err != nil {
		// Malformed pattern (e.g. an unterminated character class): fall back
		// to an exact, case-insensitive comparison.
		return strings.EqualFold(hostname, pattern)
	}
	return matched
}

// RegisterListSensorTags registers the list_sensor_tags tool
func RegisterListSensorTags() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_sensor_tags",
		Description: "List all tags in use by sensors in the organization",
		Profile:     "core",
		RequiresOID: true,
		Schema: mcp.NewTool("list_sensor_tags",
			mcp.WithDescription("List all tags currently in use by sensors in the organization. Returns a list of unique tag names."),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Get organization
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get all tags
			tags, err := org.GetAllTags()
			if err != nil {
				return tools.ErrorResultf("failed to list tags: %v", err), nil
			}

			result := map[string]interface{}{
				"tags":  tags,
				"count": len(tags),
			}

			return tools.SuccessResult(result), nil
		},
	})
}
