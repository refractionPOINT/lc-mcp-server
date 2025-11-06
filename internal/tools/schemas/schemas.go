package schemas

import (
	"context"
	"fmt"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register event schema tools
	RegisterGetEventSchema()
	RegisterGetEventSchemasBatch()
	RegisterGetEventTypesWithSchemas()
	RegisterGetEventTypesWithSchemasForPlatform()
	RegisterGetPlatformNames()
	RegisterListWithPlatform()
}


// RegisterGetEventSchema registers the get_event_schema tool
func RegisterGetEventSchema() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_event_schema",
		Description: "Get a specific event type schema definition",
		Profile:     "event_schemas",
		RequiresOID: true,
		Schema: mcp.NewTool("get_event_schema",
			mcp.WithDescription("Get a specific schema definition for an event_type in LimaCharlie"),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name of the event_type to get (e.g. 'DNS_REQUEST')")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			name, ok := args["name"].(string)
			if !ok || name == "" {
				return tools.ErrorResult("name parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get schema for specific event type
			schemaResp, err := org.GetSchema(name)
			if err != nil {
				return tools.ErrorResultf("failed to get schema for '%s': %v", name, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"schema": map[string]interface{}{
					"event_type": schemaResp.Schema.EventType,
					"elements":   schemaResp.Schema.Elements,
				},
			}), nil
		},
	})
}

// RegisterGetEventSchemasBatch registers the get_event_schemas_batch tool
func RegisterGetEventSchemasBatch() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_event_schemas_batch",
		Description: "Get schema definitions for multiple event_types in parallel",
		Profile:     "event_schemas",
		RequiresOID: true,
		Schema: mcp.NewTool("get_event_schemas_batch",
			mcp.WithDescription("Get schema definitions for multiple event_types in LimaCharlie in parallel"),
			mcp.WithArray("event_names",
				mcp.Required(),
				mcp.Description("List of event_type names to get schemas for (e.g. ['DNS_REQUEST', 'PROCESS_START'])")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			eventNamesRaw, ok := args["event_names"].([]interface{})
			if !ok || len(eventNamesRaw) == 0 {
				return tools.ErrorResult("event_names parameter is required and must be a non-empty array"), nil
			}

			// Convert to string slice
			eventNames := make([]string, 0, len(eventNamesRaw))
			for _, name := range eventNamesRaw {
				if nameStr, ok := name.(string); ok {
					eventNames = append(eventNames, nameStr)
				}
			}

			if len(eventNames) == 0 {
				return tools.ErrorResult("event_names must contain at least one valid string"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Fetch schemas in parallel
			type schemaResult struct {
				name   string
				schema *lc.SchemaResponse
				err    error
			}

			results := make(chan schemaResult, len(eventNames))
			var wg sync.WaitGroup

			for _, name := range eventNames {
				wg.Add(1)
				go func(eventName string) {
					defer wg.Done()
					schema, err := org.GetSchema(eventName)
					results <- schemaResult{
						name:   eventName,
						schema: schema,
						err:    err,
					}
				}(name)
			}

			// Wait for all goroutines to complete
			go func() {
				wg.Wait()
				close(results)
			}()

			// Collect results
			schemas := make(map[string]interface{})
			errors := make(map[string]string)

			for result := range results {
				if result.err != nil {
					errors[result.name] = result.err.Error()
				} else {
					schemas[result.name] = map[string]interface{}{
						"event_type": result.schema.Schema.EventType,
						"elements":   result.schema.Schema.Elements,
					}
				}
			}

			response := map[string]interface{}{
				"schemas": schemas,
			}

			if len(errors) > 0 {
				response["errors"] = errors
			}

			return tools.SuccessResult(response), nil
		},
	})
}

// RegisterGetEventTypesWithSchemas registers the get_event_types_with_schemas tool
func RegisterGetEventTypesWithSchemas() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_event_types_with_schemas",
		Description: "Get all available event_types with schemas",
		Profile:     "event_schemas",
		RequiresOID: true,
		Schema: mcp.NewTool("get_event_types_with_schemas",
			mcp.WithDescription("Get all available event_type with schemas available for the organization"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get all schemas
			schemas, err := org.GetSchemas()
			if err != nil {
				return tools.ErrorResultf("failed to get schemas: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"event_types": schemas.EventTypes,
				"count":       len(schemas.EventTypes),
			}), nil
		},
	})
}

// RegisterGetEventTypesWithSchemasForPlatform registers the get_event_types_with_schemas_for_platform tool
func RegisterGetEventTypesWithSchemasForPlatform() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_event_types_with_schemas_for_platform",
		Description: "Get all available event_types with schemas for a specific platform",
		Profile:     "event_schemas",
		RequiresOID: true,
		Schema: mcp.NewTool("get_event_types_with_schemas_for_platform",
			mcp.WithDescription("Get all available event_type with schemas available for a specific platform"),
			mcp.WithString("platform",
				mcp.Required(),
				mcp.Description("The platform name to get event_types for (e.g. 'windows', 'linux', 'macos', as listed in the response from get_platform_names)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			platform, ok := args["platform"].(string)
			if !ok || platform == "" {
				return tools.ErrorResult("platform parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get schemas filtered by platform
			schemas, err := org.GetSchemasForPlatform(platform)
			if err != nil {
				return tools.ErrorResultf("failed to get schemas for platform '%s': %v", platform, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"event_types": schemas.EventTypes,
				"platform":    platform,
				"count":       len(schemas.EventTypes),
			}), nil
		},
	})
}

// RegisterGetPlatformNames registers the get_platform_names tool
func RegisterGetPlatformNames() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_platform_names",
		Description: "Get the platform names ontology from LimaCharlie",
		Profile:     "event_schemas",
		RequiresOID: true,
		Schema: mcp.NewTool("get_platform_names",
			mcp.WithDescription("Get the platform names ontology from LimaCharlie (does not mean the tenant has sensors for these platforms)"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get platform names from ontology
			platforms, err := org.GetPlatformNames()
			if err != nil {
				return tools.ErrorResultf("failed to get platform names: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"platforms": platforms,
				"count":     len(platforms),
			}), nil
		},
	})
}

// RegisterListWithPlatform registers the list_with_platform tool
func RegisterListWithPlatform() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_with_platform",
		Description: "List all sensors with a specific platform",
		Profile:     "event_schemas",
		RequiresOID: true,
		Schema: mcp.NewTool("list_with_platform",
			mcp.WithDescription("List all sensors with a specific platform"),
			mcp.WithString("platform",
				mcp.Required(),
				mcp.Description("The platform name to list sensors for (e.g. 'windows', 'linux', 'macos', as listed in the response from get_platform_names)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			platform, ok := args["platform"].(string)
			if !ok || platform == "" {
				return tools.ErrorResult("platform parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// List sensors with platform selector
			selector := fmt.Sprintf("plat == `%s`", platform)
			options := lc.ListSensorsOptions{
				Selector: selector,
			}

			sensors, err := org.ListSensors(options)
			if err != nil {
				return tools.ErrorResultf("failed to list sensors with platform '%s': %v", platform, err), nil
			}

			// Convert sensor map to list format
			sensorList := make([]map[string]interface{}, 0, len(sensors))
			for sid, sensor := range sensors {
				sensorList = append(sensorList, map[string]interface{}{
					"sid": sid,
					"details": map[string]interface{}{
						"oid":          sensor.OID,
						"iid":          sensor.IID,
						"platform":     sensor.Platform,
						"architecture": sensor.Architecture,
						"hostname":     sensor.Hostname,
						"internal_ip":  sensor.InternalIP,
						"external_ip":  sensor.ExternalIP,
						"enroll_ts":    sensor.EnrollTS,
						"alive_ts":     sensor.AliveTS,
						"is_isolated":  sensor.IsIsolated,
					},
				})
			}

			return tools.SuccessResult(map[string]interface{}{
				"sensors":  sensorList,
				"platform": platform,
				"count":    len(sensorList),
			}), nil
		},
	})
}
