package hive

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register cloud sensor management tools
	RegisterListCloudSensors()
	RegisterGetCloudSensor()
	RegisterSetCloudSensor()
	RegisterDeleteCloudSensor()
}

// RegisterListCloudSensors registers the list_cloud_sensors tool
func RegisterListCloudSensors() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_cloud_sensors",
		Description: "List all cloud sensor configurations",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_cloud_sensors",
			mcp.WithDescription("List all cloud sensor configurations"),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for cloud sensors
			hive := lc.NewHiveClient(org)

			// List all cloud sensors
			cloudSensors, err := hive.List(lc.HiveArgs{
				HiveName:     "cloud_sensor",
				PartitionKey: "global",
			})
			if err != nil {
				return tools.ErrorResultf("failed to list cloud sensors: %v", err), nil
			}

			// Convert to response format
			result := make(map[string]interface{})
			for name, data := range cloudSensors {
				result[name] = map[string]interface{}{
					"data":     data.Data,
					"enabled":  data.UsrMtd.Enabled,
					"tags":     data.UsrMtd.Tags,
					"comment":  data.UsrMtd.Comment,
					"metadata": data.SysMtd,
				}
			}

			return tools.SuccessResult(map[string]interface{}{
				"cloud_sensors": result,
				"count":         len(result),
			}), nil
		},
	})
}

// RegisterGetCloudSensor registers the get_cloud_sensor tool
func RegisterGetCloudSensor() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_cloud_sensor",
		Description: "Get a specific cloud sensor configuration",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_cloud_sensor",
			mcp.WithDescription("Get a specific cloud sensor configuration"),
			mcp.WithString("sensor_name",
				mcp.Required(),
				mcp.Description("Name of the cloud sensor to retrieve")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sensorName, ok := args["sensor_name"].(string)
			if !ok || sensorName == "" {
				return tools.ErrorResult("sensor_name parameter is required"), nil
			}

			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for cloud sensors
			hive := lc.NewHiveClient(org)

			// Get cloud sensor
			cloudSensor, err := hive.Get(lc.HiveArgs{
				HiveName:     "cloud_sensor",
				PartitionKey: "global",
				Key:          sensorName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get cloud sensor '%s': %v", sensorName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"cloud_sensor": map[string]interface{}{
					"name":    sensorName,
					"data":    cloudSensor.Data,
					"enabled": cloudSensor.UsrMtd.Enabled,
					"tags":    cloudSensor.UsrMtd.Tags,
					"comment": cloudSensor.UsrMtd.Comment,
					"metadata": map[string]interface{}{
						"created_at":  cloudSensor.SysMtd.CreatedAt,
						"created_by":  cloudSensor.SysMtd.CreatedBy,
						"last_mod":    cloudSensor.SysMtd.LastMod,
						"last_author": cloudSensor.SysMtd.LastAuthor,
						"guid":        cloudSensor.SysMtd.GUID,
					},
				},
			}), nil
		},
	})
}

// RegisterSetCloudSensor registers the set_cloud_sensor tool
func RegisterSetCloudSensor() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_cloud_sensor",
		Description: "Create or update a cloud sensor configuration",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_cloud_sensor",
			mcp.WithDescription("Create or update a cloud sensor configuration"),
			mcp.WithString("sensor_name",
				mcp.Required(),
				mcp.Description("Name for the cloud sensor")),
			mcp.WithObject("sensor_config",
				mcp.Required(),
				mcp.Description("Cloud sensor configuration data")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sensorName, ok := args["sensor_name"].(string)
			if !ok || sensorName == "" {
				return tools.ErrorResult("sensor_name parameter is required"), nil
			}

			sensorConfig, ok := args["sensor_config"].(map[string]interface{})
			if !ok {
				return tools.ErrorResult("sensor_config parameter is required and must be an object"), nil
			}

			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for cloud sensors
			hive := lc.NewHiveClient(org)

			// Set cloud sensor
			enabled := true
			_, err = hive.Add(lc.HiveArgs{
				HiveName:     "cloud_sensor",
				PartitionKey: "global",
				Key:          sensorName,
				Data:         lc.Dict(sensorConfig),
				Enabled:      &enabled,
			})
			if err != nil {
				return tools.ErrorResultf("failed to set cloud sensor '%s': %v", sensorName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated cloud sensor '%s'", sensorName),
			}), nil
		},
	})
}

// RegisterDeleteCloudSensor registers the delete_cloud_sensor tool
func RegisterDeleteCloudSensor() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_cloud_sensor",
		Description: "Delete a cloud sensor configuration",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_cloud_sensor",
			mcp.WithDescription("Delete a cloud sensor configuration"),
			mcp.WithString("sensor_name",
				mcp.Required(),
				mcp.Description("Name of the cloud sensor to delete")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sensorName, ok := args["sensor_name"].(string)
			if !ok || sensorName == "" {
				return tools.ErrorResult("sensor_name parameter is required"), nil
			}

			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for cloud sensors
			hive := lc.NewHiveClient(org)

			// Delete cloud sensor
			_, err = hive.Remove(lc.HiveArgs{
				HiveName:     "cloud_sensor",
				PartitionKey: "global",
				Key:          sensorName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to delete cloud sensor '%s': %v", sensorName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted cloud sensor '%s'", sensorName),
			}), nil
		},
	})
}
