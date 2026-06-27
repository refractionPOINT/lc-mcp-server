package hive

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	RegisterGetHiveSchema()
	RegisterValidateHiveRecord()
}

// RegisterGetHiveSchema registers the get_hive_schema tool
func RegisterGetHiveSchema() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_hive_schema",
		Description: "Get a hive's record schema",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_hive_schema",
			mcp.WithDescription("Get the JSON Schema describing the record type of a given hive"),
			mcp.WithString("hive_name",
				mcp.Required(),
				mcp.Description("Name of the hive (e.g. dr-general, external_adapter, cloud_sensor)")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			hiveName, ok := args["hive_name"].(string)
			if !ok || hiveName == "" {
				return tools.ErrorResult("hive_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			schema, err := org.GetHiveSchema(hiveName)
			if err != nil {
				return tools.ErrorResultf("failed to get hive schema for '%s': %v", hiveName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"hive_name": hiveName,
				"schema":    schema,
			}), nil
		},
	})
}

// RegisterValidateHiveRecord registers the validate_hive_record tool
func RegisterValidateHiveRecord() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "validate_hive_record",
		Description: "Validate a hive record against its schema",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("validate_hive_record",
			mcp.WithDescription("Validate a hive record against its schema without persisting it"),
			mcp.WithString("hive_name",
				mcp.Required(),
				mcp.Description("Name of the hive")),
			mcp.WithString("key",
				mcp.Required(),
				mcp.Description("Key (record name) to validate")),
			mcp.WithObject("data",
				mcp.Required(),
				mcp.Description("Record data payload to validate")),
			mcp.WithString("partition_key",
				mcp.Description("Hive partition (defaults to the organization OID)")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			hiveName, ok := args["hive_name"].(string)
			if !ok || hiveName == "" {
				return tools.ErrorResult("hive_name parameter is required"), nil
			}

			key, ok := args["key"].(string)
			if !ok || key == "" {
				return tools.ErrorResult("key parameter is required"), nil
			}

			data, ok := args["data"].(map[string]interface{})
			if !ok {
				return tools.ErrorResult("data parameter is required and must be an object"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			partitionKey, _ := args["partition_key"].(string)
			if partitionKey == "" {
				partitionKey = org.GetOID()
			}

			result, err := org.ValidateHiveRecord(hiveName, partitionKey, key, lc.Dict(data))
			if err != nil {
				return tools.ErrorResultf("failed to validate hive record '%s' in hive '%s': %v", key, hiveName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"hive_name": hiveName,
				"key":       key,
				"result":    result,
			}), nil
		},
	})
}
