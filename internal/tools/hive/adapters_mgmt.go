package hive

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	RegisterEnableAdapter()
	RegisterDisableAdapter()
	RegisterSetAdapterTags()
	RegisterGetAdapterSchema()
	RegisterGetAdapterSensors()
}

// adapterHiveName maps an adapter type to its backing hive name.
// "external" adapters live in the external_adapter hive; "cloud" adapters
// (cloud sensors) live in the cloud_sensor hive.
func adapterHiveName(adapterType string) (string, bool) {
	switch adapterType {
	case "external":
		return "external_adapter", true
	case "cloud":
		return "cloud_sensor", true
	default:
		return "", false
	}
}

// setAdapterEnabled flips the Enabled flag on an adapter record while
// preserving its config (data is untouched by an mtd update), tags and comment.
func setAdapterEnabled(ctx context.Context, args map[string]interface{}, enabled bool) (*mcp.CallToolResult, error) {
	adapterName, ok := args["adapter_name"].(string)
	if !ok || adapterName == "" {
		return tools.ErrorResult("adapter_name parameter is required"), nil
	}
	adapterType, _ := args["adapter_type"].(string)
	if adapterType == "" {
		adapterType = "external"
	}
	hiveName, ok := adapterHiveName(adapterType)
	if !ok {
		return tools.ErrorResult("adapter_type must be 'external' or 'cloud'"), nil
	}

	org, err := getOrganization(ctx)
	if err != nil {
		return tools.ErrorResultf("failed to get organization: %v", err), nil
	}

	err = updateRecordMTD(org, hiveName, org.GetOID(), adapterName, func(existing lc.UsrMtd) lc.HiveArgs {
		a := preservedArgs(existing)
		e := enabled
		a.Enabled = &e
		return a
	})
	if err != nil {
		return tools.ErrorResultf("failed to set enabled on adapter '%s': %v", adapterName, err), nil
	}

	verb := "disabled"
	if enabled {
		verb = "enabled"
	}
	return tools.SuccessResult(map[string]interface{}{
		"success":      true,
		"adapter_name": adapterName,
		"adapter_type": adapterType,
		"enabled":      enabled,
		"message":      fmt.Sprintf("Successfully %s adapter '%s'", verb, adapterName),
	}), nil
}

// RegisterEnableAdapter registers the enable_adapter tool
func RegisterEnableAdapter() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "enable_adapter",
		Description: "Enable an external/cloud adapter",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("enable_adapter",
			mcp.WithDescription("Enable an external or cloud adapter while preserving its config"),
			mcp.WithString("adapter_name",
				mcp.Required(),
				mcp.Description("Name of the adapter")),
			mcp.WithString("adapter_type",
				mcp.Description("Type of adapter: 'external' (default) or 'cloud'")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return setAdapterEnabled(ctx, args, true)
		},
	})
}

// RegisterDisableAdapter registers the disable_adapter tool
func RegisterDisableAdapter() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "disable_adapter",
		Description: "Disable an external/cloud adapter",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("disable_adapter",
			mcp.WithDescription("Disable an external or cloud adapter while preserving its config"),
			mcp.WithString("adapter_name",
				mcp.Required(),
				mcp.Description("Name of the adapter")),
			mcp.WithString("adapter_type",
				mcp.Description("Type of adapter: 'external' (default) or 'cloud'")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return setAdapterEnabled(ctx, args, false)
		},
	})
}

// RegisterSetAdapterTags registers the set_adapter_tags tool
func RegisterSetAdapterTags() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_adapter_tags",
		Description: "Set/add/remove tags on an adapter",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_adapter_tags",
			mcp.WithDescription("Set, add or remove tags on an external or cloud adapter while preserving its other metadata"),
			mcp.WithString("adapter_name",
				mcp.Required(),
				mcp.Description("Name of the adapter")),
			mcp.WithString("adapter_type",
				mcp.Description("Type of adapter: 'external' (default) or 'cloud'")),
			mcp.WithArray("tags",
				mcp.Required(),
				mcp.Description("Tags to apply")),
			mcp.WithString("action",
				mcp.Description("How to apply the tags: 'set' (default), 'add', or 'remove'")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			adapterName, ok := args["adapter_name"].(string)
			if !ok || adapterName == "" {
				return tools.ErrorResult("adapter_name parameter is required"), nil
			}
			adapterType, _ := args["adapter_type"].(string)
			if adapterType == "" {
				adapterType = "external"
			}
			hiveName, ok := adapterHiveName(adapterType)
			if !ok {
				return tools.ErrorResult("adapter_type must be 'external' or 'cloud'"), nil
			}
			tags, ok := stringSlice(args["tags"])
			if !ok {
				return tools.ErrorResult("tags parameter is required and must be an array of strings"), nil
			}
			action, _ := args["action"].(string)
			if action == "" {
				action = "set"
			}
			if action != "set" && action != "add" && action != "remove" {
				return tools.ErrorResult("action must be one of 'set', 'add', or 'remove'"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			var newTags []string
			err = updateRecordMTD(org, hiveName, org.GetOID(), adapterName, func(existing lc.UsrMtd) lc.HiveArgs {
				a := preservedArgs(existing)
				newTags = applyTagAction(existing.Tags, tags, action)
				if newTags == nil {
					newTags = []string{}
				}
				a.Tags = newTags
				return a
			})
			if err != nil {
				return tools.ErrorResultf("failed to set tags on adapter '%s': %v", adapterName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":      true,
				"adapter_name": adapterName,
				"adapter_type": adapterType,
				"action":       action,
				"tags":         newTags,
			}), nil
		},
	})
}

// RegisterGetAdapterSchema registers the get_adapter_schema tool
func RegisterGetAdapterSchema() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_adapter_schema",
		Description: "Get adapter config schema / types",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_adapter_schema",
			mcp.WithDescription("Get the config schema for external or cloud adapters"),
			mcp.WithString("adapter_type",
				mcp.Description("Type of adapter: 'external' (default) or 'cloud'")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			adapterType, _ := args["adapter_type"].(string)
			if adapterType == "" {
				adapterType = "external"
			}
			hiveName, ok := adapterHiveName(adapterType)
			if !ok {
				return tools.ErrorResult("adapter_type must be 'external' or 'cloud'"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			schema, err := org.GetHiveSchema(hiveName)
			if err != nil {
				return tools.ErrorResultf("failed to get adapter schema for '%s': %v", adapterType, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"adapter_type": adapterType,
				"hive_name":    hiveName,
				"schema":       schema,
			}), nil
		},
	})
}

// extractInstallationKey digs the installation key (which becomes the sensor's
// iid) out of an adapter record's data. Adapters carry it under
// client_options.identity.installation_key.
func extractInstallationKey(data map[string]interface{}) string {
	clientOptions, ok := data["client_options"].(map[string]interface{})
	if !ok {
		return ""
	}
	identity, ok := clientOptions["identity"].(map[string]interface{})
	if !ok {
		return ""
	}
	ikey, _ := identity["installation_key"].(string)
	return ikey
}

// RegisterGetAdapterSensors registers the get_adapter_sensors tool
func RegisterGetAdapterSensors() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_adapter_sensors",
		Description: "List sensors created by an adapter",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_adapter_sensors",
			mcp.WithDescription("List the sensors created by an external or cloud adapter (matched by the adapter's installation key)"),
			mcp.WithString("adapter_name",
				mcp.Required(),
				mcp.Description("Name of the adapter")),
			mcp.WithString("adapter_type",
				mcp.Description("Type of adapter: 'external' (default) or 'cloud'")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			adapterName, ok := args["adapter_name"].(string)
			if !ok || adapterName == "" {
				return tools.ErrorResult("adapter_name parameter is required"), nil
			}
			adapterType, _ := args["adapter_type"].(string)
			if adapterType == "" {
				adapterType = "external"
			}
			hiveName, ok := adapterHiveName(adapterType)
			if !ok {
				return tools.ErrorResult("adapter_type must be 'external' or 'cloud'"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			client := lc.NewHiveClient(org)
			record, err := client.Get(lc.HiveArgs{
				HiveName:     hiveName,
				PartitionKey: org.GetOID(),
				Key:          adapterName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get adapter '%s': %v", adapterName, err), nil
			}

			ikey := extractInstallationKey(record.Data)
			if ikey == "" {
				return tools.ErrorResultf("adapter '%s' has no client_options.identity.installation_key; cannot match sensors", adapterName), nil
			}

			// Match sensors whose iid equals the adapter's installation key.
			selector := fmt.Sprintf("iid == \"%s\"", ikey)
			sensors, err := org.ListSensorsFromSelector(selector)
			if err != nil {
				return tools.ErrorResultf("failed to list sensors for adapter '%s': %v", adapterName, err), nil
			}

			result := make([]map[string]interface{}, 0, len(sensors))
			for sid, s := range sensors {
				// Defensive: only keep sensors whose iid actually matches, in
				// case the selector is interpreted loosely by the backend.
				if s.IID != "" && s.IID != ikey {
					continue
				}
				result = append(result, map[string]interface{}{
					"sid":      sid,
					"iid":      s.IID,
					"hostname": s.Hostname,
					"platform": s.Platform,
					"did":      s.DID,
				})
			}

			return tools.SuccessResult(map[string]interface{}{
				"adapter_name":     adapterName,
				"adapter_type":     adapterType,
				"installation_key": ikey,
				"sensors":          result,
				"count":            len(result),
			}), nil
		},
	})
}
