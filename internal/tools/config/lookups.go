package config

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/refractionpoint/lc-mcp-go/internal/tools/hive"
)

func init() {
	// Register lookup table management tools
	RegisterListLookups()
	RegisterGetLookup()
	RegisterSetLookup()
	RegisterDeleteLookup()
	RegisterQueryLookup()
	// Note: list_rules and get_rule are deferred as they need generic hive operations
}

// RegisterListLookups registers the list_lookups tool
func RegisterListLookups() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_lookups",
		Description: "List all lookup tables in the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_lookups",
			mcp.WithDescription("List all lookup tables in the organization"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for lookups
			client := lc.NewHiveClient(org)

			// List all lookups from the lookup hive
			lookups, err := client.List(lc.HiveArgs{
				HiveName:     "lookup",
				PartitionKey: org.GetOID(),
			})
			if err != nil {
				return tools.ErrorResultf("failed to list lookups: %v", err), nil
			}

			// Convert to response format
			result := make(map[string]interface{})
			for name, data := range lookups {
				result[name] = map[string]interface{}{
					"data":     data.Data,
					"enabled":  data.UsrMtd.Enabled,
					"tags":     data.UsrMtd.Tags,
					"comment":  data.UsrMtd.Comment,
					"metadata": data.SysMtd,
				}
			}

			return tools.SuccessResult(map[string]interface{}{
				"lookups": result,
				"count":   len(result),
			}), nil
		},
	})
}

// RegisterGetLookup registers the get_lookup tool
func RegisterGetLookup() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_lookup",
		Description: "Get a specific lookup table",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_lookup",
			mcp.WithDescription("Get a specific lookup table"),
			mcp.WithString("lookup_name",
				mcp.Required(),
				mcp.Description("Name of the lookup table to retrieve")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			lookupName, ok := args["lookup_name"].(string)
			if !ok || lookupName == "" {
				return tools.ErrorResult("lookup_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for lookups
			client := lc.NewHiveClient(org)

			// Get lookup table
			lookup, err := client.Get(lc.HiveArgs{
				HiveName:     "lookup",
				PartitionKey: org.GetOID(),
				Key:          lookupName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get lookup '%s': %v", lookupName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"lookup": map[string]interface{}{
					"name":    lookupName,
					"data":    lookup.Data,
					"enabled": lookup.UsrMtd.Enabled,
					"tags":    lookup.UsrMtd.Tags,
					"comment": lookup.UsrMtd.Comment,
					"metadata": map[string]interface{}{
						"created_at":  lookup.SysMtd.CreatedAt,
						"created_by":  lookup.SysMtd.CreatedBy,
						"last_mod":    lookup.SysMtd.LastMod,
						"last_author": lookup.SysMtd.LastAuthor,
						"guid":        lookup.SysMtd.GUID,
					},
				},
			}), nil
		},
	})
}

// RegisterSetLookup registers the set_lookup tool
func RegisterSetLookup() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_lookup",
		Description: "Create or update a lookup table",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_lookup",
			mcp.WithDescription("Create or update a lookup table. Updating an existing table preserves its metadata (enabled state, tags, comment) unless enabled/tags/comment are given."),
			mcp.WithString("lookup_name",
				mcp.Required(),
				mcp.Description("Name for the lookup table")),
			mcp.WithObject("lookup_data",
				mcp.Required(),
				mcp.Description("Lookup table data (dict of strings -> dict, string is the key, dict value is the item metadata)")),
			hive.WithMetadataOverrideParams(),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			lookupName, ok := args["lookup_name"].(string)
			if !ok || lookupName == "" {
				return tools.ErrorResult("lookup_name parameter is required"), nil
			}

			lookupData, ok := args["lookup_data"].(map[string]interface{})
			if !ok {
				return tools.ErrorResult("lookup_data parameter is required and must be an object"), nil
			}

			overrides, err := hive.ParseMetadataOverrides(args)
			if err != nil {
				return tools.ErrorResultf("%v", err), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			warning, err := hive.SetRecord(org, hive.RecordWrite{
				HiveName:  "lookup",
				Key:       lookupName,
				Data:      lc.Dict{"lookup_data": lookupData},
				Overrides: overrides,
			})
			if err != nil {
				return tools.ErrorResultf("failed to set lookup '%s': %v", lookupName, err), nil
			}

			result := map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated lookup table '%s'", lookupName),
			}
			if warning != "" {
				result["warning"] = warning
			}
			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterDeleteLookup registers the delete_lookup tool
func RegisterDeleteLookup() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_lookup",
		Description: "Delete a lookup table",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_lookup",
			mcp.WithDescription("Delete a lookup table"),
			mcp.WithString("lookup_name",
				mcp.Required(),
				mcp.Description("Name of the lookup table to delete")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			lookupName, ok := args["lookup_name"].(string)
			if !ok || lookupName == "" {
				return tools.ErrorResult("lookup_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for lookups
			client := lc.NewHiveClient(org)

			// Delete lookup table
			_, err = client.Remove(lc.HiveArgs{
				HiveName:     "lookup",
				PartitionKey: org.GetOID(),
				Key:          lookupName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to delete lookup '%s': %v", lookupName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted lookup table '%s'", lookupName),
			}), nil
		},
	})
}

// lookupValue looks an indicator up in a stored lookup record's data. It reads
// the plain lookup_data table first, then the optimized form, where
// _LC_INDICATORS maps an indicator to its index in the _LC_METADATA list.
func lookupValue(data map[string]interface{}, key string) (interface{}, bool) {
	if table, ok := data["lookup_data"].(map[string]interface{}); ok {
		if value, found := table[key]; found {
			return value, true
		}
	}

	optimized, ok := data["optimized_lookup_data"].(map[string]interface{})
	if !ok {
		return nil, false
	}
	indicators, ok := optimized["_LC_INDICATORS"].(map[string]interface{})
	if !ok {
		return nil, false
	}
	rawIndex, found := indicators[key]
	if !found {
		return nil, false
	}
	metadata, _ := optimized["_LC_METADATA"].([]interface{})
	index, ok := asIndex(rawIndex)
	if !ok || index >= len(metadata) {
		// The indicator is present; its metadata is not addressable.
		return nil, true
	}
	return metadata[index], true
}

// asIndex converts a JSON-decoded number into a usable slice index. The SDK has
// two decode paths — plain encoding/json (float64) and its own clean unmarshal
// (int64/json.Number for large integers) — so all three shapes can turn up.
func asIndex(v interface{}) (int, bool) {
	switch n := v.(type) {
	case float64:
		if n < 0 {
			return 0, false
		}
		return int(n), true
	case int64:
		if n < 0 {
			return 0, false
		}
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil || i < 0 {
			return 0, false
		}
		return int(i), true
	}
	return 0, false
}

// RegisterQueryLookup registers the query_lookup tool
func RegisterQueryLookup() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "query_lookup",
		Description: "Query a value from a lookup table",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("query_lookup",
			mcp.WithDescription("Query a value from a lookup table"),
			mcp.WithString("lookup_name",
				mcp.Required(),
				mcp.Description("Name of the lookup table")),
			mcp.WithString("key",
				mcp.Required(),
				mcp.Description("Key to look up in the table")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			lookupName, ok := args["lookup_name"].(string)
			if !ok || lookupName == "" {
				return tools.ErrorResult("lookup_name parameter is required"), nil
			}

			key, ok := args["key"].(string)
			if !ok || key == "" {
				return tools.ErrorResult("key parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for lookups
			client := lc.NewHiveClient(org)

			// Get lookup table
			lookup, err := client.Get(lc.HiveArgs{
				HiveName:     "lookup",
				PartitionKey: org.GetOID(),
				Key:          lookupName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get lookup '%s': %v", lookupName, err), nil
			}

			// A stored lookup record only ever carries lookup_data and/or
			// optimized_lookup_data at its root (the hive's PreIngest hook
			// rewrites the record into that shape), so the indicators live one
			// level down.
			value, found := lookupValue(lookup.Data, key)

			return tools.SuccessResult(map[string]interface{}{
				"value": value,
				"found": found,
			}), nil
		},
	})
}
