package config

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
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

			// Create hive client for lookups
			hive := lc.NewHiveClient(org)

			// List all lookups from the lookup hive
			lookups, err := hive.List(lc.HiveArgs{
				HiveName:     "lookup",
				PartitionKey: "global",
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
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			lookupName, ok := args["lookup_name"].(string)
			if !ok || lookupName == "" {
				return tools.ErrorResult("lookup_name parameter is required"), nil
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

			// Create hive client for lookups
			hive := lc.NewHiveClient(org)

			// Get lookup table
			lookup, err := hive.Get(lc.HiveArgs{
				HiveName:     "lookup",
				PartitionKey: "global",
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
			mcp.WithDescription("Create or update a lookup table"),
			mcp.WithString("lookup_name",
				mcp.Required(),
				mcp.Description("Name for the lookup table")),
			mcp.WithObject("lookup_data",
				mcp.Required(),
				mcp.Description("Lookup table data (key-value pairs or list of items)")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
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

			// Create hive client for lookups
			hive := lc.NewHiveClient(org)

			// Set lookup table
			enabled := true
			_, err = hive.Add(lc.HiveArgs{
				HiveName:     "lookup",
				PartitionKey: "global",
				Key:          lookupName,
				Data:         lc.Dict(lookupData),
				Enabled:      &enabled,
			})
			if err != nil {
				return tools.ErrorResultf("failed to set lookup '%s': %v", lookupName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated lookup table '%s'", lookupName),
			}), nil
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
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			lookupName, ok := args["lookup_name"].(string)
			if !ok || lookupName == "" {
				return tools.ErrorResult("lookup_name parameter is required"), nil
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

			// Create hive client for lookups
			hive := lc.NewHiveClient(org)

			// Delete lookup table
			_, err = hive.Remove(lc.HiveArgs{
				HiveName:     "lookup",
				PartitionKey: "global",
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
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
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

			// Create hive client for lookups
			hive := lc.NewHiveClient(org)

			// Get lookup table
			lookup, err := hive.Get(lc.HiveArgs{
				HiveName:     "lookup",
				PartitionKey: "global",
				Key:          lookupName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get lookup '%s': %v", lookupName, err), nil
			}

			// Query the key from the lookup data
			value, found := lookup.Data[key]

			return tools.SuccessResult(map[string]interface{}{
				"value": value,
				"found": found,
			}), nil
		},
	})
}
