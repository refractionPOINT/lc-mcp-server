package hive

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register SOP management tools
	RegisterListSops()
	RegisterGetSop()
	RegisterSetSop()
	RegisterDeleteSop()
}

// RegisterListSops registers the list_sops tool
func RegisterListSops() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_sops",
		Description: "List all Standard Operating Procedures in the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_sops",
			mcp.WithDescription("List all Standard Operating Procedures in the organization. The full listing carries every procedure body; use brief to get just the index."),
			withBriefParam("the 'description' field"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			brief := briefArg(args)

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for SOPs
			hive := lc.NewHiveClient(org)

			// List all SOPs from the sop hive
			sops, err := hive.List(lc.HiveArgs{
				HiveName:     "sop",
				PartitionKey: org.GetOID(),
			})
			if err != nil {
				return tools.ErrorResultf("failed to list SOPs: %v", err), nil
			}

			// Convert to response format
			result := make(map[string]interface{})
			for name, data := range sops {
				payload := data.Data
				if brief {
					payload = BriefData(payload, "description")
				}
				result[name] = map[string]interface{}{
					"data":     payload,
					"enabled":  data.UsrMtd.Enabled,
					"tags":     data.UsrMtd.Tags,
					"comment":  data.UsrMtd.Comment,
					"metadata": data.SysMtd,
				}
			}

			return tools.SuccessResult(map[string]interface{}{
				"sops":  result,
				"count": len(result),
			}), nil
		},
	})
}

// RegisterGetSop registers the get_sop tool
func RegisterGetSop() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_sop",
		Description: "Get a specific Standard Operating Procedure",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_sop",
			mcp.WithDescription("Get a specific Standard Operating Procedure"),
			mcp.WithString("sop_name",
				mcp.Required(),
				mcp.Description("Name of the SOP to retrieve")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sopName, ok := args["sop_name"].(string)
			if !ok || sopName == "" {
				return tools.ErrorResult("sop_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for SOPs
			hive := lc.NewHiveClient(org)

			// Get SOP
			sop, err := hive.Get(lc.HiveArgs{
				HiveName:     "sop",
				PartitionKey: org.GetOID(),
				Key:          sopName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get SOP '%s': %v", sopName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"sop": map[string]interface{}{
					"name":    sopName,
					"data":    sop.Data,
					"enabled": sop.UsrMtd.Enabled,
					"tags":    sop.UsrMtd.Tags,
					"comment": sop.UsrMtd.Comment,
					"metadata": map[string]interface{}{
						"created_at":  sop.SysMtd.CreatedAt,
						"created_by":  sop.SysMtd.CreatedBy,
						"last_mod":    sop.SysMtd.LastMod,
						"last_author": sop.SysMtd.LastAuthor,
						"guid":        sop.SysMtd.GUID,
					},
				},
			}), nil
		},
	})
}

// RegisterSetSop registers the set_sop tool
func RegisterSetSop() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_sop",
		Description: "Create or update a Standard Operating Procedure",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_sop",
			mcp.WithDescription("Create or update a Standard Operating Procedure. Updating an existing SOP preserves its metadata (enabled state, tags, comment) unless enabled/tags/comment are given."),
			mcp.WithString("sop_name",
				mcp.Required(),
				mcp.Description("Name for the SOP")),
			mcp.WithString("text",
				mcp.Required(),
				mcp.Description("The text content of the SOP")),
			mcp.WithString("description",
				mcp.Description("Optional description for the SOP")),
			WithMetadataOverrideParams(),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sopName, ok := args["sop_name"].(string)
			if !ok || sopName == "" {
				return tools.ErrorResult("sop_name parameter is required"), nil
			}

			text, ok := args["text"].(string)
			if !ok || text == "" {
				return tools.ErrorResult("text parameter is required"), nil
			}

			description, _ := args["description"].(string)

			overrides, err := ParseMetadataOverrides(args)
			if err != nil {
				return tools.ErrorResultf("%v", err), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Build the data
			sopData := lc.Dict{
				"text": text,
			}
			if description != "" {
				sopData["description"] = description
			}

			warning, err := SetRecord(org, RecordWrite{
				HiveName:  "sop",
				Key:       sopName,
				Data:      sopData,
				Overrides: overrides,
			})
			if err != nil {
				return tools.ErrorResultf("failed to set SOP '%s': %v", sopName, err), nil
			}

			result := map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated SOP '%s'", sopName),
			}
			if warning != "" {
				result["warning"] = warning
			}
			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterDeleteSop registers the delete_sop tool
func RegisterDeleteSop() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_sop",
		Description: "Delete a Standard Operating Procedure",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_sop",
			mcp.WithDescription("Delete a Standard Operating Procedure"),
			mcp.WithString("sop_name",
				mcp.Required(),
				mcp.Description("Name of the SOP to delete")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sopName, ok := args["sop_name"].(string)
			if !ok || sopName == "" {
				return tools.ErrorResult("sop_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for SOPs
			hive := lc.NewHiveClient(org)

			// Delete SOP
			_, err = hive.Remove(lc.HiveArgs{
				HiveName:     "sop",
				PartitionKey: org.GetOID(),
				Key:          sopName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to delete SOP '%s': %v", sopName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted SOP '%s'", sopName),
			}), nil
		},
	})
}
