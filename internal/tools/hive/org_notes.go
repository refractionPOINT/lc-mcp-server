package hive

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register org notes management tools
	RegisterListOrgNotes()
	RegisterGetOrgNote()
	RegisterSetOrgNote()
	RegisterDeleteOrgNote()
}

// RegisterListOrgNotes registers the list_org_notes tool
func RegisterListOrgNotes() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_org_notes",
		Description: "List all organization notes",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_org_notes",
			mcp.WithDescription("List all organization notes. The full listing carries every note body; use brief to get just the index."),
			withBriefParam("the 'description' field"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			brief := briefArg(args)

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for org notes
			hive := lc.NewHiveClient(org)

			// List all org notes from the org_notes hive
			orgNotes, err := hive.List(lc.HiveArgs{
				HiveName:     "org_notes",
				PartitionKey: org.GetOID(),
			})
			if err != nil {
				return tools.ErrorResultf("failed to list org notes: %v", err), nil
			}

			// Convert to response format
			result := make(map[string]interface{})
			for name, data := range orgNotes {
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
				"org_notes": result,
				"count":     len(result),
			}), nil
		},
	})
}

// RegisterGetOrgNote registers the get_org_note tool
func RegisterGetOrgNote() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_org_note",
		Description: "Get a specific organization note",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_org_note",
			mcp.WithDescription("Get a specific organization note"),
			mcp.WithString("note_name",
				mcp.Required(),
				mcp.Description("Name of the org note to retrieve")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			noteName, ok := args["note_name"].(string)
			if !ok || noteName == "" {
				return tools.ErrorResult("note_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for org notes
			hive := lc.NewHiveClient(org)

			// Get org note
			orgNote, err := hive.Get(lc.HiveArgs{
				HiveName:     "org_notes",
				PartitionKey: org.GetOID(),
				Key:          noteName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get org note '%s': %v", noteName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"org_note": map[string]interface{}{
					"name":    noteName,
					"data":    orgNote.Data,
					"enabled": orgNote.UsrMtd.Enabled,
					"tags":    orgNote.UsrMtd.Tags,
					"comment": orgNote.UsrMtd.Comment,
					"metadata": map[string]interface{}{
						"created_at":  orgNote.SysMtd.CreatedAt,
						"created_by":  orgNote.SysMtd.CreatedBy,
						"last_mod":    orgNote.SysMtd.LastMod,
						"last_author": orgNote.SysMtd.LastAuthor,
						"guid":        orgNote.SysMtd.GUID,
					},
				},
			}), nil
		},
	})
}

// RegisterSetOrgNote registers the set_org_note tool
func RegisterSetOrgNote() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_org_note",
		Description: "Create or update an organization note",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_org_note",
			mcp.WithDescription("Create or update an organization note. Updating an existing note preserves its metadata (enabled state, tags, comment) unless enabled/tags/comment are given."),
			mcp.WithString("note_name",
				mcp.Required(),
				mcp.Description("Name for the org note")),
			mcp.WithString("text",
				mcp.Required(),
				mcp.Description("The text content of the note")),
			mcp.WithString("description",
				mcp.Description("Optional description for the note")),
			WithMetadataOverrideParams(),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			noteName, ok := args["note_name"].(string)
			if !ok || noteName == "" {
				return tools.ErrorResult("note_name parameter is required"), nil
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
			noteData := lc.Dict{
				"text": text,
			}
			if description != "" {
				noteData["description"] = description
			}

			warning, err := SetRecord(org, RecordWrite{
				HiveName:  "org_notes",
				Key:       noteName,
				Data:      noteData,
				Overrides: overrides,
			})
			if err != nil {
				return tools.ErrorResultf("failed to set org note '%s': %v", noteName, err), nil
			}

			result := map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated org note '%s'", noteName),
			}
			if warning != "" {
				result["warning"] = warning
			}
			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterDeleteOrgNote registers the delete_org_note tool
func RegisterDeleteOrgNote() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_org_note",
		Description: "Delete an organization note",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_org_note",
			mcp.WithDescription("Delete an organization note"),
			mcp.WithString("note_name",
				mcp.Required(),
				mcp.Description("Name of the org note to delete")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			noteName, ok := args["note_name"].(string)
			if !ok || noteName == "" {
				return tools.ErrorResult("note_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for org notes
			hive := lc.NewHiveClient(org)

			// Delete org note
			_, err = hive.Remove(lc.HiveArgs{
				HiveName:     "org_notes",
				PartitionKey: org.GetOID(),
				Key:          noteName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to delete org note '%s': %v", noteName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted org note '%s'", noteName),
			}), nil
		},
	})
}
