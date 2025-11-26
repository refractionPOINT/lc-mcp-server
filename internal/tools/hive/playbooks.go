package hive

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register playbook management tools
	RegisterListPlaybooks()
	RegisterGetPlaybook()
	RegisterSetPlaybook()
	RegisterDeletePlaybook()
}

// RegisterListPlaybooks registers the list_playbooks tool
func RegisterListPlaybooks() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_playbooks",
		Description: "List all playbooks in the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_playbooks",
			mcp.WithDescription("List all playbooks in the organization"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for playbooks
			hive := lc.NewHiveClient(org)

			// List all playbooks from the playbook hive
			playbooks, err := hive.List(lc.HiveArgs{
				HiveName:     "playbook",
				PartitionKey: org.GetOID(),
			})
			if err != nil {
				return tools.ErrorResultf("failed to list playbooks: %v", err), nil
			}

			// Convert to response format
			result := make(map[string]interface{})
			for name, data := range playbooks {
				result[name] = map[string]interface{}{
					"data":     data.Data,
					"enabled":  data.UsrMtd.Enabled,
					"tags":     data.UsrMtd.Tags,
					"comment":  data.UsrMtd.Comment,
					"metadata": data.SysMtd,
				}
			}

			return tools.SuccessResult(map[string]interface{}{
				"playbooks": result,
				"count":     len(result),
			}), nil
		},
	})
}

// RegisterGetPlaybook registers the get_playbook tool
func RegisterGetPlaybook() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_playbook",
		Description: "Get a specific playbook definition",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_playbook",
			mcp.WithDescription("Get a specific playbook definition"),
			mcp.WithString("playbook_name",
				mcp.Required(),
				mcp.Description("Name of the playbook to retrieve")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			playbookName, ok := args["playbook_name"].(string)
			if !ok || playbookName == "" {
				return tools.ErrorResult("playbook_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for playbooks
			hive := lc.NewHiveClient(org)

			// Get playbook
			playbook, err := hive.Get(lc.HiveArgs{
				HiveName:     "playbook",
				PartitionKey: org.GetOID(),
				Key:          playbookName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get playbook '%s': %v", playbookName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"playbook": map[string]interface{}{
					"name":    playbookName,
					"data":    playbook.Data,
					"enabled": playbook.UsrMtd.Enabled,
					"tags":    playbook.UsrMtd.Tags,
					"comment": playbook.UsrMtd.Comment,
					"metadata": map[string]interface{}{
						"created_at":  playbook.SysMtd.CreatedAt,
						"created_by":  playbook.SysMtd.CreatedBy,
						"last_mod":    playbook.SysMtd.LastMod,
						"last_author": playbook.SysMtd.LastAuthor,
						"guid":        playbook.SysMtd.GUID,
					},
				},
			}), nil
		},
	})
}

// RegisterSetPlaybook registers the set_playbook tool
func RegisterSetPlaybook() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_playbook",
		Description: "Create or update a playbook",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_playbook",
			mcp.WithDescription("Create or update a playbook"),
			mcp.WithString("playbook_name",
				mcp.Required(),
				mcp.Description("Name for the playbook")),
			mcp.WithObject("playbook_data",
				mcp.Required(),
				mcp.Description("Playbook definition (steps, conditions, actions)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			playbookName, ok := args["playbook_name"].(string)
			if !ok || playbookName == "" {
				return tools.ErrorResult("playbook_name parameter is required"), nil
			}

			playbookData, ok := args["playbook_data"].(map[string]interface{})
			if !ok {
				return tools.ErrorResult("playbook_data parameter is required and must be an object"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for playbooks
			hive := lc.NewHiveClient(org)

			// Set playbook
			enabled := true
			_, err = hive.Add(lc.HiveArgs{
				HiveName:     "playbook",
				PartitionKey: org.GetOID(),
				Key:          playbookName,
				Data:         lc.Dict(playbookData),
				Enabled:      &enabled,
			})
			if err != nil {
				return tools.ErrorResultf("failed to set playbook '%s': %v", playbookName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated playbook '%s'", playbookName),
			}), nil
		},
	})
}

// RegisterDeletePlaybook registers the delete_playbook tool
func RegisterDeletePlaybook() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_playbook",
		Description: "Delete a playbook",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_playbook",
			mcp.WithDescription("Delete a playbook"),
			mcp.WithString("playbook_name",
				mcp.Required(),
				mcp.Description("Name of the playbook to delete")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			playbookName, ok := args["playbook_name"].(string)
			if !ok || playbookName == "" {
				return tools.ErrorResult("playbook_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for playbooks
			hive := lc.NewHiveClient(org)

			// Delete playbook
			_, err = hive.Remove(lc.HiveArgs{
				HiveName:     "playbook",
				PartitionKey: org.GetOID(),
				Key:          playbookName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to delete playbook '%s': %v", playbookName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted playbook '%s'", playbookName),
			}), nil
		},
	})
}
