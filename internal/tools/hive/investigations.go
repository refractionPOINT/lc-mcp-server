package hive

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register investigation management tools
	RegisterListInvestigations()
	RegisterGetInvestigation()
	RegisterSetInvestigation()
	RegisterDeleteInvestigation()
}

// RegisterListInvestigations registers the list_investigations tool
func RegisterListInvestigations() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_investigations",
		Description: "List all investigations in the organization",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("list_investigations",
			mcp.WithDescription("List all investigations in the organization"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for investigations
			hive := lc.NewHiveClient(org)

			// List all investigations from the investigation hive
			investigations, err := hive.List(lc.HiveArgs{
				HiveName:     "investigation",
				PartitionKey: org.GetOID(),
			})
			if err != nil {
				return tools.ErrorResultf("failed to list investigations: %v", err), nil
			}

			// Convert to response format
			result := make(map[string]interface{})
			for name, data := range investigations {
				result[name] = map[string]interface{}{
					"data":     data.Data,
					"enabled":  data.UsrMtd.Enabled,
					"tags":     data.UsrMtd.Tags,
					"comment":  data.UsrMtd.Comment,
					"metadata": data.SysMtd,
				}
			}

			return tools.SuccessResult(map[string]interface{}{
				"investigations": result,
				"count":          len(result),
			}), nil
		},
	})
}

// RegisterGetInvestigation registers the get_investigation tool
func RegisterGetInvestigation() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_investigation",
		Description: "Get a specific investigation",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("get_investigation",
			mcp.WithDescription("Get a specific investigation"),
			mcp.WithString("investigation_name",
				mcp.Required(),
				mcp.Description("Name of the investigation to retrieve")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			investigationName, ok := args["investigation_name"].(string)
			if !ok || investigationName == "" {
				return tools.ErrorResult("investigation_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for investigations
			hive := lc.NewHiveClient(org)

			// Get investigation
			investigation, err := hive.Get(lc.HiveArgs{
				HiveName:     "investigation",
				PartitionKey: org.GetOID(),
				Key:          investigationName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get investigation '%s': %v", investigationName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"investigation": map[string]interface{}{
					"name":    investigationName,
					"data":    investigation.Data,
					"enabled": investigation.UsrMtd.Enabled,
					"tags":    investigation.UsrMtd.Tags,
					"comment": investigation.UsrMtd.Comment,
					"metadata": map[string]interface{}{
						"created_at":  investigation.SysMtd.CreatedAt,
						"created_by":  investigation.SysMtd.CreatedBy,
						"last_mod":    investigation.SysMtd.LastMod,
						"last_author": investigation.SysMtd.LastAuthor,
						"guid":        investigation.SysMtd.GUID,
					},
				},
			}), nil
		},
	})
}

// RegisterSetInvestigation registers the set_investigation tool
func RegisterSetInvestigation() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_investigation",
		Description: "Create or update an investigation",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("set_investigation",
			mcp.WithDescription("Create or update an investigation"),
			mcp.WithString("investigation_name",
				mcp.Required(),
				mcp.Description("Name for the investigation")),
			mcp.WithObject("investigation_data",
				mcp.Required(),
				mcp.Description("Investigation data (name, description, status, priority, events, detections, entities, notes, summary, conclusion)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			investigationName, ok := args["investigation_name"].(string)
			if !ok || investigationName == "" {
				return tools.ErrorResult("investigation_name parameter is required"), nil
			}

			investigationData, ok := args["investigation_data"].(map[string]interface{})
			if !ok {
				return tools.ErrorResult("investigation_data parameter is required and must be an object"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for investigations
			hive := lc.NewHiveClient(org)

			// Set investigation
			enabled := true
			_, err = hive.Add(lc.HiveArgs{
				HiveName:     "investigation",
				PartitionKey: org.GetOID(),
				Key:          investigationName,
				Data:         lc.Dict(investigationData),
				Enabled:      &enabled,
			})
			if err != nil {
				return tools.ErrorResultf("failed to set investigation '%s': %v", investigationName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated investigation '%s'", investigationName),
			}), nil
		},
	})
}

// RegisterDeleteInvestigation registers the delete_investigation tool
func RegisterDeleteInvestigation() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_investigation",
		Description: "Delete an investigation",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_investigation",
			mcp.WithDescription("Delete an investigation"),
			mcp.WithString("investigation_name",
				mcp.Required(),
				mcp.Description("Name of the investigation to delete")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			investigationName, ok := args["investigation_name"].(string)
			if !ok || investigationName == "" {
				return tools.ErrorResult("investigation_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for investigations
			hive := lc.NewHiveClient(org)

			// Delete investigation
			_, err = hive.Remove(lc.HiveArgs{
				HiveName:     "investigation",
				PartitionKey: org.GetOID(),
				Key:          investigationName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to delete investigation '%s': %v", investigationName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted investigation '%s'", investigationName),
			}), nil
		},
	})
}
