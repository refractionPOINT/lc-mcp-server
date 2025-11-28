package hive

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register timeline management tools
	RegisterListTimelines()
	RegisterGetTimeline()
	RegisterSetTimeline()
	RegisterDeleteTimeline()
}

// RegisterListTimelines registers the list_timelines tool
func RegisterListTimelines() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_timelines",
		Description: "List all timelines in the organization",
		Profile:     "timeline_management",
		RequiresOID: true,
		Schema: mcp.NewTool("list_timelines",
			mcp.WithDescription("List all timelines in the organization"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for timelines
			hive := lc.NewHiveClient(org)

			// List all timelines from the timeline hive
			timelines, err := hive.List(lc.HiveArgs{
				HiveName:     "timeline",
				PartitionKey: org.GetOID(),
			})
			if err != nil {
				return tools.ErrorResultf("failed to list timelines: %v", err), nil
			}

			// Convert to response format
			result := make(map[string]interface{})
			for name, data := range timelines {
				result[name] = map[string]interface{}{
					"data":     data.Data,
					"enabled":  data.UsrMtd.Enabled,
					"tags":     data.UsrMtd.Tags,
					"comment":  data.UsrMtd.Comment,
					"metadata": data.SysMtd,
				}
			}

			return tools.SuccessResult(map[string]interface{}{
				"timelines": result,
				"count":     len(result),
			}), nil
		},
	})
}

// RegisterGetTimeline registers the get_timeline tool
func RegisterGetTimeline() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_timeline",
		Description: "Get a specific timeline",
		Profile:     "timeline_management",
		RequiresOID: true,
		Schema: mcp.NewTool("get_timeline",
			mcp.WithDescription("Get a specific timeline"),
			mcp.WithString("timeline_name",
				mcp.Required(),
				mcp.Description("Name of the timeline to retrieve")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			timelineName, ok := args["timeline_name"].(string)
			if !ok || timelineName == "" {
				return tools.ErrorResult("timeline_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for timelines
			hive := lc.NewHiveClient(org)

			// Get timeline
			timeline, err := hive.Get(lc.HiveArgs{
				HiveName:     "timeline",
				PartitionKey: org.GetOID(),
				Key:          timelineName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get timeline '%s': %v", timelineName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"timeline": map[string]interface{}{
					"name":    timelineName,
					"data":    timeline.Data,
					"enabled": timeline.UsrMtd.Enabled,
					"tags":    timeline.UsrMtd.Tags,
					"comment": timeline.UsrMtd.Comment,
					"metadata": map[string]interface{}{
						"created_at":  timeline.SysMtd.CreatedAt,
						"created_by":  timeline.SysMtd.CreatedBy,
						"last_mod":    timeline.SysMtd.LastMod,
						"last_author": timeline.SysMtd.LastAuthor,
						"guid":        timeline.SysMtd.GUID,
					},
				},
			}), nil
		},
	})
}

// RegisterSetTimeline registers the set_timeline tool
func RegisterSetTimeline() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_timeline",
		Description: "Create or update a timeline",
		Profile:     "timeline_management",
		RequiresOID: true,
		Schema: mcp.NewTool("set_timeline",
			mcp.WithDescription("Create or update a timeline"),
			mcp.WithString("timeline_name",
				mcp.Required(),
				mcp.Description("Name for the timeline")),
			mcp.WithObject("timeline_data",
				mcp.Required(),
				mcp.Description("Timeline data (name, description, status, priority, events, detections, entities, notes, summary, conclusion)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			timelineName, ok := args["timeline_name"].(string)
			if !ok || timelineName == "" {
				return tools.ErrorResult("timeline_name parameter is required"), nil
			}

			timelineData, ok := args["timeline_data"].(map[string]interface{})
			if !ok {
				return tools.ErrorResult("timeline_data parameter is required and must be an object"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for timelines
			hive := lc.NewHiveClient(org)

			// Set timeline
			enabled := true
			_, err = hive.Add(lc.HiveArgs{
				HiveName:     "timeline",
				PartitionKey: org.GetOID(),
				Key:          timelineName,
				Data:         lc.Dict(timelineData),
				Enabled:      &enabled,
			})
			if err != nil {
				return tools.ErrorResultf("failed to set timeline '%s': %v", timelineName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated timeline '%s'", timelineName),
			}), nil
		},
	})
}

// RegisterDeleteTimeline registers the delete_timeline tool
func RegisterDeleteTimeline() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_timeline",
		Description: "Delete a timeline",
		Profile:     "timeline_management",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_timeline",
			mcp.WithDescription("Delete a timeline"),
			mcp.WithString("timeline_name",
				mcp.Required(),
				mcp.Description("Name of the timeline to delete")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			timelineName, ok := args["timeline_name"].(string)
			if !ok || timelineName == "" {
				return tools.ErrorResult("timeline_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for timelines
			hive := lc.NewHiveClient(org)

			// Delete timeline
			_, err = hive.Remove(lc.HiveArgs{
				HiveName:     "timeline",
				PartitionKey: org.GetOID(),
				Key:          timelineName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to delete timeline '%s': %v", timelineName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted timeline '%s'", timelineName),
			}), nil
		},
	})
}
