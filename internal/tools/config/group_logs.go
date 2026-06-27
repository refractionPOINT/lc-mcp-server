package config

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	RegisterGetGroupLogs()
}

// RegisterGetGroupLogs registers the get_group_logs tool
func RegisterGetGroupLogs() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_group_logs",
		Description: "Get a group's logs",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_group_logs",
			mcp.WithDescription("Get a group's logs"),
			mcp.WithString("group_id",
				mcp.Required(),
				mcp.Description("ID of the group whose logs to retrieve")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			groupID, ok := args["group_id"].(string)
			if !ok || groupID == "" {
				return tools.ErrorResult("group_id parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			logs, err := org.GetGroupLogs(groupID)
			if err != nil {
				return tools.ErrorResultf("failed to get group logs for '%s': %v", groupID, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"logs": logs,
			}), nil
		},
	})
}
