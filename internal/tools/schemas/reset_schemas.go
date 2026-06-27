package schemas

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register schema-management tools
	RegisterResetEventSchemas()
}

// RegisterResetEventSchemas registers the reset_event_schemas tool
func RegisterResetEventSchemas() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "reset_event_schemas",
		Description: "Reset (recompute) event schemas",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("reset_event_schemas",
			mcp.WithDescription("Reset (recompute) all event schemas for the organization"),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			success, err := org.ResetSchemas()
			if err != nil {
				return tools.ErrorResultf("failed to reset event schemas: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"status":  "success",
				"success": success,
			}), nil
		},
	})
}
