package config

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	RegisterListAuditLogs()
}

// RegisterListAuditLogs registers the list_audit_logs tool
func RegisterListAuditLogs() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_audit_logs",
		Description: "List org audit logs",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_audit_logs",
			mcp.WithDescription("List org audit logs"),
			mcp.WithNumber("start",
				mcp.Description("Start of the window to query, in unix seconds")),
			mcp.WithNumber("end",
				mcp.Description("End of the window to query, in unix seconds")),
			mcp.WithNumber("limit",
				mcp.Description("Cap on the total number of audit entries returned (0 = no cap)")),
			mcp.WithString("event_type",
				mcp.Description("Restrict the results to a single audit event type")),
			mcp.WithString("sid",
				mcp.Description("Restrict the results to a single sensor ID")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			opts := lc.GetAuditLogsOptions{}
			if v, ok := args["start"].(float64); ok {
				opts.Start = int64(v)
			}
			if v, ok := args["end"].(float64); ok {
				opts.End = int64(v)
			}
			if v, ok := args["limit"].(float64); ok {
				opts.Limit = int(v)
			}
			if v, ok := args["event_type"].(string); ok {
				opts.EventType = v
			}
			if v, ok := args["sid"].(string); ok {
				opts.SID = v
			}

			logs, err := org.GetAuditLogs(opts)
			if err != nil {
				return tools.ErrorResultf("failed to get audit logs: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"events": logs,
				"count":  len(logs),
			}), nil
		},
	})
}
