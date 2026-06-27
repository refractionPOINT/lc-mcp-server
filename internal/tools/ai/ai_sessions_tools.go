package ai

import (
	"context"
	"log/slog"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register AI session / usage / chat management tools.
	RegisterStartAISession()
	RegisterListAISessions()
	RegisterGetAISession()
	RegisterGetAISessionHistory()
	RegisterTerminateAISession()
	RegisterListAIUsage()
	RegisterGetAIUsage()
	RegisterListAIChats()
	RegisterGetAIChat()
	RegisterGetAIChatHistory()
}

// stringArg returns the trimmed string at key, requiring it to be non-empty.
func optString(args map[string]interface{}, key string) (string, bool) {
	v, ok := args[key].(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// optStringPtr returns a *string when the arg is a non-empty string, else nil.
func optStringPtr(args map[string]interface{}, key string) *string {
	if v, ok := args[key].(string); ok && v != "" {
		return &v
	}
	return nil
}

// optIntPtr returns a *int when the arg is a JSON number, else nil.
func optIntPtr(args map[string]interface{}, key string) *int {
	switch n := args[key].(type) {
	case float64:
		i := int(n)
		return &i
	case int:
		i := n
		return &i
	}
	return nil
}

// optFloatPtr returns a *float64 when the arg is a number, else nil.
func optFloatPtr(args map[string]interface{}, key string) *float64 {
	switch n := args[key].(type) {
	case float64:
		f := n
		return &f
	case int:
		f := float64(n)
		return &f
	}
	return nil
}

// optBoolPtr returns a *bool when the arg is a bool, else nil.
func optBoolPtr(args map[string]interface{}, key string) *bool {
	if b, ok := args[key].(bool); ok {
		return &b
	}
	return nil
}

// optStringSlice returns a []string from an array arg, else nil.
func optStringSlice(args map[string]interface{}, key string) []string {
	raw, ok := args[key].([]interface{})
	if !ok || len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// RegisterStartAISession registers the start_ai_session tool.
func RegisterStartAISession() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "start_ai_session",
		Description: "Start an AI agent session from an ai_agent Hive definition (spends budget)",
		Profile:     "ai_powered",
		RequiresOID: true,
		Schema: mcp.NewTool("start_ai_session",
			mcp.WithDescription("Start an AI agent session using an ai_agent Hive definition as a template. This spends AI budget."),
			mcp.WithString("definition_name",
				mcp.Required(),
				mcp.Description("The ai_agent Hive record key (bare key or hive://ai_agent/<name> form) to use as the session template")),
			mcp.WithString("prompt",
				mcp.Description("Override the prompt from the definition")),
			mcp.WithString("name",
				mcp.Description("Override the session name")),
			mcp.WithString("idempotent_key",
				mcp.Description("Deduplication key for the session")),
			mcp.WithString("model",
				mcp.Description("Override the Anthropic model (e.g. claude-sonnet-4-6)")),
			mcp.WithNumber("max_turns",
				mcp.Description("Override the maximum number of agent turns")),
			mcp.WithNumber("max_budget_usd",
				mcp.Description("Override the hard USD cost cap")),
			mcp.WithNumber("task_budget_tokens",
				mcp.Description("Override the per-task token budget")),
			mcp.WithNumber("ttl_seconds",
				mcp.Description("Override the session time-to-live in seconds")),
			mcp.WithBoolean("one_shot",
				mcp.Description("Force one_shot mode on/off")),
			mcp.WithString("permission_mode",
				mcp.Description("Override the permission mode (acceptEdits, plan, bypassPermissions)")),
			mcp.WithArray("allowed_tools",
				mcp.Description("Override the allowed tools list")),
			mcp.WithArray("denied_tools",
				mcp.Description("Override the denied tools list")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			definitionName, ok := optString(args, "definition_name")
			if !ok {
				return tools.ErrorResult("definition_name parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			slog.Info("Tool called: start_ai_session", "definition_name", definitionName)

			opts := &lc.StartSessionOptions{
				Prompt:           optStringPtr(args, "prompt"),
				Name:             optStringPtr(args, "name"),
				IdempotentKey:    optStringPtr(args, "idempotent_key"),
				Model:            optStringPtr(args, "model"),
				MaxTurns:         optIntPtr(args, "max_turns"),
				MaxBudgetUSD:     optFloatPtr(args, "max_budget_usd"),
				TaskBudgetTokens: optIntPtr(args, "task_budget_tokens"),
				TTLSeconds:       optIntPtr(args, "ttl_seconds"),
				OneShot:          optBoolPtr(args, "one_shot"),
				PermissionMode:   optStringPtr(args, "permission_mode"),
				AllowedTools:     optStringSlice(args, "allowed_tools"),
				DeniedTools:      optStringSlice(args, "denied_tools"),
			}

			resp, err := org.AI().StartSession(ctx, definitionName, opts)
			if err != nil {
				return tools.ErrorResultf("failed to start AI session: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}(resp)), nil
		},
	})
}

// RegisterListAISessions registers the list_ai_sessions tool.
func RegisterListAISessions() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_ai_sessions",
		Description: "List org AI sessions",
		Profile:     "ai_powered",
		RequiresOID: true,
		Schema: mcp.NewTool("list_ai_sessions",
			mcp.WithDescription("List the organization's AI sessions (one page)"),
			mcp.WithString("status",
				mcp.Description("Filter by session status (running, starting, ended)")),
			mcp.WithNumber("limit",
				mcp.Description("Maximum results per page (1-200)")),
			mcp.WithString("cursor",
				mcp.Description("Pagination cursor from a previous response")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			opts := &lc.ListSessionsOptions{}
			if s, ok := optString(args, "status"); ok {
				opts.Status = s
			}
			if p := optIntPtr(args, "limit"); p != nil {
				opts.Limit = *p
			}
			if c, ok := optString(args, "cursor"); ok {
				opts.Cursor = c
			}

			resp, err := org.AI().ListSessions(ctx, opts)
			if err != nil {
				return tools.ErrorResultf("failed to list AI sessions: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}(resp)), nil
		},
	})
}

// RegisterGetAISession registers the get_ai_session tool.
func RegisterGetAISession() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_ai_session",
		Description: "Get one AI session",
		Profile:     "ai_powered",
		RequiresOID: true,
		Schema: mcp.NewTool("get_ai_session",
			mcp.WithDescription("Get details of a specific org AI session"),
			mcp.WithString("session_id",
				mcp.Required(),
				mcp.Description("The AI session ID")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sessionID, ok := optString(args, "session_id")
			if !ok {
				return tools.ErrorResult("session_id parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := org.AI().GetSession(ctx, sessionID)
			if err != nil {
				return tools.ErrorResultf("failed to get AI session '%s': %v", sessionID, err), nil
			}

			return tools.SuccessResult(map[string]interface{}(resp)), nil
		},
	})
}

// RegisterGetAISessionHistory registers the get_ai_session_history tool.
func RegisterGetAISessionHistory() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_ai_session_history",
		Description: "Get an AI session's conversation history",
		Profile:     "ai_powered",
		RequiresOID: true,
		Schema: mcp.NewTool("get_ai_session_history",
			mcp.WithDescription("Get the conversation history of an org AI session"),
			mcp.WithString("session_id",
				mcp.Required(),
				mcp.Description("The AI session ID")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sessionID, ok := optString(args, "session_id")
			if !ok {
				return tools.ErrorResult("session_id parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := org.AI().GetSessionHistory(ctx, sessionID)
			if err != nil {
				return tools.ErrorResultf("failed to get AI session history '%s': %v", sessionID, err), nil
			}

			return tools.SuccessResult(map[string]interface{}(resp)), nil
		},
	})
}

// RegisterTerminateAISession registers the terminate_ai_session tool.
func RegisterTerminateAISession() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "terminate_ai_session",
		Description: "Terminate a live AI session",
		Profile:     "ai_powered",
		RequiresOID: true,
		Schema: mcp.NewTool("terminate_ai_session",
			mcp.WithDescription("Terminate a running org AI session"),
			mcp.WithString("session_id",
				mcp.Required(),
				mcp.Description("The AI session ID to terminate")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sessionID, ok := optString(args, "session_id")
			if !ok {
				return tools.ErrorResult("session_id parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := org.AI().TerminateSession(ctx, sessionID)
			if err != nil {
				return tools.ErrorResultf("failed to terminate AI session '%s': %v", sessionID, err), nil
			}

			return tools.SuccessResult(map[string]interface{}(resp)), nil
		},
	})
}

// RegisterListAIUsage registers the list_ai_usage tool.
func RegisterListAIUsage() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_ai_usage",
		Description: "List AI usage identities",
		Profile:     "ai_powered",
		RequiresOID: true,
		Schema: mcp.NewTool("list_ai_usage",
			mcp.WithDescription("List all API key identities with AI session usage data"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := org.AI().ListUsageIdentities(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to list AI usage identities: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}(resp)), nil
		},
	})
}

// RegisterGetAIUsage registers the get_ai_usage tool.
func RegisterGetAIUsage() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_ai_usage",
		Description: "Get AI usage for an identity",
		Profile:     "ai_powered",
		RequiresOID: true,
		Schema: mcp.NewTool("get_ai_usage",
			mcp.WithDescription("Get hourly token and cost usage for a specific API key identity"),
			mcp.WithString("identity",
				mcp.Required(),
				mcp.Description("The API key identity to get usage for")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			identity, ok := optString(args, "identity")
			if !ok {
				return tools.ErrorResult("identity parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := org.AI().GetUsage(ctx, identity)
			if err != nil {
				return tools.ErrorResultf("failed to get AI usage for '%s': %v", identity, err), nil
			}

			return tools.SuccessResult(map[string]interface{}(resp)), nil
		},
	})
}

// RegisterListAIChats registers the list_ai_chats tool.
func RegisterListAIChats() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_ai_chats",
		Description: "List user AI chats",
		Profile:     "ai_powered",
		RequiresOID: true,
		Schema: mcp.NewTool("list_ai_chats",
			mcp.WithDescription("List the caller's user-owned AI chat sessions (one page)"),
			mcp.WithString("status",
				mcp.Description("Filter by session status (running, starting, ended)")),
			mcp.WithNumber("limit",
				mcp.Description("Maximum results per page (1-200)")),
			mcp.WithString("cursor",
				mcp.Description("Pagination cursor from a previous response")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			opts := &lc.ListSessionsOptions{}
			if s, ok := optString(args, "status"); ok {
				opts.Status = s
			}
			if p := optIntPtr(args, "limit"); p != nil {
				opts.Limit = *p
			}
			if c, ok := optString(args, "cursor"); ok {
				opts.Cursor = c
			}

			resp, err := org.AI().ListUserSessions(ctx, opts)
			if err != nil {
				return tools.ErrorResultf("failed to list AI chats: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}(resp)), nil
		},
	})
}

// RegisterGetAIChat registers the get_ai_chat tool.
func RegisterGetAIChat() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_ai_chat",
		Description: "Get one user AI chat",
		Profile:     "ai_powered",
		RequiresOID: true,
		Schema: mcp.NewTool("get_ai_chat",
			mcp.WithDescription("Get details of a specific user-owned AI chat session"),
			mcp.WithString("session_id",
				mcp.Required(),
				mcp.Description("The user AI chat session ID")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sessionID, ok := optString(args, "session_id")
			if !ok {
				return tools.ErrorResult("session_id parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := org.AI().GetUserSession(ctx, sessionID)
			if err != nil {
				return tools.ErrorResultf("failed to get AI chat '%s': %v", sessionID, err), nil
			}

			return tools.SuccessResult(map[string]interface{}(resp)), nil
		},
	})
}

// RegisterGetAIChatHistory registers the get_ai_chat_history tool.
func RegisterGetAIChatHistory() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_ai_chat_history",
		Description: "Get a user AI chat's conversation history",
		Profile:     "ai_powered",
		RequiresOID: true,
		Schema: mcp.NewTool("get_ai_chat_history",
			mcp.WithDescription("Get the conversation history of a user-owned AI chat session"),
			mcp.WithString("session_id",
				mcp.Required(),
				mcp.Description("The user AI chat session ID")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sessionID, ok := optString(args, "session_id")
			if !ok {
				return tools.ErrorResult("session_id parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := org.AI().GetUserSessionHistory(ctx, sessionID)
			if err != nil {
				return tools.ErrorResultf("failed to get AI chat history '%s': %v", sessionID, err), nil
			}

			return tools.SuccessResult(map[string]interface{}(resp)), nil
		},
	})
}
