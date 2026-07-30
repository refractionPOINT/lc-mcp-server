package api

import (
	"context"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// lc_call_tool dispatches by name out of the global registry, so without a bound
// it is a way around a narrow endpoint: the transport only checked that the
// caller may invoke lc_call_tool, not that it may invoke the target. These tests
// pin that the request's allowed-tool set (the active profile, or the
// X-MCP-Tools allowlist) bounds indirect dispatch too.
func TestLCCallToolHonorsAllowedToolSet(t *testing.T) {
	const target = "test_allowed_set_target"

	ran := false
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        target,
		Description: "Target used to verify allowed-set containment",
		Profile:     "platform_admin",
		RequiresOID: false,
		Schema:      mcp.NewTool(target, mcp.WithDescription("Target used to verify allowed-set containment")),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ran = true
			return tools.SuccessResult(map[string]interface{}{"ok": true}), nil
		},
	})
	t.Cleanup(func() { tools.UnregisterTool(target) })

	call := func(ctx context.Context) (*mcp.CallToolResult, bool) {
		ran = false
		result, err := handleLCCallTool(ctx, map[string]interface{}{
			"tool_name":  target,
			"parameters": map[string]interface{}{},
		})
		if err != nil {
			t.Fatalf("handleLCCallTool returned a Go error: %v", err)
		}
		return result, ran
	}

	t.Run("target outside the allowed set is refused", func(t *testing.T) {
		ctx := auth.WithAllowedTools(context.Background(), []string{"lc_call_tool", "who_am_i"})
		result, handlerRan := call(ctx)
		if handlerRan {
			t.Error("handler ran for a tool outside the request's allowed set")
		}
		if !strings.Contains(resultText(result), "not available on this endpoint") {
			t.Errorf("expected a containment refusal, got: %+v", result)
		}
	})

	t.Run("target inside the allowed set runs", func(t *testing.T) {
		ctx := auth.WithAllowedTools(context.Background(), []string{"lc_call_tool", target})
		if _, handlerRan := call(ctx); !handlerRan {
			t.Error("handler did not run for a tool inside the request's allowed set")
		}
	})

	t.Run("no allowed set means unbounded (stdio)", func(t *testing.T) {
		// On stdio the profile is already a registration-time boundary, so an
		// absent set must not block dispatch.
		if _, handlerRan := call(context.Background()); !handlerRan {
			t.Error("handler did not run when no allowed set was recorded")
		}
	})
}

func resultText(result *mcp.CallToolResult) string {
	if result == nil {
		return ""
	}
	var b strings.Builder
	for _, content := range result.Content {
		if text, ok := content.(mcp.TextContent); ok {
			b.WriteString(text.Text)
		}
	}
	return b.String()
}
