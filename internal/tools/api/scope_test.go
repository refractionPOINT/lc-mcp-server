package api

import (
	"context"
	"errors"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lc_call_tool is a scope dispatcher: the TARGET tool's classification decides
// what an OAuth token needs, so a read-only token cannot reach a destructive
// tool through it.

func TestLCCallToolIsAScopeDispatcher(t *testing.T) {
	reg, ok := tools.GetTool("lc_call_tool")
	require.True(t, ok)
	assert.Equal(t, auth.ScopeRead, reg.TransportScope(), "the transport only needs read to reach the dispatcher")
	assert.Equal(t, auth.ScopeWrite, reg.RequiredScope(), "its own annotations are destructive")
}

func TestLCCallToolEnforcesTheTargetsScope(t *testing.T) {
	runs := map[string]int{}
	register := func(name string, opts ...mcp.ToolOption) {
		tools.RegisterTool(&tools.ToolRegistration{
			Name:        name,
			Description: name,
			Profile:     "platform_admin",
			Schema:      mcp.NewTool(name, append([]mcp.ToolOption{mcp.WithDescription(name)}, opts...)...),
			Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
				runs[name]++
				return tools.SuccessResult("ran"), nil
			},
		})
		t.Cleanup(func() { tools.UnregisterTool(name) })
	}
	register("zz_api_scope_read", mcp.WithReadOnlyHintAnnotation(true))
	register("zz_api_scope_write", mcp.WithDestructiveHintAnnotation(true))
	register("zz_api_scope_bare")

	ctxFor := func(scope string) context.Context {
		return auth.WithAuthContext(context.Background(), &auth.AuthContext{
			Mode: auth.AuthModeUIDOAuth, UID: "u", Scopes: auth.NewScopeGrant(scope),
		})
	}
	call := func(ctx context.Context, target string) (*mcp.CallToolResult, error) {
		return handleLCCallTool(ctx, map[string]interface{}{"tool_name": target, "parameters": map[string]interface{}{}})
	}

	tests := []struct {
		name    string
		ctx     context.Context
		target  string
		allowed bool
	}{
		{"read token, read target", ctxFor("limacharlie:read"), "zz_api_scope_read", true},
		{"read token, destructive target", ctxFor("limacharlie:read"), "zz_api_scope_write", false},
		{"read token, unannotated target", ctxFor("limacharlie:read"), "zz_api_scope_bare", false},
		{"write token, destructive target", ctxFor("limacharlie:write"), "zz_api_scope_write", true},
		{"write token, unannotated target", ctxFor("limacharlie:write"), "zz_api_scope_bare", true},
		{"admin token, destructive target", ctxFor("limacharlie:admin"), "zz_api_scope_write", true},
		{"scopeless token, read target", ctxFor("openid"), "zz_api_scope_read", false},
		{"no grant (API key), destructive target", auth.WithAuthContext(context.Background(), &auth.AuthContext{Mode: auth.AuthModeUIDKey, UID: "u", APIKey: "k"}), "zz_api_scope_write", true},
		{"no auth context (stdio), destructive target", context.Background(), "zz_api_scope_write", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := runs[tc.target]
			res, err := call(tc.ctx, tc.target)
			if tc.allowed {
				require.NoError(t, err)
				assert.False(t, res.IsError)
				assert.Equal(t, before+1, runs[tc.target])
				return
			}
			// The typed error is what the HTTP transport maps to the 403
			// insufficient_scope challenge.
			var scopeErr *auth.InsufficientScopeError
			require.True(t, errors.As(err, &scopeErr), "got %v", err)
			assert.Equal(t, tc.target, scopeErr.Tool)
			assert.Equal(t, before, runs[tc.target], "a refused call must not run the target")
		})
	}
}
