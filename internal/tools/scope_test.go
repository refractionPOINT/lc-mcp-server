package tools

import (
	"context"
	"errors"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func scopeCtx(scope string) context.Context {
	return auth.WithAuthContext(context.Background(), &auth.AuthContext{
		Mode: auth.AuthModeUIDOAuth, UID: "u", Scopes: auth.NewScopeGrant(scope),
	})
}

// registerScopeTool registers a tool with the given annotations and returns a
// pointer to its run counter.
func registerScopeTool(t *testing.T, name string, opts ...mcp.ToolOption) *int {
	t.Helper()
	runs := new(int)
	RegisterTool(&ToolRegistration{
		Name:        name,
		Description: name,
		Profile:     "core",
		Schema:      mcp.NewTool(name, append([]mcp.ToolOption{mcp.WithDescription(name)}, opts...)...),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			*runs++
			return SuccessResult("ran"), nil
		},
	})
	t.Cleanup(func() { UnregisterTool(name) })
	return runs
}

func TestRequiredScopeFollowsTheReadOnlyHint(t *testing.T) {
	registerScopeTool(t, "zz_scope_ro", mcp.WithReadOnlyHintAnnotation(true))
	registerScopeTool(t, "zz_scope_rw", mcp.WithReadOnlyHintAnnotation(false))
	registerScopeTool(t, "zz_scope_destructive", mcp.WithDestructiveHintAnnotation(true))
	registerScopeTool(t, "zz_scope_bare")

	for name, want := range map[string]string{
		"zz_scope_ro":          auth.ScopeRead,
		"zz_scope_rw":          auth.ScopeWrite,
		"zz_scope_destructive": auth.ScopeWrite,
		"zz_scope_bare":        auth.ScopeWrite,
	} {
		reg, ok := GetTool(name)
		require.True(t, ok)
		assert.Equal(t, want, reg.RequiredScope(), name)
		assert.Equal(t, want, reg.TransportScope(), "%s is not a dispatcher", name)
	}
}

func TestScopeDispatcherNeedsOnlyReadAtTheTransport(t *testing.T) {
	registerScopeTool(t, "zz_scope_dispatcher", mcp.WithDestructiveHintAnnotation(true))
	reg, _ := GetTool("zz_scope_dispatcher")
	assert.Equal(t, auth.ScopeWrite, reg.TransportScope())

	MarkScopeDispatcher("zz_scope_dispatcher")
	t.Cleanup(func() {
		dispatchersMu.Lock()
		delete(dispatchers, "zz_scope_dispatcher")
		dispatchersMu.Unlock()
	})

	assert.Equal(t, auth.ScopeRead, reg.TransportScope())
	assert.Equal(t, auth.ScopeWrite, reg.RequiredScope(), "its own classification is unchanged")
}

func TestCallToolHonorsTheCallersScope(t *testing.T) {
	roRuns := registerScopeTool(t, "zz_scope_call_ro", mcp.WithReadOnlyHintAnnotation(true))
	rwRuns := registerScopeTool(t, "zz_scope_call_rw", mcp.WithDestructiveHintAnnotation(true))

	t.Run("read token reads", func(t *testing.T) {
		res, err := CallTool(scopeCtx("limacharlie:read"), "zz_scope_call_ro", map[string]interface{}{})
		require.NoError(t, err)
		assert.False(t, res.IsError)
		assert.Equal(t, 1, *roRuns)
	})

	t.Run("read token cannot write", func(t *testing.T) {
		res, err := CallTool(scopeCtx("limacharlie:read"), "zz_scope_call_rw", map[string]interface{}{})
		assert.Nil(t, res)
		var scopeErr *auth.InsufficientScopeError
		require.True(t, errors.As(err, &scopeErr))
		assert.Equal(t, auth.ScopeWrite, scopeErr.Required)
		assert.Equal(t, 0, *rwRuns, "a refused call must not run the tool")
	})

	t.Run("write token writes", func(t *testing.T) {
		_, err := CallTool(scopeCtx("limacharlie:write"), "zz_scope_call_rw", map[string]interface{}{})
		require.NoError(t, err)
		assert.Equal(t, 1, *rwRuns)
	})

	t.Run("credentials that are not OAuth-scoped are unrestricted", func(t *testing.T) {
		ctx := auth.WithAuthContext(context.Background(), &auth.AuthContext{Mode: auth.AuthModeUIDKey, UID: "u", APIKey: "k"})
		_, err := CallTool(ctx, "zz_scope_call_rw", map[string]interface{}{})
		require.NoError(t, err)
		assert.Equal(t, 2, *rwRuns)

		_, err = CallTool(context.Background(), "zz_scope_call_rw", map[string]interface{}{})
		require.NoError(t, err)
		assert.Equal(t, 3, *rwRuns)
	})
}
