package admin

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// add_org_to_group / remove_org_from_group act on an organization named in an
// argument. That org must pass the same ai_agent.operate check as an
// org-scoped call, before any API call is made.
func TestGroupToolsCheckTheTargetOrg(t *testing.T) {
	RegisterAddOrgToGroup()
	RegisterRemoveOrgFromGroup()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	userCtx := func(enforce bool) context.Context {
		ctx := auth.WithAuthContext(context.Background(), &auth.AuthContext{
			Mode: auth.AuthModeUIDKey, UID: "user@example.com", APIKey: "not-a-real-key",
		})
		ctx = auth.WithSDKCache(ctx, auth.NewSDKCache(time.Minute, logger))
		if enforce {
			cache := auth.NewPermissionCache(time.Minute, logger)
			t.Cleanup(cache.Close)
			ctx = auth.WithPermissionCache(ctx, cache)
			ctx = auth.WithPermissionEnforcement(ctx, true)
		}
		return ctx
	}
	text := func(r *mcp.CallToolResult) string { return r.Content[0].(mcp.TextContent).Text }

	for _, name := range []string{"add_org_to_group", "remove_org_from_group"} {
		reg, ok := tools.GetTool(name)
		require.True(t, ok, name)

		t.Run(name+"/malformed oid refused", func(t *testing.T) {
			for _, oid := range []string{"..", ".", "../11111111-2222-3333-4444-555555555555", "my-org"} {
				res, err := reg.Invoke(userCtx(false), map[string]any{"gid": "g1", "oid": oid})
				require.NoError(t, err)
				require.True(t, res.IsError, oid)
				assert.Contains(t, text(res), "invalid organization ID")
			}
		})

		t.Run(name+"/permission check fails closed", func(t *testing.T) {
			// With enforcement on, a check that can't complete (the fake key
			// can't build an API client) denies the call.
			res, err := reg.Invoke(userCtx(true), map[string]any{"gid": "g1", "oid": "11111111-2222-3333-4444-555555555555"})
			require.NoError(t, err)
			require.True(t, res.IsError)
			assert.Contains(t, text(res), "permission check for organization")
		})
	}
}
