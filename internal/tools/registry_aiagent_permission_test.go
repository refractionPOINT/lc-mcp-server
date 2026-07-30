package tools

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
)

// The ai_agent.operate check must key off the OID a call actually executes
// against. Historically the check was nested inside the "oid argument present"
// branch for UID-mode callers, so a UID-mode caller with an OID pinned on its
// auth context (X-LC-UID + X-LC-API-KEY + X-LC-OID, or LC_UID + LC_API_KEY +
// LC_OID) could skip enforcement entirely simply by omitting the oid argument.
//
// The tests below drive both dispatch paths (wrapHandler and CallTool) across
// the auth-mode / oid-argument / ambient-OID matrix. Enforcement is observed
// through checkAIAgentPermission's first step, which resolves the organization
// from the context: with no SDK cache in the context that resolution fails and
// the call is rejected with "permission check failed", while a call that skips
// the check reaches the handler. That distinction is exactly what the bug was.

const testPermissionOID = "11111111-2222-3333-4444-555555555555"

// newPermissionTestContext builds a context with permission enforcement armed
// but no SDK cache, so that reaching the permission check is observable.
func newPermissionTestContext(authCtx *auth.AuthContext) context.Context {
	ctx := auth.WithAuthContext(context.Background(), authCtx)
	ctx = auth.WithPermissionCache(ctx, auth.NewPermissionCache(time.Minute, slog.Default()))
	return auth.WithPermissionEnforcement(ctx, true)
}

// registerPermissionTestTool registers a tool that records whether its handler
// ran, and removes it from the registry when the test finishes.
func registerPermissionTestTool(t *testing.T, name string, requiresOID bool, skipsCheck bool, ran *bool) *ToolRegistration {
	t.Helper()
	reg := &ToolRegistration{
		Name:                   name,
		Description:            "Tool used to verify ai_agent.operate enforcement",
		Profile:                "platform_admin",
		RequiresOID:            requiresOID,
		SkipsAIAgentPermission: skipsCheck,
		Schema:                 mcp.NewTool(name, mcp.WithDescription("Tool used to verify ai_agent.operate enforcement")),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			*ran = true
			return SuccessResult(map[string]interface{}{"ok": true}), nil
		},
	}
	RegisterTool(reg)
	t.Cleanup(func() { delete(registry, name) })
	return reg
}

// permissionCheckFired reports whether a result is the rejection produced by
// checkAIAgentPermission rather than a handler result.
func permissionCheckFired(result *mcp.CallToolResult) bool {
	if result == nil || !result.IsError {
		return false
	}
	for _, content := range result.Content {
		if text, ok := content.(mcp.TextContent); ok {
			if strings.Contains(text.Text, "permission check failed") ||
				strings.Contains(text.Text, "ai_agent.operate") {
				return true
			}
		}
	}
	return false
}

// resultText flattens a result's text content for assertions.
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

func TestWrapHandlerEnforcesAIAgentPermission(t *testing.T) {
	tests := []struct {
		name          string
		authCtx       *auth.AuthContext
		args          map[string]interface{}
		isUIDMode     bool
		requiresOID   bool
		skipsCheck    bool
		wantCheckRuns bool
	}{
		{
			// The regression: UID mode, an OID pinned on the auth context, and no
			// oid argument. Before the fix neither branch ran and the tool executed
			// against the ambient OID unchecked.
			name:          "UID mode, ambient OID, no oid argument",
			authCtx:       &auth.AuthContext{Mode: auth.AuthModeUIDKey, UID: "user@example.com", APIKey: "key", OID: testPermissionOID},
			args:          map[string]interface{}{},
			isUIDMode:     true,
			requiresOID:   true,
			wantCheckRuns: true,
		},
		{
			name:          "UID mode, oid argument",
			authCtx:       &auth.AuthContext{Mode: auth.AuthModeUIDKey, UID: "user@example.com", APIKey: "key"},
			args:          map[string]interface{}{"oid": testPermissionOID},
			isUIDMode:     true,
			requiresOID:   true,
			wantCheckRuns: true,
		},
		{
			name:          "UID mode, no ambient OID, no oid argument",
			authCtx:       &auth.AuthContext{Mode: auth.AuthModeUIDKey, UID: "user@example.com", APIKey: "key"},
			args:          map[string]interface{}{},
			isUIDMode:     true,
			requiresOID:   true,
			wantCheckRuns: false,
		},
		{
			name:          "normal mode, pinned OID",
			authCtx:       &auth.AuthContext{Mode: auth.AuthModeNormal, OID: testPermissionOID, APIKey: "key"},
			args:          map[string]interface{}{},
			requiresOID:   true,
			wantCheckRuns: true,
		},
		{
			name:          "tool does not require an OID",
			authCtx:       &auth.AuthContext{Mode: auth.AuthModeUIDKey, UID: "user@example.com", APIKey: "key", OID: testPermissionOID},
			args:          map[string]interface{}{},
			isUIDMode:     true,
			requiresOID:   false,
			wantCheckRuns: false,
		},
		{
			name:          "tool skips the ai_agent permission check",
			authCtx:       &auth.AuthContext{Mode: auth.AuthModeUIDKey, UID: "user@example.com", APIKey: "key", OID: testPermissionOID},
			args:          map[string]interface{}{},
			isUIDMode:     true,
			requiresOID:   true,
			skipsCheck:    true,
			wantCheckRuns: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handlerRan := false
			reg := registerPermissionTestTool(t, "test_wraphandler_permission_tool", tt.requiresOID, tt.skipsCheck, &handlerRan)

			handler := wrapHandler(reg, tt.isUIDMode)
			result, err := handler(newPermissionTestContext(tt.authCtx), mcp.CallToolRequest{
				Params: mcp.CallToolParams{Name: reg.Name, Arguments: tt.args},
			})
			if err != nil {
				t.Fatalf("handler returned a Go error: %v", err)
			}

			if got := permissionCheckFired(result); got != tt.wantCheckRuns {
				t.Errorf("ai_agent.operate check fired = %v, want %v (result: %+v)", got, tt.wantCheckRuns, result)
			}
			if handlerRan == tt.wantCheckRuns {
				t.Errorf("handler ran = %v while check fired = %v; the check must gate the handler", handlerRan, tt.wantCheckRuns)
			}
		})
	}
}

func TestCallToolEnforcesAIAgentPermission(t *testing.T) {
	tests := []struct {
		name          string
		authCtx       *auth.AuthContext
		args          map[string]interface{}
		wantCheckRuns bool
		// wantRefused marks the cases CallTool rejects before dispatch, where
		// neither the check nor the handler runs.
		wantRefused bool
	}{
		{
			// Same regression on the CallTool path, which lc_call_tool delegates to.
			// Its fallback branch used to be gated on AuthModeNormal.
			name:          "UID mode, ambient OID, no oid argument",
			authCtx:       &auth.AuthContext{Mode: auth.AuthModeUIDKey, UID: "user@example.com", APIKey: "key", OID: testPermissionOID},
			args:          map[string]interface{}{},
			wantCheckRuns: true,
		},
		{
			name:          "UID mode, oid argument",
			authCtx:       &auth.AuthContext{Mode: auth.AuthModeUIDKey, UID: "user@example.com", APIKey: "key"},
			args:          map[string]interface{}{"oid": testPermissionOID},
			wantCheckRuns: true,
		},
		{
			// An org-scoped tool with no resolvable OID is refused outright: it
			// would otherwise issue a malformed org-less request AND skip the
			// permission check on the way, which is the guard the HTTP dispatcher
			// applies for JWT passthrough and lc_call_tool used to sidestep.
			name:          "UID mode, no ambient OID, no oid argument is refused",
			authCtx:       &auth.AuthContext{Mode: auth.AuthModeUIDKey, UID: "user@example.com", APIKey: "key"},
			args:          map[string]interface{}{},
			wantCheckRuns: false,
			wantRefused:   true,
		},
		{
			name:          "normal mode, pinned OID",
			authCtx:       &auth.AuthContext{Mode: auth.AuthModeNormal, OID: testPermissionOID, APIKey: "key"},
			args:          map[string]interface{}{},
			wantCheckRuns: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handlerRan := false
			const toolName = "test_calltool_permission_tool"
			registerPermissionTestTool(t, toolName, true, false, &handlerRan)

			result, err := CallTool(newPermissionTestContext(tt.authCtx), toolName, tt.args)
			if err != nil {
				t.Fatalf("CallTool returned a Go error: %v", err)
			}

			if got := permissionCheckFired(result); got != tt.wantCheckRuns {
				t.Errorf("ai_agent.operate check fired = %v, want %v (result: %+v)", got, tt.wantCheckRuns, result)
			}

			// The handler must run only when nothing stopped it: neither a fired
			// permission check nor an up-front refusal.
			wantHandlerRan := !tt.wantCheckRuns && !tt.wantRefused
			if handlerRan != wantHandlerRan {
				t.Errorf("handler ran = %v, want %v (check fired = %v, refused = %v)", handlerRan, wantHandlerRan, tt.wantCheckRuns, tt.wantRefused)
			}
			if tt.wantRefused && !strings.Contains(resultText(result), "'oid' parameter is required") {
				t.Errorf("expected an oid-required refusal, got: %+v", result)
			}
		})
	}
}
