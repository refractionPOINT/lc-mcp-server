package tools

import (
	"context"
	"sync"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
)

// OAuth scope policy for tool calls.
//
// A tool needs limacharlie:read when its MCP readOnlyHint annotation is
// explicitly true, and limacharlie:write otherwise (destructive, non-read-only
// and unannotated tools alike: the policy fails closed). Scopes are
// hierarchical, admin > write > read (see auth.ScopeGrant).
//
// The policy only restricts MCP OAuth access tokens. API keys, LimaCharlie JWT
// passthrough and server-wide credentials are not OAuth-scoped and carry no
// grant, so they are never restricted here.

var (
	dispatchersMu sync.RWMutex
	dispatchers   = map[string]bool{}
)

// MarkScopeDispatcher declares a meta tool that does nothing itself but invoke
// another registered tool. The scope of such a call is decided by the TARGET
// tool, which the meta tool must check with CheckToolScope before dispatching;
// the transport therefore only requires read access to reach the meta tool.
// Without this declaration a meta tool is classified by its own annotations
// like any other tool.
func MarkScopeDispatcher(toolName string) {
	dispatchersMu.Lock()
	defer dispatchersMu.Unlock()
	dispatchers[toolName] = true
}

func isScopeDispatcher(toolName string) bool {
	dispatchersMu.RLock()
	defer dispatchersMu.RUnlock()
	return dispatchers[toolName]
}

// RequiredScope returns the OAuth scope needed to call the tool itself,
// ignoring any dispatch (see TransportScope).
func (reg *ToolRegistration) RequiredScope() string {
	return auth.ScopeRequiredForTool(reg.ToolSchema().Annotations.ReadOnlyHint)
}

// TransportScope returns the scope the transport requires before it will run
// the tool: RequiredScope, except that a scope dispatcher only needs read here
// because the target decides what the call needs.
func (reg *ToolRegistration) TransportScope() string {
	if isScopeDispatcher(reg.ToolName()) {
		return auth.ScopeRead
	}
	return reg.RequiredScope()
}

// CheckToolScope enforces the scope policy for calling reg on behalf of the
// request in ctx. It returns an *auth.InsufficientScopeError when the request's
// OAuth token lacks the scope the tool needs, and nil otherwise (including for
// every credential that is not OAuth-scoped). Meta tools that dispatch to
// another tool must call it with the target.
func CheckToolScope(ctx context.Context, reg *ToolRegistration) error {
	return auth.CheckScope(ctx, reg.ToolName(), reg.RequiredScope())
}
