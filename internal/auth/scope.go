package auth

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// OAuth scopes the MCP authorization server issues (see oauth/metadata).
const (
	ScopeRead  = "limacharlie:read"
	ScopeWrite = "limacharlie:write"
	ScopeAdmin = "limacharlie:admin"
)

// defaultGrantedScopes is what the authorization server grants when a client
// asks for no scope (oauth/metadata.DefaultScope). A stored token that carries
// no scope at all is treated the same way, so that tokens issued before scopes
// were recorded keep working exactly as they did.
const defaultGrantedScopes = ScopeRead + " " + ScopeWrite

// ScopeGrant is the set of OAuth scopes granted to an MCP access token.
//
// Scopes are hierarchical, as the MCP authorization spec requires of servers
// ("servers MUST account for scope hierarchies, where a broader scope implies
// narrower ones"): admin implies write, and write implies read.
//
// A nil *ScopeGrant means "not OAuth-scoped": API keys, LimaCharlie JWT
// passthrough and server-wide credentials carry no OAuth scope and are never
// restricted by this mechanism. A non-nil grant ALWAYS restricts, including an
// empty one (a token whose scopes are all unrecognized can call nothing).
type ScopeGrant struct {
	scopes map[string]bool
}

// NewScopeGrant parses a space-separated OAuth scope string into a grant.
// An empty string means the authorization server's default scope. Unrecognized
// scopes are kept for display but grant nothing.
func NewScopeGrant(scope string) *ScopeGrant {
	if strings.TrimSpace(scope) == "" {
		scope = defaultGrantedScopes
	}
	g := &ScopeGrant{scopes: map[string]bool{}}
	for _, s := range strings.Fields(scope) {
		g.scopes[s] = true
	}
	return g
}

// Allows reports whether the grant satisfies the required scope, honoring the
// hierarchy. An empty required scope is always satisfied.
func (g *ScopeGrant) Allows(required string) bool {
	if g == nil || required == "" {
		return true
	}
	if g.scopes[ScopeAdmin] {
		return true
	}
	switch required {
	case ScopeRead:
		return g.scopes[ScopeRead] || g.scopes[ScopeWrite]
	case ScopeWrite:
		return g.scopes[ScopeWrite]
	case ScopeAdmin:
		return false
	default:
		// A scope this server does not define can only be granted verbatim.
		return g.scopes[required]
	}
}

// String returns the granted scopes, sorted, space-separated.
func (g *ScopeGrant) String() string {
	if g == nil {
		return ""
	}
	names := make([]string, 0, len(g.scopes))
	for s := range g.scopes {
		names = append(names, s)
	}
	sort.Strings(names)
	return strings.Join(names, " ")
}

// ScopeRequiredForTool returns the scope a tool call needs: read for a tool
// whose readOnlyHint annotation is explicitly true, write for every other tool
// (destructive, non-read-only, or unannotated: the policy fails closed).
func ScopeRequiredForTool(readOnlyHint *bool) string {
	if readOnlyHint != nil && *readOnlyHint {
		return ScopeRead
	}
	return ScopeWrite
}

// ScopeGrantFromContext returns the OAuth scope grant of the request's
// credential, or nil when the credential is not OAuth-scoped (or there is no
// auth context, as on stdio).
func ScopeGrantFromContext(ctx context.Context) *ScopeGrant {
	a, err := FromContext(ctx)
	if err != nil {
		return nil
	}
	return a.Scopes
}

// InsufficientScopeError reports a tool call refused because the request's
// OAuth access token does not grant the scope the tool needs. The HTTP
// transport turns it into the 403 insufficient_scope challenge the MCP
// authorization spec defines, so a client can step up and retry.
type InsufficientScopeError struct {
	Tool     string
	Required string
	Granted  string
}

func (e *InsufficientScopeError) Error() string {
	return fmt.Sprintf("insufficient_scope: tool %q requires the OAuth scope %q, but the access token only grants %q",
		e.Tool, e.Required, e.Granted)
}

// CheckScope returns an *InsufficientScopeError when the request's credential
// is OAuth-scoped and does not satisfy required, and nil otherwise.
func CheckScope(ctx context.Context, tool, required string) error {
	g := ScopeGrantFromContext(ctx)
	if g.Allows(required) {
		return nil
	}
	return &InsufficientScopeError{Tool: tool, Required: required, Granted: g.String()}
}
