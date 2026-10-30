package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScopeGrantAllows(t *testing.T) {
	tests := []struct {
		name                string
		scope               string
		read, write, admin  bool
		wantGrantedAsString string
	}{
		{"read", "limacharlie:read", true, false, false, "limacharlie:read"},
		{"write implies read", "limacharlie:write", true, true, false, "limacharlie:write"},
		{"admin implies write and read", "limacharlie:admin", true, true, true, "limacharlie:admin"},
		{"read and write", "limacharlie:write limacharlie:read", true, true, false, "limacharlie:read limacharlie:write"},
		{"empty scope is the server default", "", true, true, false, "limacharlie:read limacharlie:write"},
		{"blank scope is the server default", "   ", true, true, false, "limacharlie:read limacharlie:write"},
		{"unrecognized scopes grant nothing", "openid profile", false, false, false, "openid profile"},
		{"unrecognized next to read", "openid limacharlie:read", true, false, false, "limacharlie:read openid"},
		{"repeated whitespace", "limacharlie:read   limacharlie:write", true, true, false, "limacharlie:read limacharlie:write"},
		// Scope names are exact: a look-alike must not satisfy the policy.
		{"case matters", "LimaCharlie:Write", false, false, false, "LimaCharlie:Write"},
		{"prefix is not the scope", "limacharlie:writer limacharlie:readonly", false, false, false, "limacharlie:readonly limacharlie:writer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewScopeGrant(tc.scope)
			assert.Equal(t, tc.read, g.Allows(ScopeRead), "read")
			assert.Equal(t, tc.write, g.Allows(ScopeWrite), "write")
			assert.Equal(t, tc.admin, g.Allows(ScopeAdmin), "admin")
			assert.Equal(t, tc.wantGrantedAsString, g.String())
		})
	}
}

func TestScopeGrantEdgeCases(t *testing.T) {
	var none *ScopeGrant
	assert.True(t, none.Allows(ScopeAdmin), "a nil grant is not OAuth-scoped and restricts nothing")
	assert.Empty(t, none.String())

	assert.True(t, NewScopeGrant("openid").Allows(""), "an empty requirement is always met")

	// A scope this server does not define is satisfied only by itself, and admin
	// covers it too.
	assert.True(t, NewScopeGrant("custom:thing").Allows("custom:thing"))
	assert.False(t, NewScopeGrant("limacharlie:write").Allows("custom:thing"))
	assert.True(t, NewScopeGrant("limacharlie:admin").Allows("custom:thing"))
}

func TestScopeRequiredForTool(t *testing.T) {
	yes, no := true, false
	assert.Equal(t, ScopeRead, ScopeRequiredForTool(&yes))
	assert.Equal(t, ScopeWrite, ScopeRequiredForTool(&no))
	assert.Equal(t, ScopeWrite, ScopeRequiredForTool(nil), "unannotated tools fail closed")
}

func TestCheckScope(t *testing.T) {
	withGrant := func(scope string) context.Context {
		return WithAuthContext(context.Background(), &AuthContext{Mode: AuthModeUIDOAuth, UID: "u", Scopes: NewScopeGrant(scope)})
	}

	assert.NoError(t, CheckScope(withGrant("limacharlie:write"), "t", ScopeWrite))

	err := CheckScope(withGrant("limacharlie:read"), "delete_secret", ScopeWrite)
	var scopeErr *InsufficientScopeError
	require.True(t, errors.As(err, &scopeErr))
	assert.Equal(t, "delete_secret", scopeErr.Tool)
	assert.Equal(t, ScopeWrite, scopeErr.Required)
	assert.Equal(t, ScopeRead, scopeErr.Granted)
	assert.Contains(t, err.Error(), "insufficient_scope")
	assert.Contains(t, err.Error(), ScopeWrite)

	// Not OAuth-scoped: no grant, or no auth context at all (stdio).
	noGrant := WithAuthContext(context.Background(), &AuthContext{Mode: AuthModeUIDKey, UID: "u", APIKey: "k"})
	assert.NoError(t, CheckScope(noGrant, "delete_secret", ScopeWrite))
	assert.NoError(t, CheckScope(context.Background(), "delete_secret", ScopeWrite))
}

func TestScopeGrantSurvivesCloneAndOrgSwitch(t *testing.T) {
	grant := NewScopeGrant("limacharlie:read")
	orig := &AuthContext{Mode: AuthModeUIDOAuth, UID: "user", JWTToken: "jwt", Scopes: grant}

	assert.Same(t, grant, orig.Clone().Scopes, "Clone must carry the grant")

	// Passthrough-style org switch (no Firebase token): the new context keeps
	// the grant, or switching orgs would lift the scope limit.
	switched, err := WithOID(WithAuthContext(context.Background(), orig), "11111111-2222-3333-4444-555555555555", nil)
	require.NoError(t, err)
	got, err := FromContext(switched)
	require.NoError(t, err)
	assert.Same(t, grant, got.Scopes)
	assert.False(t, ScopeGrantFromContext(switched).Allows(ScopeWrite))
}
