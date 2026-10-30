package http

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// delete_secret is the tool the original report invoked with a read-only token.
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/config"
)

// OAuth scope enforcement: an MCP access token reaches only the tools its
// granted scopes cover, directly and through lc_call_tool. Tokens here are real
// stored tokens (miniredis); only the LimaCharlie JWT exchange is stubbed.

const (
	scopeReadTool  = "zz_scope_read"  // readOnlyHint=true
	scopeWriteTool = "zz_scope_write" // destructiveHint=true
	scopePlainTool = "zz_scope_plain" // no annotations at all
)

const (
	scopeR = auth.ScopeRead
	scopeW = auth.ScopeWrite
	scopeA = auth.ScopeAdmin
)

// scopeFixture holds the tools and the counters of how often each one ran.
type scopeFixture struct {
	srv  *Server
	runs map[string]int
}

func newScopeFixture(t *testing.T) *scopeFixture {
	t.Helper()
	srv, _ := createOAuthTestServer(t)
	srv.profile = ""
	t.Cleanup(srv.sdkCache.Close)
	srv.tokenManager.WithJWTExchange(func(string, string, *slog.Logger) (string, error) { return "lc-jwt", nil })

	f := &scopeFixture{srv: srv, runs: map[string]int{}}
	reg := func(name string, opts ...mcp.ToolOption) {
		tools.RegisterTool(&tools.ToolRegistration{
			Name:        name,
			Description: "scope test tool " + name,
			Profile:     "core",
			Schema:      mcp.NewTool(name, append([]mcp.ToolOption{mcp.WithDescription("scope test tool " + name)}, opts...)...),
			Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
				f.runs[name]++
				return tools.SuccessResult(map[string]any{"ran": name}), nil
			},
		})
		t.Cleanup(func() { tools.UnregisterTool(name) })
	}
	reg(scopeReadTool, mcp.WithReadOnlyHintAnnotation(true))
	reg(scopeWriteTool, mcp.WithDestructiveHintAnnotation(true))
	reg(scopePlainTool)
	return f
}

// storeToken stores a live MCP access token with the given scope string.
func (f *scopeFixture) storeToken(t *testing.T, accessToken, scope string) {
	t.Helper()
	data := state.NewAccessTokenData(accessToken, "user-1", "fb-id", "fb-refresh",
		time.Now().Add(time.Hour).Unix(), scope, state.TokenTTL)
	require.NoError(t, f.srv.stateManager.StoreAccessToken(context.Background(), data))
}

// call invokes tool name with arguments in the given protocol era, optionally
// through lc_call_tool, presenting bearer as an OAuth access token.
func (f *scopeFixture) call(t *testing.T, modern bool, bearer, path, name string, arguments map[string]any) rpcResponse {
	t.Helper()
	if arguments == nil {
		arguments = map[string]any{}
	}
	var (
		body    map[string]any
		headers map[string]string
	)
	if modern {
		body, headers = modernRequest(1, "tools/call", map[string]any{"name": name, "arguments": arguments})
		delete(headers, "X-LC-OID")
		delete(headers, "X-LC-API-KEY")
	} else {
		body = map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": arguments}}
		headers = map[string]string{}
	}
	headers["Authorization"] = "Bearer " + bearer
	if path == "/mcp" {
		// The default endpoint serves the tools named here; the test tools are
		// not part of any profile.
		headers["X-MCP-Tools"] = name
	}
	return postJSON(t, f.srv, path, body, headers)
}

func (f *scopeFixture) viaDispatcher(t *testing.T, modern bool, bearer, target string) rpcResponse {
	return f.call(t, modern, bearer, "/mcp/api_access", "lc_call_tool", map[string]any{
		"tool_name": target, "parameters": map[string]any{},
	})
}

var challengeAttr = regexp.MustCompile(`(\w+)="([^"]*)"`)

// parseChallenge splits a Bearer challenge into its auth-params.
func parseChallenge(t *testing.T, header string) map[string]string {
	t.Helper()
	require.True(t, strings.HasPrefix(header, "Bearer "), header)
	attrs := map[string]string{}
	for _, m := range challengeAttr.FindAllStringSubmatch(header, -1) {
		attrs[m[1]] = m[2]
	}
	return attrs
}

// requireInsufficientScope asserts the exact 403 the MCP authorization spec
// (2026-07-28, "Runtime Insufficient Scope Errors") prescribes.
func requireInsufficientScope(t *testing.T, resp rpcResponse, path, wantScope string) {
	t.Helper()
	require.Equal(t, http.StatusForbidden, resp.Status, "%s", resp.Raw)
	header := resp.Header.Get("WWW-Authenticate")
	attrs := parseChallenge(t, header)
	assert.Equal(t, "insufficient_scope", attrs["error"], header)
	assert.Equal(t, wantScope, attrs["scope"], header)
	assert.Equal(t, audServer+"/.well-known/oauth-protected-resource"+path, attrs["resource_metadata"], header)
	assert.Contains(t, attrs["error_description"], wantScope, header)
	assert.Len(t, attrs, 4, "unexpected auth-params: %s", header)
	assert.Equal(t, float64(1), resp.Body["id"])
	assert.NotNil(t, resp.errorObj(t)["message"])
}

func TestInsufficientScopeChallengeExactShape(t *testing.T) {
	f := newScopeFixture(t)
	f.storeToken(t, "ro", scopeR)

	resp := f.call(t, false, "ro", "/mcp", scopeWriteTool, nil)

	require.Equal(t, http.StatusForbidden, resp.Status)
	assert.Equal(t, `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", `+
		`scope="limacharlie:write", error="insufficient_scope", `+
		`error_description="The access token does not grant the limacharlie:write scope required to call zz_scope_write"`,
		resp.Header.Get("WWW-Authenticate"))
	assert.Equal(t, 0, f.runs[scopeWriteTool])
}

// directExpectation is what a call to a tool of a given class should do.
type directExpectation struct {
	read, write, plain bool
}

var scopeMatrix = []struct {
	name  string
	scope string
	want  directExpectation
}{
	{"read only", scopeR, directExpectation{read: true}},
	{"write only implies read", scopeW, directExpectation{read: true, write: true, plain: true}},
	{"default read+write", scopeR + " " + scopeW, directExpectation{read: true, write: true, plain: true}},
	{"admin implies write and read", scopeA, directExpectation{read: true, write: true, plain: true}},
	{"read+admin", scopeR + " " + scopeA, directExpectation{read: true, write: true, plain: true}},
	{"no scope recorded means the server default (read+write)", "", directExpectation{read: true, write: true, plain: true}},
	{"unrecognized scope grants nothing", "profile email", directExpectation{}},
	{"unrecognized scope next to read grants only read", "profile " + scopeR, directExpectation{read: true}},
}

func TestDirectToolCallScopeEnforcement(t *testing.T) {
	targets := []struct {
		name     string
		allowed  func(directExpectation) bool
		required string
	}{
		{scopeReadTool, func(e directExpectation) bool { return e.read }, scopeR},
		{scopeWriteTool, func(e directExpectation) bool { return e.write }, scopeW},
		// Unannotated tools fail closed: they need write.
		{scopePlainTool, func(e directExpectation) bool { return e.plain }, scopeW},
	}
	for _, era := range []struct {
		name   string
		modern bool
	}{{"legacy", false}, {"modern", true}} {
		for _, tc := range scopeMatrix {
			for _, tool := range targets {
				t.Run(era.name+"/"+tc.name+"/"+tool.name, func(t *testing.T) {
					f := newScopeFixture(t)
					f.storeToken(t, "tok", tc.scope)

					resp := f.call(t, era.modern, "tok", "/mcp", tool.name, nil)

					if tool.allowed(tc.want) {
						require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
						assert.Empty(t, resp.Header.Get("WWW-Authenticate"))
						assert.Equal(t, 1, f.runs[tool.name], "tool must have run")
						return
					}
					requireInsufficientScope(t, resp, "/mcp", tool.required)
					assert.Equal(t, 0, f.runs[tool.name], "a refused call must not run the tool")
				})
			}
		}
	}
}

// The reproduction from the security report: a token granted only
// limacharlie:read invoked delete_secret.
func TestReadOnlyTokenCannotDeleteSecret(t *testing.T) {
	for _, modern := range []bool{false, true} {
		f := newScopeFixture(t)
		f.storeToken(t, "ro", scopeR)

		resp := f.call(t, modern, "ro", "/mcp", "delete_secret", map[string]any{"oid": testOID, "secret_name": "prod-db"})
		requireInsufficientScope(t, resp, "/mcp", scopeW)

		// And indirectly.
		resp = f.viaDispatcher(t, modern, "ro", "delete_secret")
		requireInsufficientScope(t, resp, "/mcp/api_access", scopeW)
	}
}

func TestDispatcherScopeIsDecidedByTheTargetTool(t *testing.T) {
	for _, era := range []struct {
		name   string
		modern bool
	}{{"legacy", false}, {"modern", true}} {
		for _, tc := range scopeMatrix {
			for _, target := range []struct {
				name     string
				allowed  func(directExpectation) bool
				required string
			}{
				{scopeReadTool, func(e directExpectation) bool { return e.read }, scopeR},
				{scopeWriteTool, func(e directExpectation) bool { return e.write }, scopeW},
				{scopePlainTool, func(e directExpectation) bool { return e.plain }, scopeW},
			} {
				t.Run(era.name+"/"+tc.name+"/"+target.name, func(t *testing.T) {
					f := newScopeFixture(t)
					f.storeToken(t, "tok", tc.scope)

					resp := f.viaDispatcher(t, era.modern, "tok", target.name)

					if target.allowed(tc.want) {
						require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
						assert.Equal(t, 1, f.runs[target.name])
						return
					}
					// A token that cannot even read cannot use the dispatcher
					// itself; otherwise the missing scope is the target's.
					wantPath := "/mcp/api_access"
					if !tc.want.read && !tc.want.write {
						requireInsufficientScope(t, resp, wantPath, scopeR)
					} else {
						requireInsufficientScope(t, resp, wantPath, target.required)
					}
					assert.Equal(t, 0, f.runs[target.name], "a refused call must not run the target")
				})
			}
		}
	}
}

func TestDispatcherRefusesOnTheTransportForUnreadableTokens(t *testing.T) {
	f := newScopeFixture(t)
	f.storeToken(t, "none", "profile")

	resp := f.viaDispatcher(t, true, "none", scopeReadTool)

	requireInsufficientScope(t, resp, "/mcp/api_access", scopeR)
	assert.Equal(t, 0, f.runs[scopeReadTool])
}

// Credentials that are not OAuth-scoped are never restricted by scope.
func TestNonOAuthCredentialsAreNotScopeRestricted(t *testing.T) {
	cases := map[string]func(f *scopeFixture, modern bool) map[string]string{
		"org API key": func(f *scopeFixture, _ bool) map[string]string {
			return map[string]string{"X-LC-OID": testOID, "X-LC-API-KEY": testAPIKey}
		},
		"user API key": func(f *scopeFixture, _ bool) map[string]string {
			return map[string]string{"X-LC-UID": testUID, "X-LC-API-KEY": testAPIKey}
		},
		"server-wide credentials": func(f *scopeFixture, _ bool) map[string]string {
			f.srv.serverAuthCtx = &auth.AuthContext{Mode: auth.AuthModeNormal, OID: testOID, APIKey: testAPIKey}
			return map[string]string{}
		},
		"LimaCharlie JWT": func(f *scopeFixture, _ bool) map[string]string {
			fakeLCJWTs(t, map[string]*auth.LCClaims{"header.payload.sig": {UID: testUID}})
			return map[string]string{"Authorization": "Bearer header.payload.sig"}
		},
	}
	for name, setup := range cases {
		for _, modern := range []bool{false, true} {
			t.Run(name, func(t *testing.T) {
				f := newScopeFixture(t)
				headers := setup(f, modern)
				for _, target := range []string{scopeReadTool, scopeWriteTool, scopePlainTool} {
					var body map[string]any
					if modern {
						var h map[string]string
						body, h = modernRequest(1, "tools/call", map[string]any{"name": target, "arguments": map[string]any{}})
						delete(h, "X-LC-OID")
						delete(h, "X-LC-API-KEY")
						for k, v := range headers {
							h[k] = v
						}
						h["X-MCP-Tools"] = target
						resp := postJSON(t, f.srv, "/mcp", body, h)
						require.Equal(t, http.StatusOK, resp.Status, "%s: %s", target, resp.Raw)
					} else {
						body = map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": target, "arguments": map[string]any{}}}
						h := map[string]string{"X-MCP-Tools": target}
						for k, v := range headers {
							h[k] = v
						}
						resp := postJSON(t, f.srv, "/mcp", body, h)
						require.Equal(t, http.StatusOK, resp.Status, "%s: %s", target, resp.Raw)
					}
					assert.Equal(t, 1, f.runs[target], target)
				}
				// And through the dispatcher.
				for _, target := range []string{scopeWriteTool, scopePlainTool} {
					before := f.runs[target]
					dispatch := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{
						"name": "lc_call_tool", "arguments": map[string]any{"tool_name": target, "parameters": map[string]any{}}}}
					resp := postJSON(t, f.srv, "/mcp/api_access", dispatch, headers)
					require.Equal(t, http.StatusOK, resp.Status, "%s: %s", target, resp.Raw)
					assert.Equal(t, before+1, f.runs[target], target)
				}
			})
		}
	}
}

// The grant survives an org switch: WithOID clones the auth context, and
// dropping the scopes there would lift the limit for every call that names an
// oid.
func TestScopeSurvivesOrgSwitchOnTheCallPath(t *testing.T) {
	f := newScopeFixture(t)
	f.storeToken(t, "ro", scopeR)
	const orgTool = "zz_scope_org_write"
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        orgTool,
		Description: "org scoped write",
		Profile:     "core",
		RequiresOID: true,
		Schema:      mcp.NewTool(orgTool, mcp.WithDescription("org scoped write")),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			f.runs[orgTool]++
			return tools.SuccessResult("ok"), nil
		},
	})
	t.Cleanup(func() { tools.UnregisterTool(orgTool) })

	resp := f.call(t, false, "ro", "/mcp", orgTool, map[string]any{"oid": testOID})
	requireInsufficientScope(t, resp, "/mcp", scopeW)
	assert.Equal(t, 0, f.runs[orgTool])

	resp = f.call(t, false, "ro", "/mcp/api_access", "lc_call_tool", map[string]any{
		"tool_name": orgTool, "parameters": map[string]any{"oid": testOID}})
	requireInsufficientScope(t, resp, "/mcp/api_access", scopeW)
	assert.Equal(t, 0, f.runs[orgTool])
}

// tools/list is not narrowed by scope (see listTools), and it still carries
// readOnlyHint so clients can see which tools a scope covers.
func TestToolsListIsNotNarrowedByScope(t *testing.T) {
	f := newScopeFixture(t)
	f.storeToken(t, "ro", scopeR)
	for _, modern := range []bool{false, true} {
		var body map[string]any
		var headers map[string]string
		if modern {
			body, headers = modernRequest(1, "tools/list", nil)
			delete(headers, "X-LC-OID")
			delete(headers, "X-LC-API-KEY")
		} else {
			body = map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
			headers = map[string]string{}
		}
		headers["Authorization"] = "Bearer ro"
		headers["X-MCP-Tools"] = scopeReadTool + "," + scopeWriteTool + "," + scopePlainTool
		resp := postJSON(t, f.srv, "/mcp", body, headers)
		require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
		assert.Equal(t, true, listedTool(t, resp, scopeReadTool)["annotations"].(map[string]any)["readOnlyHint"])
		assert.Equal(t, false, listedTool(t, resp, scopeWriteTool)["annotations"].(map[string]any)["readOnlyHint"])
		assert.Equal(t, false, listedTool(t, resp, scopePlainTool)["annotations"].(map[string]any)["readOnlyHint"])
	}
}
