package http

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A request that presents credential headers but not a complete set must be
// rejected. It must never fall back to the server-wide credentials: that would
// run it as the server's own identity, in the server's org.

const (
	serverOID    = "aaaaaaaa-1111-2222-3333-444444444444"
	serverAPIKey = "server-wide-api-key-for-tests"
	serverUID    = "bbbbbbbb-1111-2222-3333-444444444444"
)

var (
	serverOrgCreds = func() *auth.AuthContext {
		return &auth.AuthContext{Mode: auth.AuthModeNormal, OID: serverOID, APIKey: serverAPIKey}
	}
	serverUserCreds = func() *auth.AuthContext {
		return &auth.AuthContext{Mode: auth.AuthModeUIDKey, UID: serverUID, APIKey: serverAPIKey}
	}
)

const probeTool = "zz_hdr_probe"

// registerProbeTool registers a tool that records the org it ran against.
func registerProbeTool(t *testing.T) *[]string {
	t.Helper()
	ranAs := &[]string{}
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        probeTool,
		Description: "records the identity the call ran as",
		Profile:     "core",
		Schema:      mcp.NewTool(probeTool, mcp.WithDescription("records the identity"), mcp.WithReadOnlyHintAnnotation(true)),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			a, err := auth.FromContext(ctx)
			if err != nil {
				return nil, err
			}
			*ranAs = append(*ranAs, a.UID+"|"+a.OID+"|"+a.APIKey)
			return tools.SuccessResult("ok"), nil
		},
	})
	t.Cleanup(func() { tools.UnregisterTool(probeTool) })
	return ranAs
}

type headerSet map[string]string

func (h headerSet) names() string {
	var n []string
	for k := range h {
		n = append(n, k)
	}
	sort.Strings(n)
	return strings.Join(n, "+")
}

var incompleteSets = []headerSet{
	{"X-LC-API-KEY": testAPIKey},
	{"X-LC-UID": testUID},
	{"X-LC-OID": testOID},
	{"X-LC-UID": testUID, "X-LC-OID": testOID},
}

var completeSets = []struct {
	name     string
	headers  headerSet
	wantUID  string
	wantOID  string
	wantMode auth.AuthMode
}{
	{"user key", headerSet{"X-LC-UID": testUID, "X-LC-API-KEY": testAPIKey}, testUID, "", auth.AuthModeUIDKey},
	{"org key", headerSet{"X-LC-OID": testOID, "X-LC-API-KEY": testAPIKey}, "", testOID, auth.AuthModeNormal},
	{"user key with default org", headerSet{"X-LC-UID": testUID, "X-LC-OID": testOID, "X-LC-API-KEY": testAPIKey}, testUID, testOID, auth.AuthModeUIDKey},
}

func resolveWith(t *testing.T, s *Server, headers map[string]string) (*resolvedAuth, *authFailure) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "/mcp", nil)
	require.NoError(t, err)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return s.resolveRequestAuth(req, "test")
}

func TestIncompleteCredentialHeadersNeverFallBackToServerCredentials(t *testing.T) {
	for _, server := range []struct {
		name  string
		creds func() *auth.AuthContext
	}{
		{"server org credentials", serverOrgCreds},
		{"server user credentials", serverUserCreds},
		{"no server credentials", func() *auth.AuthContext { return nil }},
	} {
		for _, set := range incompleteSets {
			t.Run(server.name+"/"+set.names(), func(t *testing.T) {
				s := newProtocolTestServer(t)
				s.serverAuthCtx = server.creds()

				resolved, failure := resolveWith(t, s, set)

				require.NotNil(t, failure, "an incomplete header set must be rejected")
				assert.Nil(t, resolved)
				assert.True(t, failure.challenge, "answered with the 401 challenge, like missing credentials")
				assert.Empty(t, failure.oauthError)
				assert.Contains(t, failure.detail, "Incomplete credentials")
				for h := range set {
					assert.Contains(t, failure.detail, h)
				}
			})
		}
	}
}

func TestIncompleteCredentialHeadersOverHTTPNeverRunAsTheServer(t *testing.T) {
	for _, modern := range []bool{false, true} {
		for _, set := range incompleteSets {
			name := set.names()
			if modern {
				name = "modern/" + name
			} else {
				name = "legacy/" + name
			}
			t.Run(name, func(t *testing.T) {
				s := newProtocolTestServer(t)
				ran := registerProbeTool(t)
				s.serverAuthCtx = serverOrgCreds()

				headers := map[string]string{"X-MCP-Tools": probeTool}
				var body map[string]any
				if modern {
					var h map[string]string
					body, h = modernRequest(1, "tools/call", map[string]any{"name": probeTool, "arguments": map[string]any{}})
					delete(h, "X-LC-OID")
					delete(h, "X-LC-API-KEY")
					for k, v := range h {
						headers[k] = v
					}
				} else {
					body = map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": probeTool, "arguments": map[string]any{}}}
				}
				for k, v := range set {
					headers[k] = v
				}
				resp := postJSON(t, s, "/mcp", body, headers)

				require.Equal(t, http.StatusUnauthorized, resp.Status, "%s", resp.Raw)
				assert.NotEmpty(t, resp.Header.Get("WWW-Authenticate"))
				assert.Empty(t, *ran, "the tool must not run as the server")
			})
		}
	}
}

func TestIncompleteCredentialHeadersChallengeOAuthClients(t *testing.T) {
	s, _ := createOAuthTestServer(t)
	s.serverAuthCtx = serverOrgCreds()

	resp := postMCP(t, s, "/mcp", "tools/call", map[string]string{"X-LC-API-KEY": testAPIKey})

	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Contains(t, resp.Header().Get("WWW-Authenticate"), `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"`)
}

func TestSessionOpeningGatesAgreeWithTheNewRule(t *testing.T) {
	// initialize and server/discover need a credential; a partial header set is
	// not one, even when the server has credentials of its own.
	for _, set := range incompleteSets {
		t.Run(set.names(), func(t *testing.T) {
			s, _ := createOAuthTestServer(t)
			s.serverAuthCtx = serverOrgCreds()

			req, err := http.NewRequest(http.MethodPost, "/mcp", nil)
			require.NoError(t, err)
			for k, v := range set {
				req.Header.Set(k, v)
			}
			assert.False(t, s.requestHasCredentials(req))

			// Over the wire, legacy initialize and modern discover are refused.
			init := postMCP(t, s, "/mcp", "initialize", set)
			assert.Equal(t, http.StatusUnauthorized, init.Code)

			body, headers := modernRequest(1, "server/discover", nil)
			delete(headers, "X-LC-OID")
			delete(headers, "X-LC-API-KEY")
			for k, v := range set {
				headers[k] = v
			}
			resp := postJSON(t, s, "/mcp", body, headers)
			assert.Equal(t, http.StatusUnauthorized, resp.Status)
		})
	}

	t.Run("no credential headers still use the server credentials", func(t *testing.T) {
		s, _ := createOAuthTestServer(t)
		s.serverAuthCtx = serverOrgCreds()
		req, err := http.NewRequest(http.MethodPost, "/mcp", nil)
		require.NoError(t, err)
		assert.True(t, s.requestHasCredentials(req))
		assert.Equal(t, http.StatusOK, postMCP(t, s, "/mcp", "initialize", nil).Code)
	})

	t.Run("complete sets and a Bearer token count as credentials", func(t *testing.T) {
		s, _ := createOAuthTestServer(t)
		s.serverAuthCtx = serverOrgCreds()
		for _, tc := range completeSets {
			req, err := http.NewRequest(http.MethodPost, "/mcp", nil)
			require.NoError(t, err)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			assert.True(t, s.requestHasCredentials(req), tc.name)
		}
		req, err := http.NewRequest(http.MethodPost, "/mcp", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer x")
		req.Header.Set("X-LC-OID", testOID)
		assert.True(t, s.requestHasCredentials(req), "Bearer + X-LC-OID")
	})
}

func TestCompleteCredentialHeadersRunAsThemselves(t *testing.T) {
	for _, server := range []struct {
		name  string
		creds func() *auth.AuthContext
	}{
		{"server credentials configured", serverOrgCreds},
		{"no server credentials", func() *auth.AuthContext { return nil }},
	} {
		for _, tc := range completeSets {
			for _, modern := range []bool{false, true} {
				era := "legacy"
				if modern {
					era = "modern"
				}
				t.Run(server.name+"/"+tc.name+"/"+era, func(t *testing.T) {
					s := newProtocolTestServer(t)
					ran := registerProbeTool(t)
					s.serverAuthCtx = server.creds()

					resolved, failure := resolveWith(t, s, tc.headers)
					require.Nil(t, failure)
					assert.Equal(t, tc.wantMode, resolved.authCtx.Mode)
					assert.Equal(t, tc.wantUID, resolved.authCtx.UID)
					assert.Equal(t, tc.wantOID, resolved.authCtx.OID)
					assert.Equal(t, testAPIKey, resolved.authCtx.APIKey)

					headers := map[string]string{"X-MCP-Tools": probeTool}
					var body map[string]any
					if modern {
						var h map[string]string
						body, h = modernRequest(1, "tools/call", map[string]any{"name": probeTool, "arguments": map[string]any{}})
						delete(h, "X-LC-OID")
						delete(h, "X-LC-API-KEY")
						for k, v := range h {
							headers[k] = v
						}
					} else {
						body = map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": probeTool, "arguments": map[string]any{}}}
					}
					for k, v := range tc.headers {
						headers[k] = v
					}
					resp := postJSON(t, s, "/mcp", body, headers)
					require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
					require.Len(t, *ran, 1)
					assert.Equal(t, tc.wantUID+"|"+tc.wantOID+"|"+testAPIKey, (*ran)[0], "ran as the request's identity, not the server's")
				})
			}
		}
	}
}

func TestBearerWithOIDHeaderStillPinsOrgJWT(t *testing.T) {
	// Authorization + X-LC-OID is a complete credential (org JWT pinning), not
	// an incomplete header set.
	const orgJWT = "hdr.org-token.sig"
	fakeLCJWTs(t, map[string]*auth.LCClaims{orgJWT: {OIDs: []string{testOID}}})
	s := newProtocolTestServer(t)
	s.serverAuthCtx = serverOrgCreds()

	resolved, failure := resolveWith(t, s, map[string]string{"Authorization": "Bearer " + orgJWT, "X-LC-OID": testOID})

	require.Nil(t, failure)
	assert.Equal(t, auth.AuthModeNormal, resolved.authCtx.Mode)
	assert.Equal(t, testOID, resolved.authCtx.OID)
	assert.Equal(t, orgJWT, resolved.authCtx.JWTToken)
	assert.Nil(t, resolved.authCtx.Scopes, "a LimaCharlie JWT is not OAuth-scoped")
}

func TestNoCredentialHeadersUseServerCredentialsOnlyWhenConfigured(t *testing.T) {
	s := newProtocolTestServer(t)

	_, failure := resolveWith(t, s, nil)
	require.NotNil(t, failure, "no credentials and no server credentials")
	assert.True(t, failure.challenge)
	assert.Contains(t, failure.detail, "Missing authentication")

	s.serverAuthCtx = serverOrgCreds()
	resolved, failure := resolveWith(t, s, nil)
	require.Nil(t, failure)
	assert.Equal(t, serverOID, resolved.authCtx.OID)
	assert.Equal(t, serverAPIKey, resolved.authCtx.APIKey)
}

func TestToolsListStaysOpenWithIncompleteHeaders(t *testing.T) {
	// Listing never rejects a caller. With a partial header set the credential
	// does not resolve, so a modern listing keeps the oid parameter (it cannot
	// claim the call would be pinned to the server's org, because it would not).
	s := newProtocolTestServer(t)
	registerOrgScopedTool(t)
	s.serverAuthCtx = serverOrgCreds()

	body, headers := modernRequest(1, "tools/list", nil)
	delete(headers, "X-LC-OID")
	delete(headers, "X-LC-API-KEY")
	headers["X-LC-API-KEY"] = testAPIKey
	headers["X-MCP-Tools"] = protoOrgTool
	resp := postJSON(t, s, "/mcp", body, headers)
	require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
	schema := listedTool(t, resp, protoOrgTool)["inputSchema"].(map[string]any)
	assert.Contains(t, schema["properties"], "oid")

	// Without any credential header the server's pinned org applies, as before.
	body, headers = modernRequest(2, "tools/list", nil)
	delete(headers, "X-LC-OID")
	delete(headers, "X-LC-API-KEY")
	headers["X-MCP-Tools"] = protoOrgTool
	resp = postJSON(t, s, "/mcp", body, headers)
	require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
	schema = listedTool(t, resp, protoOrgTool)["inputSchema"].(map[string]any)
	assert.NotContains(t, schema["properties"], "oid")
}

// A credential header that is present with an empty value is judged by being
// sent, not by its value: it is a request aimed at some identity that did not
// name it, so it never runs as the server.
var emptyCredentialSets = []headerSet{
	{"Authorization": ""},
	{"X-LC-UID": ""},
	{"X-LC-OID": ""},
	{"X-LC-API-KEY": ""},
	{"X-LC-UID": "", "X-LC-OID": "", "X-LC-API-KEY": ""},
	{"X-LC-UID": testUID, "X-LC-API-KEY": ""},
	{"X-LC-OID": testOID, "X-LC-API-KEY": ""},
	{"X-LC-UID": "", "X-LC-API-KEY": testAPIKey},
	{"X-LC-OID": "", "X-LC-API-KEY": testAPIKey},
	{"Authorization": "", "X-LC-OID": testOID},
	{"Authorization": "", "X-LC-UID": testUID},
}

func TestEmptyCredentialHeadersNeverFallBackToServerCredentials(t *testing.T) {
	for _, server := range []struct {
		name  string
		creds func() *auth.AuthContext
	}{
		{"server org credentials", serverOrgCreds},
		{"server user credentials", serverUserCreds},
		{"no server credentials", func() *auth.AuthContext { return nil }},
	} {
		for _, set := range emptyCredentialSets {
			t.Run(server.name+"/"+set.names()+"/"+set.values(), func(t *testing.T) {
				s := newProtocolTestServer(t)
				s.serverAuthCtx = server.creds()

				resolved, failure := resolveWith(t, s, set)
				require.NotNil(t, failure, "a present-but-empty credential header must be rejected")
				assert.Nil(t, resolved)
				assert.True(t, failure.challenge, "answered with the 401 challenge")

				req, err := http.NewRequest(http.MethodPost, "/mcp", nil)
				require.NoError(t, err)
				for k, v := range set {
					req.Header.Set(k, v)
				}
				assert.False(t, s.requestHasCredentials(req), "the session-opening gate agrees")
			})
		}
	}
}

func (h headerSet) values() string {
	var n []string
	for _, k := range strings.Split(h.names(), "+") {
		if h[k] == "" {
			n = append(n, k+"=empty")
		}
	}
	return strings.Join(n, ",")
}

func TestEmptyCredentialHeadersOverHTTPNeverRunAsTheServer(t *testing.T) {
	for _, modern := range []bool{false, true} {
		for _, set := range emptyCredentialSets {
			name := "legacy/"
			if modern {
				name = "modern/"
			}
			t.Run(name+set.names()+"/"+set.values(), func(t *testing.T) {
				s := newProtocolTestServer(t)
				ran := registerProbeTool(t)
				s.serverAuthCtx = serverOrgCreds()

				headers := map[string]string{"X-MCP-Tools": probeTool}
				var body map[string]any
				if modern {
					var h map[string]string
					body, h = modernRequest(1, "tools/call", map[string]any{"name": probeTool, "arguments": map[string]any{}})
					delete(h, "X-LC-OID")
					delete(h, "X-LC-API-KEY")
					for k, v := range h {
						headers[k] = v
					}
				} else {
					body = map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": probeTool, "arguments": map[string]any{}}}
				}
				for k, v := range set {
					headers[k] = v
				}
				resp := postJSON(t, s, "/mcp", body, headers)

				require.Equal(t, http.StatusUnauthorized, resp.Status, "%s", resp.Raw)
				assert.NotEmpty(t, resp.Header.Get("WWW-Authenticate"))
				assert.Empty(t, *ran, "the tool must not run as the server")
			})
		}
	}
}

func TestEmptyCredentialHeadersRefuseSessionOpening(t *testing.T) {
	for _, set := range emptyCredentialSets {
		t.Run(set.names()+"/"+set.values(), func(t *testing.T) {
			s, _ := createOAuthTestServer(t)
			s.serverAuthCtx = serverOrgCreds()

			init := postMCP(t, s, "/mcp", "initialize", set)
			assert.Equal(t, http.StatusUnauthorized, init.Code)

			body, headers := modernRequest(1, "server/discover", nil)
			delete(headers, "X-LC-OID")
			delete(headers, "X-LC-API-KEY")
			for k, v := range set {
				headers[k] = v
			}
			resp := postJSON(t, s, "/mcp", body, headers)
			assert.Equal(t, http.StatusUnauthorized, resp.Status)
		})
	}
}

// tools/list never rejects a caller; an empty credential header does not
// resolve, so the modern listing keeps the oid parameter rather than claiming
// the server's pinned org.
func TestToolsListStaysOpenWithEmptyCredentialHeaders(t *testing.T) {
	for _, header := range []string{"Authorization", "X-LC-UID", "X-LC-OID", "X-LC-API-KEY"} {
		t.Run(header, func(t *testing.T) {
			s := newProtocolTestServer(t)
			registerOrgScopedTool(t)
			s.serverAuthCtx = serverOrgCreds()

			body, headers := modernRequest(1, "tools/list", nil)
			delete(headers, "X-LC-OID")
			delete(headers, "X-LC-API-KEY")
			headers[header] = ""
			headers["X-MCP-Tools"] = protoOrgTool
			resp := postJSON(t, s, "/mcp", body, headers)
			require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
			schema := listedTool(t, resp, protoOrgTool)["inputSchema"].(map[string]any)
			assert.Contains(t, schema["properties"], "oid")

			// Legacy era: the listing is the one the server always had.
			legacy := postMCP(t, s, "/mcp", "tools/list", map[string]string{header: "", "X-MCP-Tools": protoOrgTool})
			assert.Equal(t, http.StatusOK, legacy.Code)
		})
	}
}

func TestEmptyAuthorizationDoesNotMaskACompleteHeaderSet(t *testing.T) {
	// A complete, non-empty header set is a credential of its own: an extra
	// empty Authorization neither falls back to the server nor blocks it.
	s := newProtocolTestServer(t)
	s.serverAuthCtx = serverOrgCreds()
	resolved, failure := resolveWith(t, s, map[string]string{"Authorization": "", "X-LC-OID": testOID, "X-LC-API-KEY": testAPIKey})
	require.Nil(t, failure)
	assert.Equal(t, testOID, resolved.authCtx.OID)
	assert.Equal(t, testAPIKey, resolved.authCtx.APIKey)
}
