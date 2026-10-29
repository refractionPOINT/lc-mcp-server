package http

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const audServer = "https://mcp.example.com" // createOAuthTestServer's MCP_SERVER_URL

// audServerWithToken builds an OAuth test server holding one live token bound
// to resource ("" stores a legacy token). Validation and storage are real
// (miniredis); only the LimaCharlie JWT exchange is stubbed.
func audServerWithToken(t *testing.T, accessToken, resource string) *Server {
	t.Helper()
	s, _ := createOAuthTestServer(t)
	s.tokenManager.WithJWTExchange(func(string, string, *slog.Logger) (string, error) { return "lc-jwt", nil })
	data := state.NewAccessTokenData(accessToken, "user-1", "fb-id", "fb-refresh",
		time.Now().Add(time.Hour).Unix(), "openid", state.TokenTTL)
	data.Resource = resource
	require.NoError(t, s.stateManager.StoreAccessToken(context.Background(), data))
	return s
}

func audResolve(t *testing.T, s *Server, path, accessToken string) (*resolvedAuth, *authFailure) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	return s.resolveRequestAuth(req, "test")
}

var audAllPaths = []string{
	"/", "/mcp", "/mcp/v1", "/mcp/all", "/mcp/v1/all", "/mcp/api_access", "/mcp/v1/api_access",
}

func TestTokenAudienceCoversTheEndpointsItIsBoundTo(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		allowed  []string
	}{
		{
			name:     "mcp covers everything under /mcp and the root",
			resource: audServer + "/mcp",
			allowed:  audAllPaths,
		},
		{
			name:     "versioned alias of mcp is the same resource",
			resource: audServer + "/mcp/v1",
			allowed:  audAllPaths,
		},
		{
			name:     "the bare server origin covers everything",
			resource: audServer,
			allowed:  audAllPaths,
		},
		{
			name:     "legacy token without a resource covers everything",
			resource: "",
			allowed:  audAllPaths,
		},
		{
			name:     "a profile token works at the profile and its versioned alias only",
			resource: audServer + "/mcp/all",
			allowed:  []string{"/mcp/all", "/mcp/v1/all"},
		},
		{
			name:     "versioned alias of a profile is the same resource",
			resource: audServer + "/mcp/v1/api_access",
			allowed:  []string{"/mcp/api_access", "/mcp/v1/api_access"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := audServerWithToken(t, "tok", tc.resource)
			allowed := map[string]bool{}
			for _, p := range tc.allowed {
				allowed[p] = true
			}
			for _, path := range audAllPaths {
				resolved, failure := audResolve(t, s, path, "tok")
				if allowed[path] {
					require.Nil(t, failure, "%s at %s", tc.resource, path)
					require.NotNil(t, resolved)
					assert.Equal(t, auth.AuthModeUIDOAuth, resolved.authCtx.Mode)
					assert.Equal(t, "user-1", resolved.authCtx.UID)
					assert.Equal(t, "lc-jwt", resolved.authCtx.JWTToken)
					continue
				}
				require.NotNil(t, failure, "%q must be refused at %s", tc.resource, path)
				assert.True(t, failure.challenge, path)
				assert.Equal(t, "invalid_token", failure.oauthError, path)
				assert.Contains(t, failure.detail, "not issued for", path)
			}
		})
	}
}

func TestTokenAudienceMismatchIsAnInvalidTokenChallenge(t *testing.T) {
	s := audServerWithToken(t, "tok", audServer+"/mcp/all")
	live := func() map[string]string { return map[string]string{"Authorization": "Bearer tok"} }

	for _, path := range []string{"/mcp", "/mcp/v1", "/mcp/api_access", "/mcp/v1/api_access"} {
		t.Run(path, func(t *testing.T) {
			w := postMCP(t, s, path, "tools/call", live())

			assert.Equal(t, http.StatusUnauthorized, w.Code)
			challenge := w.Header().Get("WWW-Authenticate")
			// The challenge names the metadata of the endpoint being used, so
			// the client signs in again for that resource.
			assert.Contains(t, challenge, `resource_metadata="`+audServer+`/.well-known/oauth-protected-resource`+path+`"`)
			assert.Contains(t, challenge, `error="invalid_token"`)
			assert.Contains(t, challenge, `error_description="The access token was not issued for `+audServer+`/mcp`)
			assert.Contains(t, w.Body.String(), "not issued for")
		})
	}

	t.Run("the bound endpoint is not challenged", func(t *testing.T) {
		// Past authentication the JWT exchange is stubbed to fail, which is a
		// transient (not a 401) answer; anything but a 401 shows auth passed.
		s.tokenManager.WithJWTExchange(func(string, string, *slog.Logger) (string, error) {
			return "", assert.AnError
		})
		for _, path := range []string{"/mcp/all", "/mcp/v1/all"} {
			w := postMCP(t, s, path, "tools/call", live())
			assert.Equal(t, http.StatusOK, w.Code, path)
			assert.Empty(t, w.Header().Get("WWW-Authenticate"), path)
		}
	})
}

func TestTokenAudienceOnTheRootPath(t *testing.T) {
	// A client configured with the bare server URL talks to "/", which serves
	// /mcp: a token for /mcp (what the root's protected resource metadata
	// names) must work there, and a profile token must not.
	t.Run("mcp token", func(t *testing.T) {
		s := audServerWithToken(t, "tok", audServer+"/mcp")
		s.tokenManager.WithJWTExchange(func(string, string, *slog.Logger) (string, error) { return "", assert.AnError })
		w := postMCP(t, s, "/", "tools/call", map[string]string{"Authorization": "Bearer tok"})
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("WWW-Authenticate"))
	})
	t.Run("profile token", func(t *testing.T) {
		s := audServerWithToken(t, "tok", audServer+"/mcp/all")
		w := postMCP(t, s, "/", "tools/call", map[string]string{"Authorization": "Bearer tok"})
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
	})
}

func TestTokenAudienceOfAnotherServerIsRejected(t *testing.T) {
	// A token minted while MCP_SERVER_URL was another origin is not for this server.
	for _, resource := range []string{
		"https://old.example.com/mcp",
		"https://old.example.com",
		"http://mcp.example.com/mcp",
		"https://mcp.example.com:8443/mcp",
		"not a resource",
		audServer + "/mcp?x=1",
		audServer + "/other",
	} {
		t.Run(resource, func(t *testing.T) {
			s := audServerWithToken(t, "tok", resource)
			for _, path := range audAllPaths {
				_, failure := audResolve(t, s, path, "tok")
				require.NotNil(t, failure, path)
				assert.True(t, failure.challenge)
				assert.Equal(t, "invalid_token", failure.oauthError)
				assert.NotContains(t, failure.detail, "old.example.com", "the token's own resource is not echoed")
			}

			w := postMCP(t, s, "/mcp", "tools/call", map[string]string{"Authorization": "Bearer tok"})
			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Contains(t, w.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
		})
	}
}

func TestTokenAudienceMismatchDoesNotRefreshTheToken(t *testing.T) {
	s, _ := createOAuthTestServer(t)
	exchanged := false
	s.tokenManager.WithJWTExchange(func(string, string, *slog.Logger) (string, error) {
		exchanged = true
		return "lc-jwt", nil
	})
	// In its grace period: a valid request would revive the token.
	data := state.NewAccessTokenData("tok", "user-1", "fb-id", "fb-refresh", time.Now().Add(time.Hour).Unix(), "openid", state.TokenTTL)
	data.Resource = audServer + "/mcp/all"
	data.ExpiresAt = time.Now().Add(-time.Hour).Unix()
	require.NoError(t, s.stateManager.StoreAccessToken(context.Background(), data))

	_, failure := audResolve(t, s, "/mcp", "tok")
	require.NotNil(t, failure)
	assert.Equal(t, "invalid_token", failure.oauthError)
	assert.False(t, exchanged)

	stored, err := s.stateManager.GetAccessTokenData(context.Background(), "tok")
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Zero(t, stored.ExtensionCount)
}

func TestTokenAudienceUnknownTokenStaysGeneric(t *testing.T) {
	s := audServerWithToken(t, "tok", audServer+"/mcp/all")
	_, failure := audResolve(t, s, "/mcp", "other-token")
	require.NotNil(t, failure)
	assert.Equal(t, "The access token is invalid or expired", failure.detail)
}

func TestTokenAudienceIgnoredWithoutOAuth(t *testing.T) {
	// No OAuth: there is nothing to bind to, and tokens are not MCP tokens.
	s := createTestServer(t)
	_, failure := audResolve(t, s, "/mcp", "whatever")
	require.NotNil(t, failure)
	assert.Equal(t, "The access token is invalid or expired", failure.detail)
}
