package http

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/crypto"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/metadata"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/token"
	"github.com/refractionpoint/lc-mcp-go/internal/redis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createOAuthTestServer builds a test server with OAuth token validation
// backed by miniredis, so token lookups run the real validation path.
func createOAuthTestServer(t *testing.T) (*Server, *miniredis.Miniredis) {
	t.Helper()

	t.Setenv("MCP_SERVER_URL", "https://mcp.example.com")
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	t.Setenv("REDIS_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(key))

	logger := slog.Default()
	mr := miniredis.RunT(t)
	redisClient, err := redis.New(&redis.Config{URL: "redis://" + mr.Addr()}, logger)
	require.NoError(t, err)
	encryption, err := crypto.NewTokenEncryption(logger)
	require.NoError(t, err)

	s := createTestServer(t)
	s.stateManager = state.NewManager(redisClient, encryption, logger)
	s.tokenManager = token.NewManager(s.stateManager, nil, logger)
	s.metadataProvider = metadata.NewProvider(logger)
	return s, mr
}

func postMCP(t *testing.T, s *Server, path string, method string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params": map[string]interface{}{
			"name":      "list_sensors",
			"arguments": map[string]interface{}{},
		},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	return w
}

func TestInitializeRequiresCredentials(t *testing.T) {
	s, _ := createOAuthTestServer(t)

	for _, path := range []string{"/mcp", "/mcp/all", "/mcp/v1"} {
		t.Run("no credentials on "+path, func(t *testing.T) {
			w := postMCP(t, s, path, "initialize", nil)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Equal(t,
				`Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`,
				w.Header().Get("WWW-Authenticate"))

			var resp map[string]interface{}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Nil(t, resp["result"])
			assert.Equal(t, "Unauthorized", resp["error"].(map[string]interface{})["message"])
		})
	}

	t.Run("bearer token", func(t *testing.T) {
		w := postMCP(t, s, "/mcp", "initialize", map[string]string{"Authorization": "Bearer some-token"})
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("WWW-Authenticate"))
	})

	t.Run("user API key headers", func(t *testing.T) {
		w := postMCP(t, s, "/mcp", "initialize", map[string]string{"X-LC-UID": "user@example.com", "X-LC-API-KEY": "key"})
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("org API key headers", func(t *testing.T) {
		w := postMCP(t, s, "/mcp", "initialize", map[string]string{"X-LC-OID": "oid", "X-LC-API-KEY": "key"})
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("API key without an identity is not a credential", func(t *testing.T) {
		w := postMCP(t, s, "/mcp", "initialize", map[string]string{"X-LC-API-KEY": "key"})
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestInitializeWithServerCredentials(t *testing.T) {
	s := createTestServer(t)
	s.serverAuthCtx = &auth.AuthContext{
		Mode:   auth.AuthModeNormal,
		OID:    "11111111-2222-3333-4444-555555555555",
		APIKey: "key",
	}

	w := postMCP(t, s, "/mcp", "initialize", nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestToolsListAndPingStayPublic(t *testing.T) {
	s, _ := createOAuthTestServer(t)

	w := postMCP(t, s, "/mcp", "tools/list", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp["result"].(map[string]interface{})["tools"])

	w = postMCP(t, s, "/mcp", "ping", nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestToolCallTokenErrors(t *testing.T) {
	t.Run("unknown token is challenged", func(t *testing.T) {
		s, _ := createOAuthTestServer(t)

		w := postMCP(t, s, "/mcp", "tools/call", map[string]string{"Authorization": "Bearer not-a-real-token"})

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t,
			`Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", error="invalid_token", error_description="The access token is invalid or expired"`,
			w.Header().Get("WWW-Authenticate"))
	})

	t.Run("backend failure is not a 401", func(t *testing.T) {
		s, mr := createOAuthTestServer(t)
		// With Redis down the token cannot be checked. That is not proof the
		// token is bad, so the client must not be sent back to sign in.
		mr.Close()

		w := postMCP(t, s, "/mcp", "tools/call", map[string]string{"Authorization": "Bearer not-a-real-token"})

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("WWW-Authenticate"))
		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "Unauthorized", resp["error"].(map[string]interface{})["message"])
	})

	t.Run("live token whose JWT exchange fails is not a 401", func(t *testing.T) {
		s, _ := createOAuthTestServer(t)
		s.tokenManager.WithJWTExchange(func(string, string, *slog.Logger) (string, error) {
			return "", errors.New("jwt service unavailable")
		})
		tokenData := state.NewAccessTokenData("live-token", "user", "fb-id", "fb-refresh",
			time.Now().Add(time.Hour).Unix(), "openid", state.TokenTTL)
		require.NoError(t, s.stateManager.StoreAccessToken(context.Background(), tokenData))

		w := postMCP(t, s, "/mcp", "tools/call", map[string]string{"Authorization": "Bearer live-token"})

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("WWW-Authenticate"))
	})

	t.Run("no OAuth configured and not a LimaCharlie JWT", func(t *testing.T) {
		s := createTestServer(t)

		w := postMCP(t, s, "/mcp", "tools/call", map[string]string{"Authorization": "Bearer not-a-real-token"})

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t,
			`Bearer realm="limacharlie-mcp", error="invalid_token", error_description="The access token is invalid or expired"`,
			w.Header().Get("WWW-Authenticate"))
	})
}
