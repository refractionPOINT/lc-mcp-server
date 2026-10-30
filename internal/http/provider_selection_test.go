package http

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/endpoints"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The selection page's provider links are plain GETs to
// /oauth/select-provider/<provider>. For CIMD clients they must only work when
// the browser that saw the page makes the request itself.
func TestProviderSelectionRoute_CIMDClientNeedsSameOriginClick(t *testing.T) {
	s, _ := createOAuthTestServer(t)
	t.Chdir("../..") // templates are loaded relative to the repo root
	handlers, err := endpoints.NewHandlers(s.stateManager, s.tokenManager, nil, s.metadataProvider, slog.Default(), []string{"http://localhost/callback"})
	require.NoError(t, err)
	s.oauthHandlers = handlers

	const secret = "browser-binding-secret"
	// The browser's binding secret, as the selection page issues it (43 chars).
	const browserSecret = "bBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBb"
	sum := sha256.Sum256([]byte(secret))
	newSession := func(id string) {
		require.NoError(t, s.stateManager.CreateSelectionSession(context.Background(), id, map[string]string{
			"client_id":       "https://client.example.com/oauth/client.json",
			"redirect_uri":    "https://client.example.com/callback",
			"state":           "s",
			"code_challenge":  "c",
			"_selection_view": hex.EncodeToString(sum[:]),
		}))
	}
	click := func(session, provider, site string, withCookie bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/oauth/select-provider/"+provider+"?session="+session, nil)
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		if withCookie {
			// The server URL is https, so the cookies carry the __Host- prefix.
			req.AddCookie(&http.Cookie{Name: "__Host-lc_oauth_selection_view", Value: secret})
			req.AddCookie(&http.Cookie{Name: "__Host-lc_oauth_browser", Value: browserSecret})
		}
		w := httptest.NewRecorder()
		s.mux.ServeHTTP(w, req)
		return w
	}

	// the user's click on the page
	newSession("click")
	w := click("click", "google", "same-origin", true)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	assert.Contains(t, w.Header().Get("Location"), "/authorize?")
	var ack *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-lc_oauth_selection" {
			ack = c
		}
	}
	require.NotNil(t, ack)
	assert.Equal(t, http.SameSiteStrictMode, ack.SameSite)
	assert.Equal(t, "/", ack.Path)

	// a cross-site page navigating the popup that showed the page, cookie and all
	for _, site := range []string{"cross-site", "same-site", "none"} {
		newSession("attack-" + site)
		w = click("attack-"+site, "microsoft", site, true)
		assert.Equal(t, http.StatusBadRequest, w.Code, site)
		assert.Empty(t, w.Header().Get("Location"), site)
	}

	// no cookie (Strict cookies are not sent on cross-site navigations)
	newSession("nocookie")
	w = click("nocookie", "google", "", false)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
