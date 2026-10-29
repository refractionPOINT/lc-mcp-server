package endpoints

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Helpers that drive the authorization endpoints the way a browser does, using
// nothing but their HTTP interface.

// authorizeRequest runs one GET /authorize against h.
func authorizeRequest(h *Handlers, q url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.HandleAuthorize(w, req)
	return w
}

// completeSelection plays the browser on the selection page of a session: it
// loads the page, then picks provider from the same browser. It returns the
// response to the pick (a redirect back to /authorize, or an error).
func completeSelection(t *testing.T, h *Handlers, session, provider string) *httptest.ResponseRecorder {
	t.Helper()
	page := httptest.NewRecorder()
	h.HandleProviderSelection(page, httptest.NewRequest(http.MethodGet, "/oauth/select-provider?session="+session, nil), session)
	require.Equal(t, http.StatusOK, page.Code, page.Body.String())

	form := url.Values{"provider": {provider}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/select-provider?session="+session, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range page.Result().Cookies() {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.HandleProviderSelection(w, req, session)
	return w
}

// browserAuthorize is /authorize for a request that names a provider, the way a
// real browser gets there: the provider is not honoured on the first request, so
// the browser goes through the selection page and comes back to /authorize with
// the acknowledgement. It returns the final /authorize response (to the identity
// provider), or the first response when /authorize refused the request.
func browserAuthorize(t *testing.T, h *Handlers, q url.Values) *httptest.ResponseRecorder {
	t.Helper()
	provider := q.Get("provider")
	first := url.Values{}
	for k, v := range q {
		first[k] = v
	}
	first.Del("provider")
	w := authorizeRequest(h, first)
	loc, err := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusFound || err != nil || loc.Path != "/oauth/select-provider" {
		return w
	}
	picked := completeSelection(t, h, loc.Query().Get("session"), provider)
	if picked.Code != http.StatusFound {
		return picked
	}
	back, err := url.Parse(picked.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/authorize", back.Path)
	return authorizeRequest(h, back.Query(), picked.Result().Cookies()...)
}
