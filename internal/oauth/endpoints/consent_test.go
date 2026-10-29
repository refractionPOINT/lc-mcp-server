package endpoints

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registerDCR registers a client through /register and returns its client_id
// and the name the server stored.
// pageHas and pageLacks assert on page text without dumping the whole page on failure.
func pageHas(t *testing.T, html, sub string, msg ...any) {
	t.Helper()
	assert.Truef(t, strings.Contains(html, sub), "page should contain %q %v", sub, msg)
}

func pageLacks(t *testing.T, html, sub string, msg ...any) {
	t.Helper()
	assert.Falsef(t, strings.Contains(html, sub), "page should not contain %q %v", sub, msg)
}

func registerDCR(t *testing.T, h *Handlers, name string, redirects ...string) (clientID, storedName string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"client_name": name, "redirect_uris": redirects})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	h.HandleRegister(w, httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(string(body))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp["client_id"].(string), resp["client_name"].(string)
}

// selectionPageOf starts /authorize for clientID (no provider) and renders the
// selection page, returning its HTML, the session id and the browser's cookies.
func selectionPageOf(t *testing.T, h *Handlers, clientID, redirect string) (html, session string, cookies []*http.Cookie) {
	t.Helper()
	q := authQuery(clientID, redirect, "client-state", victimVerifier)
	q.Del("provider")
	w := authorizeRequest(h, q)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/oauth/select-provider", loc.Path)
	session = loc.Query().Get("session")

	page := httptest.NewRecorder()
	h.HandleProviderSelection(page, httptest.NewRequest(http.MethodGet, "/oauth/select-provider?session="+session, nil), session)
	require.Equal(t, http.StatusOK, page.Code, page.Body.String())
	return page.Body.String(), session, page.Result().Cookies()
}

func TestRegister_ClientNameIsKeptPlain(t *testing.T) {
	h, sm, _, _ := testHandlers(t)

	t.Run("control and bidi characters are dropped, length is bounded", func(t *testing.T) {
		for name, in := range map[string]string{
			"bidi override":   "Trusted‮ App",
			"zero width":      "Trus​ted App",
			"control":         "Trusted\x00\x07\n\rApp",
			"line separator":  "Trusted App",
			"overlong":        strings.Repeat("A", 5000),
			"overlong runes":  strings.Repeat("日", 5000),
			"invalid utf8":    "Trusted\xff\xfeApp",
			"bidi isolate":    "⁦Trusted⁩ App",
			"padded":          "   Trusted App   ",
			"mixed with text": "Ok‮App‬",
		} {
			id, stored := registerDCR(t, h, in, "https://dcr.example.com/cb")
			assert.LessOrEqual(t, utf8.RuneCountInString(stored), 101, name)
			assert.True(t, utf8.ValidString(stored), name)
			for _, r := range stored {
				assert.False(t, r < 0x20 || r == 0x7f || (r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x2028 || r == 0x2029,
					"%s: %U must not survive", name, r)
			}
			reg, err := sm.GetClientRegistration(context.Background(), id)
			require.NoError(t, err)
			assert.Equal(t, stored, reg.ClientName, name+": what is stored is what is shown")
			assert.NotEmpty(t, stored, name)
		}
	})

	t.Run("an ordinary name is kept", func(t *testing.T) {
		_, stored := registerDCR(t, h, "My MCP Client – ünïcode 日本", "https://dcr.example.com/cb")
		assert.Equal(t, "My MCP Client – ünïcode 日本", stored)
	})

	t.Run("a name with nothing printable is refused", func(t *testing.T) {
		body := `{"client_name":"‮​","redirect_uris":["https://dcr.example.com/cb"]}`
		w := httptest.NewRecorder()
		h.HandleRegister(w, httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body)))
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestSelectionPage_DCRClientShowsNameAndRedirectHost(t *testing.T) {
	h, _, _, _ := testHandlers(t)
	id, _ := registerDCR(t, h, "Acme Notes", "https://notes.acme.example.org:8443/oauth/cb")
	html, _, _ := selectionPageOf(t, h, id, "https://notes.acme.example.org:8443/oauth/cb")

	pageHas(t, html, `id="client-info"`)
	pageHas(t, html, "Acme Notes")
	pageHas(t, html, "notes.acme.example.org:8443", "the redirect host, with its port")
	pageHas(t, html, "not verified", "a self-chosen name is labelled as such")
	pageLacks(t, html, `role="alert"`, "no localhost warning for a remote host")
}

func TestSelectionPage_DCRClientNameIsEscaped(t *testing.T) {
	h, _, _, _ := testHandlers(t)
	for _, name := range []string{
		`<script>alert(1)</script>`,
		`"><img src=x onerror=alert(1)>`,
		`</div><a href="https://evil.example.com">Click</a>`,
		`' onmouseover='alert(1)`,
	} {
		id, _ := registerDCR(t, h, name, "https://dcr.example.com/cb")
		html, _, _ := selectionPageOf(t, h, id, "https://dcr.example.com/cb")
		pageLacks(t, html, "<script>alert(1)</script>", name)
		pageLacks(t, html, "<img src=x", name)
		pageLacks(t, html, `<a href="https://evil.example.com">`, name)
		pageHas(t, html, `id="client-info"`)
	}

	// The text is still shown, as text.
	id, _ := registerDCR(t, h, `<b>Bold</b> & co`, "https://dcr.example.com/cb")
	html, _, _ := selectionPageOf(t, h, id, "https://dcr.example.com/cb")
	pageHas(t, html, "&lt;b&gt;Bold&lt;/b&gt; &amp; co")
}

func TestSelectionPage_LocalhostRedirectShowsTheWarning(t *testing.T) {
	h, _, _, _ := testHandlers(t)
	id, _ := registerDCR(t, h, "Local Tool", "http://localhost:3000/callback")
	html, _, _ := selectionPageOf(t, h, id, "http://localhost:3000/callback")
	pageHas(t, html, `role="alert"`)
	pageHas(t, html, "localhost:3000")

	// An allow-listed opaque client on loopback gets it too.
	html, _, _ = selectionPageOf(t, h, "first-party", "http://127.0.0.1:3000/callback")
	pageHas(t, html, `role="alert"`)
	pageHas(t, html, "127.0.0.1:3000")
}

func TestSelectionPage_OpaqueClientIDIsShownEscaped(t *testing.T) {
	h, _, _, _ := testHandlers(t)
	html, _, _ := selectionPageOf(t, h, `evil<b>client"id`, victimRedirect)
	pageHas(t, html, `id="client-info"`)
	pageLacks(t, html, "<b>client")
	pageHas(t, html, "evil&lt;b&gt;client")
	pageHas(t, html, "app.example.com")
}

// A registration written before names were sanitized can hold anything.
func TestSelectionPage_LegacyRegistrationNameIsSanitizedAtDisplay(t *testing.T) {
	h, sm, _, _ := testHandlers(t)
	reg := state.NewClientRegistration("mcp_legacy", "Trusted‮ Bank"+strings.Repeat("x", 500), []string{"https://legacy.example.com/cb"})
	require.NoError(t, sm.StoreClientRegistration(context.Background(), reg))
	html, _, _ := selectionPageOf(t, h, "mcp_legacy", "https://legacy.example.com/cb")
	pageLacks(t, html, "‮")
	pageLacks(t, html, strings.Repeat("x", 200), "overlong names are cut")
	pageHas(t, html, "Trusted Bank")

	// A name that is nothing but junk falls back to the client id.
	reg = state.NewClientRegistration("mcp_junk", "‮​", []string{"https://legacy.example.com/cb"})
	require.NoError(t, sm.StoreClientRegistration(context.Background(), reg))
	html, _, _ = selectionPageOf(t, h, "mcp_junk", "https://legacy.example.com/cb")
	pageHas(t, html, "mcp_junk")
	pageLacks(t, html, "‮")
}

func TestSelectionPage_LookalikeRedirectHostIsShownInPunycode(t *testing.T) {
	h, _, _, _ := testHandlers(t)
	const homograph = "https://аpple.example.com/cb" // Cyrillic "а"
	id, _ := registerDCR(t, h, "Apple Support", homograph)
	html, _, _ := selectionPageOf(t, h, id, homograph)
	pageHas(t, html, "xn--pple-43d.example.com")
	pageLacks(t, html, "аpple")
}

func TestSelectionPage_UnknownOrExpiredSessionShowsNoPage(t *testing.T) {
	h, _, _, _ := testHandlers(t)
	w := httptest.NewRecorder()
	h.HandleProviderSelection(w, httptest.NewRequest(http.MethodGet, "/oauth/select-provider?session=nope", nil), "nope")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NotContains(t, w.Body.String(), "Sign in to LimaCharlie")
}

func TestSelectionPage_RedirectURIDroppedFromTheRegistrationShowsNoPage(t *testing.T) {
	h, sm, _, _ := testHandlers(t)
	// A session whose redirect URI the client no longer vouches for.
	require.NoError(t, sm.CreateSelectionSession(context.Background(), "stale", map[string]string{
		"client_id": "some-client", "redirect_uri": "https://evil.example.com/cb", "state": "s",
	}))
	w := httptest.NewRecorder()
	h.HandleProviderSelection(w, httptest.NewRequest(http.MethodGet, "/oauth/select-provider?session=stale", nil), "stale")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSelection_PickingFromABrowserThatDidNotRenderThePageFails(t *testing.T) {
	for name, c := range map[string]struct{ client, redirect string }{
		"allow-listed client": {victimClient, victimRedirect},
		"dynamic client":      {"", "https://dcr.example.com/cb"},
	} {
		t.Run(name, func(t *testing.T) {
			h, _, mockFB, mr := testHandlers(t)
			created := false
			mockFB.createAuthURIFunc = func(ctx context.Context, provider, continueURI string, scopes []string) (string, string, error) {
				created = true
				return "s", "https://firebase.example.com/auth?state=fb", nil
			}
			clientID := c.client
			if clientID == "" {
				clientID, _ = registerDCR(t, h, "Dyn App", c.redirect)
			}

			// The attacker prepares a session and sends the victim its provider link.
			_, session, attackerCookies := selectionPageOf(t, h, clientID, c.redirect)

			// The victim's browser never rendered the page: no cookie, or somebody else's.
			for _, cookies := range [][]*http.Cookie{
				nil,
				{{Name: selectionBindCookie, Value: "attacker-chosen"}},
			} {
				_, session2, _ := selectionPageOf(t, h, clientID, c.redirect)
				req := httptest.NewRequest(http.MethodGet, "/oauth/select-provider/google?session="+session2, nil)
				for _, ck := range cookies {
					req.AddCookie(ck)
				}
				w := httptest.NewRecorder()
				h.CompleteProviderSelection(w, req, session2, "google")
				assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
				assert.Empty(t, w.Header().Get("Location"))
				assert.Empty(t, w.Result().Cookies(), "no acknowledgement is issued")

				// The session is gone: the link cannot be retried from the right browser either.
				req = httptest.NewRequest(http.MethodGet, "/oauth/select-provider/google?session="+session2, nil)
				w = httptest.NewRecorder()
				h.CompleteProviderSelection(w, req, session2, "google")
				assert.Equal(t, http.StatusBadRequest, w.Code)
			}
			assert.False(t, created)
			assert.Empty(t, storedTxs(t, h.stateManager, mr))

			// The browser that rendered the page can pick, and reaches the provider once.
			req := httptest.NewRequest(http.MethodGet, "/oauth/select-provider/google?session="+session, nil)
			for _, ck := range attackerCookies {
				req.AddCookie(ck)
			}
			w := httptest.NewRecorder()
			h.CompleteProviderSelection(w, req, session, "google")
			require.Equal(t, http.StatusFound, w.Code, w.Body.String())
			back, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err)
			assert.NotEmpty(t, back.Query().Get(selectionAckParam))
			w2 := authorizeRequest(h, back.Query(), w.Result().Cookies()...)
			assert.Contains(t, w2.Header().Get("Location"), "firebase.example.com")
			assert.True(t, created)
		})
	}
}

// Registering a client and sending the user straight to the provider, the
// shortcut that used to skip the page, now shows the page.
func TestAuthorize_DCRClientWithDirectProviderIsShownThePage(t *testing.T) {
	h, _, mockFB, mr := testHandlers(t)
	mockFB.createAuthURIFunc = func(ctx context.Context, provider, continueURI string, scopes []string) (string, string, error) {
		t.Error("the identity provider must not be reached without the selection page")
		return "s", "https://firebase.example.com/auth?state=fb", nil
	}
	id, _ := registerDCR(t, h, "Totally Legit Updater", "https://collector.example.net/cb")

	w := authorizeRequest(h, authQuery(id, "https://collector.example.net/cb", "s", victimVerifier))
	require.Equal(t, http.StatusFound, w.Code)
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "/oauth/select-provider", loc.Path)
	assert.Empty(t, storedTxs(t, h.stateManager, mr), "no transaction before the user has seen who is asking")

	page := httptest.NewRecorder()
	h.HandleProviderSelection(page, httptest.NewRequest(http.MethodGet, loc.RequestURI(), nil), loc.Query().Get("session"))
	assert.Contains(t, page.Body.String(), "Totally Legit Updater")
	assert.Contains(t, page.Body.String(), "collector.example.net")
}
