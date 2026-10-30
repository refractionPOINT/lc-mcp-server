package endpoints

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The whole browser leg of a sign-in, through a real cookie jar that applies
// cookie Path, Secure and __Host- rules the way a browser does: authorize →
// selection page → provider choice → authorize → provider → callback. Hand-made
// cookie plumbing in other tests can't catch a cookie the browser wouldn't send.
func TestSignIn_ThroughARealCookieJar(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		name := "http"
		if useTLS {
			name = "https"
		}
		t.Run(name, func(t *testing.T) {
			var mux http.Handler
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mux.ServeHTTP(w, r) }))
			if useTLS {
				srv.StartTLS()
			} else {
				srv.Start()
			}
			t.Cleanup(srv.Close)

			h, _, mockFB, _ := testHandlers(t)
			os.Setenv("MCP_SERVER_URL", srv.URL)
			h.metadataProvider = metadata.NewProvider(testLogger())
			realisticFirebase(mockFB)

			m := http.NewServeMux()
			m.HandleFunc("/authorize", h.HandleAuthorize)
			m.HandleFunc("/oauth/select-provider", func(w http.ResponseWriter, r *http.Request) {
				session := r.URL.Query().Get("session")
				if session == "" {
					session = r.FormValue("session")
				}
				h.HandleProviderSelection(w, r, session)
			})
			m.HandleFunc("/oauth/select-provider/google", func(w http.ResponseWriter, r *http.Request) {
				h.CompleteProviderSelection(w, r, r.URL.Query().Get("session"), "google")
			})
			m.HandleFunc("/oauth/callback", h.HandleCallback)
			mux = m

			jar, err := cookiejar.New(nil)
			require.NoError(t, err)
			client := srv.Client()
			client.Jar = jar
			// Stop at anything that leaves this server (the provider, the client).
			srvURL, _ := url.Parse(srv.URL)
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				if req.URL.Host != srvURL.Host {
					return http.ErrUseLastResponse
				}
				return nil
			}

			// 1. The client opens /authorize; the browser lands on the selection page.
			resp, err := client.Get(srv.URL + "/authorize?" + authQuery("some-client", "https://app.example.com/callback", "client-state", "verifier-verifier-verifier-verifier-verifier").Encode())
			require.NoError(t, err)
			resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, "/oauth/select-provider", resp.Request.URL.Path)
			session := resp.Request.URL.Query().Get("session")
			require.NotEmpty(t, session)

			// 2. The user clicks Google on that page; the browser goes back to
			// /authorize with the acknowledgement and on to the provider.
			req, _ := http.NewRequest(http.MethodGet, srv.URL+"/oauth/select-provider/google?session="+url.QueryEscape(session), nil)
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			resp, err = client.Do(req)
			require.NoError(t, err)
			resp.Body.Close()
			require.Equal(t, http.StatusFound, resp.StatusCode, "must reach the provider, not loop back to the selection page")
			loc, _ := url.Parse(resp.Header.Get("Location"))
			require.Equal(t, "firebase.example.com", loc.Host)

			// 3. The provider sends the browser back to the callback.
			req, _ = http.NewRequest(http.MethodGet, srv.URL+"/oauth/callback?state="+url.QueryEscape(loc.Query().Get("state"))+"&code=provider-code", nil)
			req.Header.Set("Sec-Fetch-Site", "cross-site")
			resp, err = client.Do(req)
			require.NoError(t, err)
			resp.Body.Close()
			require.Equal(t, http.StatusFound, resp.StatusCode)
			back, _ := url.Parse(resp.Header.Get("Location"))
			assert.Equal(t, "app.example.com", back.Host)
			assert.NotEmpty(t, back.Query().Get("code"), "the client gets its authorization code")
			assert.Equal(t, "client-state", back.Query().Get("state"))
		})
	}
}
