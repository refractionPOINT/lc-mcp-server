package endpoints

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func postRegister(h *Handlers, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleRegister(w, req)
	return w
}

func TestHandleRegister_BoundsWhatItStores(t *testing.T) {
	h, _, _, _ := testHandlers(t)

	manyURIs := make([]string, maxRegisterRedirectURIs+1)
	for i := range manyURIs {
		manyURIs[i] = fmt.Sprintf("https://app%d.example.com/cb", i)
	}
	atLimit := manyURIs[:maxRegisterRedirectURIs]
	longURI := "https://app.example.com/" + strings.Repeat("a", maxRegisterRedirectURI)

	for _, tc := range []struct {
		name string
		uris []string
		want int
	}{
		{"at the redirect_uris limit", atLimit, http.StatusCreated},
		{"too many redirect_uris", manyURIs, http.StatusBadRequest},
		{"redirect_uri too long", []string{longURI}, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"client_name": "App", "redirect_uris": tc.uris})
			assert.Equal(t, tc.want, postRegister(h, body).Code)
		})
	}

	t.Run("oversized body is rejected", func(t *testing.T) {
		pad := strings.Repeat("x", maxRegisterBodyBytes)
		body := []byte(`{"client_name":"App","redirect_uris":["https://a.example.com/cb"],"pad":"` + pad + `"}`)
		assert.Equal(t, http.StatusBadRequest, postRegister(h, body).Code)
	})
}

// A client that stays signed in only through token refreshes keeps its
// registration alive: refreshing past the registration TTL does not strand it.
func TestRefreshExtendsClientRegistration(t *testing.T) {
	h, sm, _, mr := testHandlers(t)
	ctx := context.Background()
	require.NoError(t, sm.StoreClientRegistration(ctx, state.NewClientRegistration("test-client", "App", []string{"https://app.example.com/cb"})))

	// Registered long ago; the refresh token is newer (they rotate).
	mr.FastForward(state.ClientRegistrationTTL - time.Hour)
	refresh := "refresh-extends-registration"
	audStoreRefresh(t, sm, refresh, "")

	w := audPostToken(t, h, audRefreshForm(refresh))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, state.ClientRegistrationTTL, mr.TTL(state.ClientPrefix+"test-client"))

	mr.FastForward(state.ClientRegistrationTTL - time.Hour)
	reg, err := sm.GetClientRegistration(ctx, "test-client")
	require.NoError(t, err)
	assert.NotNil(t, reg, "still registered after more than one full TTL of refreshing")
}
