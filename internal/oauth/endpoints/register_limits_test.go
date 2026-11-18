package endpoints

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
