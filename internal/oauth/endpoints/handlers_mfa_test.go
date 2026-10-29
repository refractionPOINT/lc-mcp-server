package endpoints

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/firebase"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupMFASession stores an OAuth state and a pending MFA session, returning the MFA session ID
func setupMFASession(t *testing.T, stateManager *state.Manager, oauthStateParam string) string {
	t.Helper()
	ctx := context.Background()
	oauthState := state.NewOAuthState(oauthStateParam, "challenge", "S256", "https://app.example.com/callback", "test-client", "openid", "", "google.com")
	require.NoError(t, stateManager.StoreOAuthState(ctx, oauthState))
	sessionID, err := stateManager.GenerateMFASessionID()
	require.NoError(t, err)
	mfaSession := state.NewMFASession("pending", "totp-id", oauthStateParam, "User", "uid", "user@test.com", nil)
	require.NoError(t, stateManager.StoreMFASession(ctx, sessionID, mfaSession))
	return sessionID
}

func TestHandleMFAVerify_FirebaseErrorMapping(t *testing.T) {
	tests := []struct {
		name           string
		fbErr          error
		wantStatus     int
		wantError      string
		sessionRemains bool
	}{
		{"wrong code allows retry", fmt.Errorf("%w: INVALID_CODE", firebase.ErrMFAInvalidCode), http.StatusBadRequest, "invalid_code", true},
		{"expired pending credential ends session", fmt.Errorf("%w: INVALID_MFA_PENDING_CREDENTIAL", firebase.ErrMFASessionExpired), http.StatusBadRequest, "session_expired", false},
		{"firebase rate limit", fmt.Errorf("%w: TOO_MANY_ATTEMPTS_TRY_LATER", firebase.ErrMFATooManyAttempts), http.StatusTooManyRequests, "too_many_attempts", true},
		{"enrollment mismatch is a server error", fmt.Errorf("MFA finalization failed: %w", &firebase.FirebaseError{}), http.StatusInternalServerError, "server_error", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handlers, stateManager, mockFB, _ := testHandlers(t)
			sessionID := setupMFASession(t, stateManager, "oauth-mfa-map")
			mockFB.finalizeMFASignInFunc = func(ctx context.Context, pending, enrollment, code string) (*firebase.FinalizeMFAResponse, error) {
				return nil, tt.fbErr
			}

			w := httptest.NewRecorder()
			handlers.HandleMFAVerify(w, httptest.NewRequest(http.MethodPost, "/oauth/mfa-verify", nil), sessionID, "123456")

			assert.Equal(t, tt.wantStatus, w.Code)
			var resp map[string]interface{}
			require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Equal(t, false, resp["success"])
			assert.Equal(t, tt.wantError, resp["error"])
			if tt.wantError != "invalid_code" {
				assert.NotContains(t, resp["error_description"], "Invalid verification code",
					"only a wrong code may be reported as one")
				assert.NotContains(t, resp, "attempts_remaining")
			}

			remaining, _ := stateManager.GetMFASession(context.Background(), sessionID)
			assert.Equal(t, tt.sessionRemains, remaining != nil)
		})
	}
}

func TestHandleMFAVerify_AfterSessionExpiredReportsExpiry(t *testing.T) {
	handlers, stateManager, mockFB, _ := testHandlers(t)
	sessionID := setupMFASession(t, stateManager, "oauth-mfa-expired")
	mockFB.finalizeMFASignInFunc = func(ctx context.Context, pending, enrollment, code string) (*firebase.FinalizeMFAResponse, error) {
		return nil, fmt.Errorf("%w: INVALID_MFA_PENDING_CREDENTIAL", firebase.ErrMFASessionExpired)
	}

	w := httptest.NewRecorder()
	handlers.HandleMFAVerify(w, httptest.NewRequest(http.MethodPost, "/oauth/mfa-verify", nil), sessionID, "123456")
	require.Equal(t, http.StatusBadRequest, w.Code)

	// The challenge page lets the user submit again; that must say the
	// session is gone rather than fail with a server error.
	w = httptest.NewRecorder()
	handlers.HandleMFAVerify(w, httptest.NewRequest(http.MethodPost, "/oauth/mfa-verify", nil), sessionID, "654321")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Contains(t, resp["error_description"], "expired or invalid")
}

func TestHandleCallback_MFAWithoutTOTPFactor(t *testing.T) {
	handlers, stateManager, mockFB, _ := testHandlers(t)
	ctx := context.Background()

	oauthState := state.NewOAuthState("oauth-sms-only", "challenge", "S256", "https://app.example.com/callback", "test-client", "openid", "", "google.com")
	require.NoError(t, stateManager.StoreOAuthState(ctx, oauthState))
	fbState := "fb-sms-only"
	stateManager.StoreSelectionSession(ctx, "oauth:session:oauth-sms-only", map[string]string{"firebase_state": fbState})
	stateManager.StoreSelectionSession(ctx, "oauth:state:"+fbState, map[string]string{"oauth_state": "oauth-sms-only"})
	stateManager.StoreSelectionSession(ctx, "oauth:fbsession:"+fbState, map[string]string{"session_id": "session-sms"})

	mockFB.signInWithIdpFunc = func(ctx context.Context, requestURI, postBody, sid, providerId string) (*firebase.SignInWithIdpResponse, error) {
		return nil, &firebase.MFAUnsupportedError{FactorCount: 1}
	}

	w := httptest.NewRecorder()
	handlers.HandleCallback(w, httptest.NewRequest(http.MethodGet, "/oauth/callback?state="+fbState+"&code=test", nil))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Empty(t, w.Header().Get("Location"), "must not start an MFA challenge that cannot succeed")
	assert.Contains(t, w.Body.String(), "authenticator app")

	consumed, _ := stateManager.GetOAuthState(ctx, "oauth-sms-only")
	assert.Nil(t, consumed, "OAuth state must not be reusable after the flow ends")
}

func TestRenderOAuthError_UsesRealTemplate(t *testing.T) {
	handlers, _, _, _ := testHandlers(t)
	tmpl, err := template.ParseGlob("../../../templates/*.html")
	require.NoError(t, err)
	handlers.templates = tmpl

	w := httptest.NewRecorder()
	handlers.renderOAuthError(w, http.StatusForbidden, oauthErrorPage{
		ErrorTitle:   "Authenticator App Required",
		ErrorMessage: "Use an authenticator app.",
		ErrorCode:    "mfa_method_unsupported",
		RetryURL:     limaCharlieWebAppURL,
		RetryLabel:   "Open LimaCharlie",
	})

	assert.Equal(t, http.StatusForbidden, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "<!DOCTYPE html>", "should render the styled page, not the plain fallback")
	assert.Contains(t, body, `href="`+limaCharlieWebAppURL+`"`)
	assert.Contains(t, body, "Open LimaCharlie")
	assert.NotContains(t, body, "Try Again")
	assert.Contains(t, body, "mfa_method_unsupported")
}
