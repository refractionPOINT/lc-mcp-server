package firebase

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// roundTripFunc serves canned Firebase responses without network access
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newTestClient(status int, body string, captured *[]byte) *Client {
	return &Client{
		apiKey: "test-key",
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if captured != nil && r.Body != nil {
				*captured, _ = io.ReadAll(r.Body)
			}
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		})},
	}
}

const (
	phoneFactor = `{"mfaEnrollmentId":"phone-id","displayName":"Phone","phoneInfo":"+*******1234","enrolledAt":"2024-01-01T00:00:00Z"}`
	totpFactor  = `{"mfaEnrollmentId":"totp-id","displayName":"Authenticator","totpInfo":{},"enrolledAt":"2024-02-01T00:00:00Z"}`
)

func mfaSignInBody(factors ...string) string {
	return `{"mfaPendingCredential":"pending-cred","localId":"uid-1","email":"user@example.com","mfaInfo":[` + strings.Join(factors, ",") + `]}`
}

func TestSignInWithIdp_SelectsTOTPFactor(t *testing.T) {
	tests := []struct {
		name    string
		factors []string
	}{
		{"totp only", []string{totpFactor}},
		{"phone listed before totp", []string{phoneFactor, totpFactor}},
		{"totp listed before phone", []string{totpFactor, phoneFactor}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(http.StatusOK, mfaSignInBody(tt.factors...), nil)

			_, err := c.SignInWithIdp(context.Background(), "https://mcp/cb", "code=x", "sid", "google.com")

			var mfaErr *MFARequiredError
			require.ErrorAs(t, err, &mfaErr)
			assert.Equal(t, "totp-id", mfaErr.MFAEnrollmentID)
			assert.Equal(t, "Authenticator", mfaErr.DisplayName)
			assert.Equal(t, "pending-cred", mfaErr.MFAPendingCredential)
			assert.Equal(t, "uid-1", mfaErr.LocalID)
		})
	}
}

func TestSignInWithIdp_NoTOTPFactorIsUnsupported(t *testing.T) {
	tests := []struct {
		name    string
		factors []string
	}{
		{"phone only", []string{phoneFactor}},
		{"two phones", []string{phoneFactor, strings.Replace(phoneFactor, "phone-id", "phone-2", 1)}},
		{"unknown factor type", []string{`{"mfaEnrollmentId":"email-id","emailInfo":{"emailAddress":"x@example.com"}}`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(http.StatusOK, mfaSignInBody(tt.factors...), nil)

			_, err := c.SignInWithIdp(context.Background(), "https://mcp/cb", "code=x", "sid", "google.com")

			var unsupported *MFAUnsupportedError
			require.ErrorAs(t, err, &unsupported)
			assert.Equal(t, len(tt.factors), unsupported.FactorCount)
			var mfaErr *MFARequiredError
			assert.False(t, errors.As(err, &mfaErr), "must not start a TOTP challenge without a TOTP factor")
		})
	}
}

func TestFinalizeMFASignIn_SendsTOTPCodeForEnrollment(t *testing.T) {
	var body []byte
	c := newTestClient(http.StatusOK, `{"idToken":"id","refreshToken":"rt","localId":"uid-1"}`, &body)

	resp, err := c.FinalizeMFASignIn(context.Background(), "pending-cred", "totp-id", "123456")
	require.NoError(t, err)
	assert.Equal(t, "uid-1", resp.LocalID)

	var sent map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &sent))
	assert.Equal(t, "pending-cred", sent["mfaPendingCredential"])
	assert.Equal(t, "totp-id", sent["mfaEnrollmentId"])
	assert.Equal(t, map[string]interface{}{"verificationCode": "123456"}, sent["totpVerificationInfo"])
}

func TestFinalizeMFASignIn_ErrorMapping(t *testing.T) {
	firebaseErr := func(msg string) string {
		return `{"error":{"code":400,"message":"` + msg + `","errors":[{"message":"` + msg + `","domain":"global","reason":"invalid"}]}}`
	}
	tests := []struct {
		name   string
		status int
		body   string
		want   error // nil: none of the sentinels may match
	}{
		{"wrong code", 400, firebaseErr("INVALID_CODE"), ErrMFAInvalidCode},
		{"wrong code with detail", 400, firebaseErr("INVALID_CODE : Invalid verification code."), ErrMFAInvalidCode},
		{"empty code", 400, firebaseErr("MISSING_CODE"), ErrMFAInvalidCode},
		{"pending credential expired", 400, firebaseErr("INVALID_MFA_PENDING_CREDENTIAL"), ErrMFASessionExpired},
		{"pending credential rejected", 400, firebaseErr("INVALID_PENDING_TOKEN"), ErrMFASessionExpired},
		{"session expired", 400, firebaseErr("SESSION_EXPIRED"), ErrMFASessionExpired},
		{"rate limited", 400, firebaseErr("TOO_MANY_ATTEMPTS_TRY_LATER"), ErrMFATooManyAttempts},
		{"wrong enrollment is not a bad code", 400, firebaseErr("INVALID_MFA_ENROLLMENT_ID"), nil},
		{"unknown enrollment is not a bad code", 400, firebaseErr("MFA_ENROLLMENT_NOT_FOUND"), nil},
		{"non-JSON upstream failure", 503, "upstream unavailable", nil},
	}
	sentinels := []error{ErrMFAInvalidCode, ErrMFASessionExpired, ErrMFATooManyAttempts}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(tt.status, tt.body, nil)

			_, err := c.FinalizeMFASignIn(context.Background(), "pending-cred", "totp-id", "123456")
			require.Error(t, err)

			for _, s := range sentinels {
				assert.Equal(t, s == tt.want, errors.Is(err, s), "errors.Is(err, %q)", s)
			}
			if tt.status == 400 {
				var fbErr *FirebaseError
				assert.ErrorAs(t, err, &fbErr, "original Firebase error must stay inspectable for logs")
			}
		})
	}
}

func TestRefreshIDToken_DistinguishesDeadFromTransient(t *testing.T) {
	fbBody := func(msg string) string {
		b, _ := json.Marshal(map[string]any{"error": map[string]any{"code": 400, "message": msg}})
		return string(b)
	}
	cases := []struct {
		name   string
		status int
		body   string
		dead   bool
	}{
		{"token expired", http.StatusBadRequest, fbBody("TOKEN_EXPIRED"), true},
		{"token expired with detail", http.StatusBadRequest, fbBody("TOKEN_EXPIRED : the credential is no longer valid"), true},
		{"user disabled", http.StatusBadRequest, fbBody("USER_DISABLED"), true},
		{"user not found", http.StatusBadRequest, fbBody("USER_NOT_FOUND"), true},
		{"invalid refresh token", http.StatusBadRequest, fbBody("INVALID_REFRESH_TOKEN"), true},
		{"api key not valid", http.StatusBadRequest, fbBody("API key not valid. Please pass a valid API key."), false},
		{"invalid api key", http.StatusBadRequest, fbBody("INVALID_API_KEY"), false},
		{"project mismatch", http.StatusBadRequest, fbBody("PROJECT_NUMBER_MISMATCH"), false},
		{"invalid grant type", http.StatusBadRequest, fbBody("INVALID_GRANT_TYPE"), false},
		{"missing refresh token", http.StatusBadRequest, fbBody("MISSING_REFRESH_TOKEN"), false},
		{"unknown code", http.StatusBadRequest, fbBody("SOMETHING_NEW"), false},
		{"400 that is not Firebase's format", http.StatusBadRequest, "<html>bad request</html>", false},
		{"dead code on a 500 is not trusted", http.StatusInternalServerError, fbBody("TOKEN_EXPIRED"), false},
		{"unavailable", http.StatusServiceUnavailable, fbBody("TOKEN_EXPIRED"), false},
		{"rate limited", http.StatusTooManyRequests, fbBody("TOKEN_EXPIRED"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(tc.status, tc.body, nil)
			_, _, err := c.RefreshIDToken(context.Background(), "rt")
			require.Error(t, err)
			assert.Equal(t, tc.dead, errors.Is(err, ErrRefreshTokenRejected))
		})
	}
}
