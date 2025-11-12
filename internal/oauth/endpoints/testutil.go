package endpoints

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/refractionpoint/lc-mcp-go/internal/crypto"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/firebase"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/metadata"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/token"
	"github.com/refractionpoint/lc-mcp-go/internal/redis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLogger creates a test logger that discards output
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// generateEncryptionKey generates a valid encryption key
func generateEncryptionKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(key)
}

// setupTestRedis sets up miniredis for testing
func setupTestRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()

	// Setup miniredis
	mr := miniredis.RunT(t)

	// Setup Redis client
	redisClient, err := redis.New(&redis.Config{
		URL: "redis://" + mr.Addr(),
	}, testLogger())
	require.NoError(t, err)

	return redisClient, mr
}

// setupTestEncryption sets up encryption for testing
func setupTestEncryption(t *testing.T) *crypto.TokenEncryption {
	t.Helper()

	// Set encryption key in environment
	os.Setenv("REDIS_ENCRYPTION_KEY", generateEncryptionKey(t))
	t.Cleanup(func() {
		os.Unsetenv("REDIS_ENCRYPTION_KEY")
	})

	encryption, err := crypto.NewTokenEncryption(testLogger())
	require.NoError(t, err)

	return encryption
}

// setupTestStateManager sets up a state manager for testing
func setupTestStateManager(t *testing.T) (*state.Manager, *miniredis.Miniredis) {
	t.Helper()

	redisClient, mr := setupTestRedis(t)
	encryption := setupTestEncryption(t)

	manager := state.NewManager(redisClient, encryption, testLogger())
	require.NotNil(t, manager)

	return manager, mr
}

// mockFirebaseClient implements firebase.ClientInterface for testing
type mockFirebaseClient struct {
	createAuthURIFunc     func(ctx context.Context, provider, continueURI string, scopes []string) (string, string, error)
	signInWithIdpFunc     func(ctx context.Context, requestURI, postBody, sessionID, providerId string) (*firebase.SignInWithIdpResponse, error)
	validateCallbackFunc  func(fullRequestURI string) (string, error)
	refreshIDTokenFunc    func(ctx context.Context, refreshToken string) (string, int64, error)
	finalizeMFASignInFunc func(ctx context.Context, mfaPendingCredential, mfaEnrollmentId, mfaVerificationCode string) (*firebase.FinalizeMFAResponse, error)
}

func newMockFirebaseClient() *mockFirebaseClient {
	return &mockFirebaseClient{
		// Default implementations
		createAuthURIFunc: func(ctx context.Context, provider, continueURI string, scopes []string) (string, string, error) {
			sessionID := "test-session-id"
			authURI := "https://firebase.example.com/auth?state=firebase-state-123&redirect_uri=" + url.QueryEscape(continueURI)
			return sessionID, authURI, nil
		},
		validateCallbackFunc: func(fullRequestURI string) (string, error) {
			// Extract query string from URI
			parts := strings.SplitN(fullRequestURI, "?", 2)
			if len(parts) < 2 {
				return "", assert.AnError
			}
			return parts[1], nil
		},
		signInWithIdpFunc: func(ctx context.Context, requestURI, postBody, sessionID, providerId string) (*firebase.SignInWithIdpResponse, error) {
			return &firebase.SignInWithIdpResponse{
				LocalID:      "test-uid-123",
				IDToken:      "test-id-token",
				RefreshToken: "test-refresh-token",
				ExpiresIn:    "3600",
			}, nil
		},
		refreshIDTokenFunc: func(ctx context.Context, refreshToken string) (string, int64, error) {
			expiresAt := time.Now().Add(1 * time.Hour).Unix()
			return "refreshed-id-token", expiresAt, nil
		},
		finalizeMFASignInFunc: func(ctx context.Context, mfaPendingCredential, mfaEnrollmentId, mfaVerificationCode string) (*firebase.FinalizeMFAResponse, error) {
			if mfaVerificationCode != "123456" {
				return nil, assert.AnError
			}
			return &firebase.FinalizeMFAResponse{
				LocalID:      "test-uid-123",
				IDToken:      "test-id-token-mfa",
				RefreshToken: "test-refresh-token-mfa",
				ExpiresIn:    "3600",
			}, nil
		},
	}
}

func (m *mockFirebaseClient) CreateAuthURI(ctx context.Context, provider, continueURI string, scopes []string) (string, string, error) {
	return m.createAuthURIFunc(ctx, provider, continueURI, scopes)
}

func (m *mockFirebaseClient) SignInWithIdp(ctx context.Context, requestURI, postBody, sessionID, providerId string) (*firebase.SignInWithIdpResponse, error) {
	return m.signInWithIdpFunc(ctx, requestURI, postBody, sessionID, providerId)
}

func (m *mockFirebaseClient) ValidateProviderCallback(fullRequestURI string) (string, error) {
	return m.validateCallbackFunc(fullRequestURI)
}

func (m *mockFirebaseClient) RefreshIDToken(ctx context.Context, refreshToken string) (string, int64, error) {
	return m.refreshIDTokenFunc(ctx, refreshToken)
}

func (m *mockFirebaseClient) FinalizeMFASignIn(ctx context.Context, mfaPendingCredential, mfaEnrollmentId, mfaVerificationCode string) (*firebase.FinalizeMFAResponse, error) {
	return m.finalizeMFASignInFunc(ctx, mfaPendingCredential, mfaEnrollmentId, mfaVerificationCode)
}

// testHandlers creates handlers for testing with mocked dependencies
func testHandlers(t *testing.T) (*Handlers, *state.Manager, *mockFirebaseClient) {
	t.Helper()

	// Setup test environment
	os.Setenv("MCP_SERVER_URL", "https://test.example.com")
	t.Cleanup(func() {
		os.Unsetenv("MCP_SERVER_URL")
	})

	// Setup state manager with Redis and encryption
	stateManager, _ := setupTestStateManager(t)

	// Create mock Firebase client
	mockFB := newMockFirebaseClient()

	// Create metadata provider
	metadataProvider := metadata.NewProvider(testLogger())

	// Create token manager
	tokenManager := token.NewManager(stateManager, mockFB, testLogger())

	// Allowed redirect URIs for testing
	allowedRedirectURIs := []string{
		"https://app.example.com/callback",
		"https://app.example.com/oauth/callback",
		"http://localhost:3000/callback",
		"http://127.0.0.1:3000/callback",
	}

	// Create handlers - need to bypass template loading
	handlers := &Handlers{
		stateManager:        stateManager,
		tokenManager:        tokenManager,
		firebaseClient:      mockFB,
		metadataProvider:    metadataProvider,
		logger:              testLogger(),
		templates:           nil, // Templates not needed for most tests
		allowedRedirectURIs: allowedRedirectURIs,
	}

	return handlers, stateManager, mockFB
}

// generatePKCEChallenge generates a PKCE challenge from verifier
func generatePKCEChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// stringPtr is a helper to get a pointer to a string
func stringPtr(s string) *string {
	return &s
}
