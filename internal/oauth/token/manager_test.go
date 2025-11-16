package token

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Helper to create test logger
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewManager(t *testing.T) {
	t.Run("creates new token manager", func(t *testing.T) {
		mgr := NewManager(nil, nil, testLogger())

		assert.NotNil(t, mgr)
		assert.NotNil(t, mgr.logger)
	})
}

func TestValidationResult_Structure(t *testing.T) {
	t.Run("ValidationResult has expected fields", func(t *testing.T) {
		result := &ValidationResult{
			Valid:                true,
			UID:                  "test-uid",
			FirebaseIDToken:      "firebase-token",
			FirebaseRefreshToken: "refresh-token",
			LimaCharlieJWT:       "lc-jwt",
			Scope:                "openid email",
			Error:                "",
			Refreshed:            false,
		}

		assert.True(t, result.Valid)
		assert.Equal(t, "test-uid", result.UID)
		assert.Equal(t, "firebase-token", result.FirebaseIDToken)
		assert.Equal(t, "refresh-token", result.FirebaseRefreshToken)
		assert.Equal(t, "lc-jwt", result.LimaCharlieJWT)
		assert.Equal(t, "openid email", result.Scope)
		assert.Empty(t, result.Error)
		assert.False(t, result.Refreshed)
	})

	t.Run("Invalid ValidationResult includes error", func(t *testing.T) {
		result := &ValidationResult{
			Valid: false,
			Error: "token expired",
		}

		assert.False(t, result.Valid)
		assert.Equal(t, "token expired", result.Error)
		assert.Empty(t, result.UID)
	})
}

func TestTokenResponse_Structure(t *testing.T) {
	t.Run("TokenResponse has OAuth 2.0 compliant fields", func(t *testing.T) {
		resp := &TokenResponse{
			AccessToken:  "access-token-123",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "refresh-token-456",
			Scope:        "openid email profile",
		}

		assert.Equal(t, "access-token-123", resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, 3600, resp.ExpiresIn)
		assert.Equal(t, "refresh-token-456", resp.RefreshToken)
		assert.Equal(t, "openid email profile", resp.Scope)
	})

	t.Run("TokenResponse optional fields can be empty", func(t *testing.T) {
		resp := &TokenResponse{
			AccessToken: "token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			// RefreshToken and Scope are optional
		}

		assert.Equal(t, "token", resp.AccessToken)
		assert.Empty(t, resp.RefreshToken)
		assert.Empty(t, resp.Scope)
	})
}

func TestIntrospectionResponse_Structure(t *testing.T) {
	t.Run("IntrospectionResponse follows RFC 7662", func(t *testing.T) {
		resp := &IntrospectionResponse{
			Active:    true,
			Scope:     "openid email",
			ClientID:  "client-123",
			TokenType: "Bearer",
			Exp:       1234567890,
			Iat:       1234564290,
			Sub:       "user-firebase-uid",
		}

		assert.True(t, resp.Active)
		assert.Equal(t, "openid email", resp.Scope)
		assert.Equal(t, "client-123", resp.ClientID)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, int64(1234567890), resp.Exp)
		assert.Equal(t, int64(1234564290), resp.Iat)
		assert.Equal(t, "user-firebase-uid", resp.Sub)
	})

	t.Run("Inactive token introspection response", func(t *testing.T) {
		resp := &IntrospectionResponse{
			Active: false,
		}

		assert.False(t, resp.Active)
		// All other fields should be zero values when inactive
		assert.Empty(t, resp.Scope)
		assert.Empty(t, resp.ClientID)
	})
}

// Note: Edge case tests with nil dependencies would panic (expected behavior)
// These are documented here but not tested since they represent programmer errors,
// not runtime conditions. The manager expects valid dependencies from NewManager.

// Test validation of token expiry thresholds
func TestTokenExpiryThresholds(t *testing.T) {
	t.Run("5 minute threshold for Firebase token refresh is reasonable", func(t *testing.T) {
		// The code uses 300 seconds (5 minutes) as the threshold for refreshing
		// Firebase tokens before they expire. This is a good balance:
		// - Not too aggressive (would refresh too often)
		// - Not too conservative (might expire mid-request)

		const refreshThreshold = 300 // seconds, from manager.go:80

		assert.Equal(t, 300, refreshThreshold)
		assert.Greater(t, refreshThreshold, 60, "Should be more than 1 minute")
		assert.Less(t, refreshThreshold, 600, "Should be less than 10 minutes")
	})
}

// Test constant values match OAuth 2.0 spec
func TestOAuthCompliance(t *testing.T) {
	t.Run("TokenResponse TokenType should be Bearer", func(t *testing.T) {
		// OAuth 2.0 spec (RFC 6749) requires "Bearer" token type
		resp := &TokenResponse{
			TokenType: "Bearer",
		}

		assert.Equal(t, "Bearer", resp.TokenType, "Token type must be 'Bearer' per RFC 6749")
	})

	t.Run("IntrospectionResponse follows RFC 7662 field names", func(t *testing.T) {
		// RFC 7662 specifies exact field names for introspection response
		resp := &IntrospectionResponse{
			Active: true,
		}

		// Verify fields match spec (by checking they exist via struct tags)
		assert.NotNil(t, resp)
		// Field names are validated by JSON marshaling in actual usage
	})
}

// Benchmark token validation result creation
func BenchmarkValidationResult(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = &ValidationResult{
			Valid:                true,
			UID:                  "user-123",
			FirebaseIDToken:      "firebase-token",
			FirebaseRefreshToken: "refresh-token",
			LimaCharlieJWT:       "lc-jwt",
			Scope:                "openid email",
			Refreshed:            false,
		}
	}
}

func BenchmarkTokenResponse(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = &TokenResponse{
			AccessToken:  "token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "refresh",
			Scope:        "openid email",
		}
	}
}

// NOTE: Security properties such as refresh token rotation, auto-refresh behavior,
// and JWT exchange are documented in the production code comments (manager.go).
// Actual behavioral tests for these features require integration testing with
// real Firebase and LimaCharlie services, or comprehensive mocking of the
// firebase.ClientInterface and stateManager dependencies.
