package firebase

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to create a fake JWT for testing
// WARNING: This creates INVALID JWTs for testing only - signature is fake!
func createFakeJWT(claims map[string]interface{}) string {
	// Create header
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Create payload
	payloadJSON, _ := json.Marshal(claims)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create fake signature (not cryptographically valid)
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))

	return headerB64 + "." + payloadB64 + "." + signature
}

func TestParseIDTokenClaims(t *testing.T) {
	t.Run("parses valid JWT structure", func(t *testing.T) {
		claims := map[string]interface{}{
			"sub":   "user-123",
			"email": "user@example.com",
			"iat":   1234567890,
			"exp":   1234567990,
		}
		token := createFakeJWT(claims)

		parsed, err := ParseIDTokenClaims(token)

		require.NoError(t, err)
		assert.Equal(t, "user-123", parsed["sub"])
		assert.Equal(t, "user@example.com", parsed["email"])
		assert.Equal(t, float64(1234567890), parsed["iat"]) // JSON numbers are float64
		assert.Equal(t, float64(1234567990), parsed["exp"])
	})

	t.Run("rejects token with wrong number of parts", func(t *testing.T) {
		invalidTokens := []string{
			"single-part",
			"two.parts",
			"four.parts.are.invalid",
			"",
		}

		for _, token := range invalidTokens {
			_, err := ParseIDTokenClaims(token)
			assert.Error(t, err, "Should error for token: %s", token)
			assert.Contains(t, err.Error(), "invalid JWT format")
		}
	})

	t.Run("rejects token with invalid base64 payload", func(t *testing.T) {
		// Create token with invalid base64 in payload section
		token := "eyJhbGciOiJIUzI1NiJ9.invalid!!!base64.signature"

		_, err := ParseIDTokenClaims(token)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode JWT payload")
	})

	t.Run("rejects token with invalid JSON payload", func(t *testing.T) {
		// Create token with valid base64 but invalid JSON
		invalidJSON := base64.RawURLEncoding.EncodeToString([]byte("{not valid json"))
		token := "eyJhbGciOiJIUzI1NiJ9." + invalidJSON + ".signature"

		_, err := ParseIDTokenClaims(token)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal JWT claims")
	})

	t.Run("handles special characters in claims", func(t *testing.T) {
		claims := map[string]interface{}{
			"sub":   "user-with-special-chars-@#$%",
			"name":  "Test User 日本語",
			"email": "test+tag@example.com",
		}
		token := createFakeJWT(claims)

		parsed, err := ParseIDTokenClaims(token)

		require.NoError(t, err)
		assert.Equal(t, claims["sub"], parsed["sub"])
		assert.Equal(t, claims["name"], parsed["name"])
		assert.Equal(t, claims["email"], parsed["email"])
	})

	t.Run("handles nested claims", func(t *testing.T) {
		claims := map[string]interface{}{
			"sub": "user-123",
			"firebase": map[string]interface{}{
				"identities": map[string]interface{}{
					"google.com": []string{"1234567890"},
				},
				"sign_in_provider": "google.com",
			},
		}
		token := createFakeJWT(claims)

		parsed, err := ParseIDTokenClaims(token)

		require.NoError(t, err)
		assert.Equal(t, "user-123", parsed["sub"])
		firebase, ok := parsed["firebase"].(map[string]interface{})
		require.True(t, ok, "firebase claim should be a map")
		assert.Equal(t, "google.com", firebase["sign_in_provider"])
	})
}

func TestExtractUIDFromIDToken(t *testing.T) {
	t.Run("extracts UID from valid token", func(t *testing.T) {
		claims := map[string]interface{}{
			"sub":   "user-abc-123",
			"email": "user@example.com",
		}
		token := createFakeJWT(claims)

		uid, err := ExtractUIDFromIDToken(token)

		require.NoError(t, err)
		assert.Equal(t, "user-abc-123", uid)
	})

	t.Run("returns error for empty token", func(t *testing.T) {
		uid, err := ExtractUIDFromIDToken("")

		assert.Error(t, err)
		assert.Empty(t, uid)
		assert.Contains(t, err.Error(), "ID token is empty")
	})

	t.Run("returns error when sub claim is missing", func(t *testing.T) {
		claims := map[string]interface{}{
			"email": "user@example.com",
			"iat":   1234567890,
			// No "sub" claim
		}
		token := createFakeJWT(claims)

		uid, err := ExtractUIDFromIDToken(token)

		assert.Error(t, err)
		assert.Empty(t, uid)
		assert.Contains(t, err.Error(), "sub claim not found")
	})

	t.Run("returns error when sub claim is empty string", func(t *testing.T) {
		claims := map[string]interface{}{
			"sub":   "",
			"email": "user@example.com",
		}
		token := createFakeJWT(claims)

		uid, err := ExtractUIDFromIDToken(token)

		assert.Error(t, err)
		assert.Empty(t, uid)
		assert.Contains(t, err.Error(), "sub claim not found or invalid")
	})

	t.Run("returns error when sub claim is not a string", func(t *testing.T) {
		claims := map[string]interface{}{
			"sub":   123456, // Number instead of string
			"email": "user@example.com",
		}
		token := createFakeJWT(claims)

		uid, err := ExtractUIDFromIDToken(token)

		assert.Error(t, err)
		assert.Empty(t, uid)
		assert.Contains(t, err.Error(), "sub claim not found or invalid")
	})

	t.Run("handles malformed JWT", func(t *testing.T) {
		invalidTokens := []string{
			"not.a.jwt",
			"single-part",
			"two.parts",
		}

		for _, token := range invalidTokens {
			uid, err := ExtractUIDFromIDToken(token)
			assert.Error(t, err, "Should error for token: %s", token)
			assert.Empty(t, uid)
		}
	})

	t.Run("extracts UID with special characters", func(t *testing.T) {
		specialUIDs := []string{
			"user-with-dashes-123",
			"user_with_underscores_456",
			"user.with.dots.789",
			"CamelCaseUID",
			"UPPERCASE",
			"lowercase",
			"1234567890",
		}

		for _, expectedUID := range specialUIDs {
			claims := map[string]interface{}{
				"sub": expectedUID,
			}
			token := createFakeJWT(claims)

			uid, err := ExtractUIDFromIDToken(token)

			require.NoError(t, err, "Should extract UID: %s", expectedUID)
			assert.Equal(t, expectedUID, uid)
		}
	})
}

// Test real-world Firebase token structure (without signature verification)
func TestRealWorldFirebaseTokenStructure(t *testing.T) {
	t.Run("parses typical Firebase auth token claims", func(t *testing.T) {
		// Typical Firebase ID token claims structure
		claims := map[string]interface{}{
			"iss":            "https://securetoken.google.com/project-id",
			"aud":            "project-id",
			"auth_time":      1234567890,
			"user_id":        "abc123def456",
			"sub":            "abc123def456",
			"iat":            1234567890,
			"exp":            1234571490,
			"email":          "user@example.com",
			"email_verified": true,
			"firebase": map[string]interface{}{
				"identities": map[string]interface{}{
					"email": []string{"user@example.com"},
				},
				"sign_in_provider": "password",
			},
		}
		token := createFakeJWT(claims)

		parsed, err := ParseIDTokenClaims(token)
		require.NoError(t, err)

		// Verify key claims are present
		assert.Equal(t, "abc123def456", parsed["sub"])
		assert.Equal(t, "user@example.com", parsed["email"])
		assert.Equal(t, true, parsed["email_verified"])
		assert.NotNil(t, parsed["firebase"])

		// Extract UID
		uid, err := ExtractUIDFromIDToken(token)
		require.NoError(t, err)
		assert.Equal(t, "abc123def456", uid)
	})

	t.Run("handles Google OAuth provider token", func(t *testing.T) {
		claims := map[string]interface{}{
			"sub":            "google-user-12345",
			"email":          "user@gmail.com",
			"email_verified": true,
			"name":           "Test User",
			"picture":        "https://example.com/photo.jpg",
			"firebase": map[string]interface{}{
				"identities": map[string]interface{}{
					"google.com": []string{"1234567890"},
					"email":      []string{"user@gmail.com"},
				},
				"sign_in_provider": "google.com",
			},
		}
		token := createFakeJWT(claims)

		uid, err := ExtractUIDFromIDToken(token)
		require.NoError(t, err)
		assert.Equal(t, "google-user-12345", uid)

		parsed, err := ParseIDTokenClaims(token)
		require.NoError(t, err)
		firebase, ok := parsed["firebase"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "google.com", firebase["sign_in_provider"])
	})
}

// Benchmark JWT parsing performance
func BenchmarkParseIDTokenClaims(b *testing.B) {
	claims := map[string]interface{}{
		"sub":   "user-123",
		"email": "user@example.com",
		"iat":   1234567890,
		"exp":   1234567990,
	}
	token := createFakeJWT(claims)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseIDTokenClaims(token)
	}
}

func BenchmarkExtractUIDFromIDToken(b *testing.B) {
	claims := map[string]interface{}{
		"sub": "user-123",
	}
	token := createFakeJWT(claims)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractUIDFromIDToken(token)
	}
}

// Test edge cases
func TestJWTEdgeCases(t *testing.T) {
	t.Run("handles very long UID", func(t *testing.T) {
		longUID := strings.Repeat("a", 1000)
		claims := map[string]interface{}{
			"sub": longUID,
		}
		token := createFakeJWT(claims)

		uid, err := ExtractUIDFromIDToken(token)

		require.NoError(t, err)
		assert.Equal(t, longUID, uid)
		assert.Len(t, uid, 1000)
	})

	t.Run("handles minimal valid token", func(t *testing.T) {
		claims := map[string]interface{}{
			"sub": "u",
		}
		token := createFakeJWT(claims)

		uid, err := ExtractUIDFromIDToken(token)

		require.NoError(t, err)
		assert.Equal(t, "u", uid)
	})

	t.Run("handles token with many claims", func(t *testing.T) {
		claims := make(map[string]interface{})
		claims["sub"] = "user-123"
		for i := 0; i < 100; i++ {
			claims[string(rune('a'+i%26))+string(rune(i))] = "value"
		}
		token := createFakeJWT(claims)

		uid, err := ExtractUIDFromIDToken(token)

		require.NoError(t, err)
		assert.Equal(t, "user-123", uid)
	})
}
