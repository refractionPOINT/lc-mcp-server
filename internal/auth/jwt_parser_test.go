package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIsJWTFormat(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected bool
	}{
		{
			name:     "valid JWT format",
			token:    "header.payload.signature",
			expected: true,
		},
		{
			name:     "real-looking JWT",
			token:    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature",
			expected: true,
		},
		{
			name:     "empty string",
			token:    "",
			expected: false,
		},
		{
			name:     "no dots",
			token:    "notajwt",
			expected: false,
		},
		{
			name:     "one dot only",
			token:    "header.payload",
			expected: false,
		},
		{
			name:     "too many dots",
			token:    "header.payload.signature.extra",
			expected: false,
		},
		{
			name:     "API key format (not JWT)",
			token:    "api_key_12345678901234567890123456789012",
			expected: false,
		},
		{
			name:     "MCP OAuth token (not JWT)",
			token:    "mcp_token_abcdef1234567890",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsJWTFormat(tt.token)
			assert.Equal(t, tt.expected, result, "IsJWTFormat(%q)", tt.token)
		})
	}
}

func TestParseAndValidateLimaCharlieJWT_InvalidFormats(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		expectError bool
	}{
		{
			name:        "empty token",
			token:       "",
			expectError: true,
		},
		{
			name:        "not a JWT format",
			token:       "not-a-jwt-token",
			expectError: true,
		},
		{
			name:        "malformed JWT",
			token:       "invalid.jwt.here",
			expectError: true,
		},
		{
			name:        "JWT with invalid base64",
			token:       "not-base64!.not-base64!.not-base64!",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := ParseAndValidateLimaCharlieJWT(tt.token)
			if tt.expectError {
				assert.Error(t, err, "Expected error for token: %s", tt.token)
				assert.Nil(t, claims, "Claims should be nil on error")
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, claims)
			}
		})
	}
}

func TestParseAndValidateLimaCharlieJWT_PublicKeyLoading(t *testing.T) {
	// This test verifies that the public key loads correctly
	// Even with an invalid JWT, we should get a parsing error, not a key loading error
	_, err := ParseAndValidateLimaCharlieJWT("invalid.jwt.token")

	// Should get a JWT parsing error, not a key loading error
	assert.Error(t, err)
	assert.NotContains(t, err.Error(), "failed to load API public key")
}

// TestLCClaims tests the LCClaims structure
func TestLCClaims(t *testing.T) {
	t.Run("org token claims", func(t *testing.T) {
		claims := &LCClaims{
			UID:         "test-user-123",
			Ident:       "test@example.com",
			OIDs:        []string{"org1", "org2"},
			IsUserToken: false,
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			KeyID:       "key123",
			SourceIP:    "192.168.1.1",
			Permissions: map[string][]string{
				"org1": {"sensor.get", "sensor.list"},
				"org2": {"sensor.get"},
			},
		}

		assert.Equal(t, "test-user-123", claims.UID)
		assert.Equal(t, "test@example.com", claims.Ident)
		assert.Len(t, claims.OIDs, 2)
		assert.False(t, claims.IsUserToken)
		assert.True(t, claims.ExpiresAt.After(time.Now()))
	})

	t.Run("user token claims", func(t *testing.T) {
		claims := &LCClaims{
			UID:         "user@example.com",
			Ident:       "user@example.com",
			OIDs:        []string{"org1", "org2", "org3"},
			IsUserToken: true,
			ExpiresAt:   time.Now().Add(30 * time.Minute),
			Permissions: map[string][]string{
				"org1": {"dr.set", "sensor.list"},
				"org2": {"insight.evt.get"},
				"org3": {"sensor.get"},
			},
		}

		assert.Equal(t, "user@example.com", claims.UID)
		assert.True(t, claims.IsUserToken)
		assert.Len(t, claims.OIDs, 3)
		assert.Len(t, claims.Permissions, 3)
	})
}

// Note: To test actual JWT parsing with valid signatures, you would need:
// 1. A test JWT signed with the corresponding private key, or
// 2. Mock the RSA verification (complex for this use case), or
// 3. Integration tests with real JWTs from the LimaCharlie platform
//
// For now, these tests validate:
// - Format detection
// - Error handling for invalid tokens
// - Public key loading
// - Claims structure
//
// Integration tests with real API gateway JWTs will validate the full flow.

func TestParseAndValidateLimaCharlieJWT_SignatureValidation(t *testing.T) {
	// This test verifies that signature validation is attempted
	// We use a valid JWT structure but with a wrong signature

	// Valid JWT structure with invalid signature
	// Header: {"alg":"RS256","typ":"JWT"}
	// Payload: {"uid":"test","email":"test@test.com","oid":["test-org"],"exp":9999999999}
	// Signature: invalid
	invalidJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiJ0ZXN0IiwiZW1haWwiOiJ0ZXN0QHRlc3QuY29tIiwib2lkIjpbInRlc3Qtb3JnIl0sImV4cCI6OTk5OTk5OTk5OX0.invalid_signature"

	claims, err := ParseAndValidateLimaCharlieJWT(invalidJWT)

	// Should fail because signature is invalid
	assert.Error(t, err, "Should reject JWT with invalid signature")
	assert.Nil(t, claims, "Claims should be nil for invalid signature")
}
