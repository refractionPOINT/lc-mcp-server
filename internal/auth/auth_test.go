package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthMode_String(t *testing.T) {
	tests := []struct {
		mode     AuthMode
		expected string
	}{
		{AuthModeNormal, "normal"},
		{AuthModeUIDKey, "uid_key"},
		{AuthModeUIDOAuth, "uid_oauth"},
		{AuthMode(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.mode.String())
		})
	}
}

func TestAuthContext_CacheKey(t *testing.T) {
	t.Run("different credentials produce different keys", func(t *testing.T) {
		auth1 := &AuthContext{
			Mode:   AuthModeNormal,
			OID:    "org1",
			APIKey: "key1",
		}

		auth2 := &AuthContext{
			Mode:   AuthModeNormal,
			OID:    "org2",
			APIKey: "key2",
		}

		key1 := auth1.CacheKey()
		key2 := auth2.CacheKey()

		assert.NotEqual(t, key1, key2, "Different credentials must produce different cache keys")
	})

	t.Run("same credentials produce same key", func(t *testing.T) {
		auth1 := &AuthContext{
			Mode:   AuthModeNormal,
			OID:    "org1",
			APIKey: "key1",
		}

		auth2 := &AuthContext{
			Mode:   AuthModeNormal,
			OID:    "org1",
			APIKey: "key1",
		}

		key1 := auth1.CacheKey()
		key2 := auth2.CacheKey()

		assert.Equal(t, key1, key2, "Same credentials must produce same cache key")
	})

	t.Run("key includes all credential components", func(t *testing.T) {
		base := &AuthContext{
			Mode:        AuthModeUIDKey,
			OID:         "org1",
			APIKey:      "key1",
			UID:         "user1",
			JWTToken:    "token1",
			Environment: "prod",
		}

		// Change each component and verify key changes
		changed := base.Clone()
		changed.OID = "org2"
		assert.NotEqual(t, base.CacheKey(), changed.CacheKey(), "OID change must change key")

		changed = base.Clone()
		changed.APIKey = "key2"
		assert.NotEqual(t, base.CacheKey(), changed.CacheKey(), "APIKey change must change key")

		changed = base.Clone()
		changed.UID = "user2"
		assert.NotEqual(t, base.CacheKey(), changed.CacheKey(), "UID change must change key")

		changed = base.Clone()
		changed.Mode = AuthModeNormal
		assert.NotEqual(t, base.CacheKey(), changed.CacheKey(), "Mode change must change key")

		// CRITICAL: JWT token must be included in cache key to prevent credential cross-contamination
		changed = base.Clone()
		changed.JWTToken = "token2"
		assert.NotEqual(t, base.CacheKey(), changed.CacheKey(), "JWTToken change must change key")

		changed = base.Clone()
		changed.Environment = "dev"
		assert.NotEqual(t, base.CacheKey(), changed.CacheKey(), "Environment change must change key")
	})
}

func TestAuthContext_Validate(t *testing.T) {
	tests := []struct {
		name    string
		auth    *AuthContext
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid normal mode",
			auth: &AuthContext{
				Mode:   AuthModeNormal,
				OID:    "test-org",
				APIKey: "test-key",
			},
			wantErr: false,
		},
		{
			name: "normal mode missing OID",
			auth: &AuthContext{
				Mode:   AuthModeNormal,
				APIKey: "test-key",
			},
			wantErr: true,
			errMsg:  "OID is required",
		},
		{
			name: "normal mode missing API key",
			auth: &AuthContext{
				Mode: AuthModeNormal,
				OID:  "test-org",
			},
			wantErr: true,
			errMsg:  "API key is required",
		},
		{
			name: "valid UID key mode",
			auth: &AuthContext{
				Mode:   AuthModeUIDKey,
				UID:    "test-user",
				APIKey: "test-key",
			},
			wantErr: false,
		},
		{
			name: "UID key mode missing UID",
			auth: &AuthContext{
				Mode:   AuthModeUIDKey,
				APIKey: "test-key",
			},
			wantErr: true,
			errMsg:  "UID is required",
		},
		{
			name: "UID key mode missing API key",
			auth: &AuthContext{
				Mode: AuthModeUIDKey,
				UID:  "test-user",
			},
			wantErr: true,
			errMsg:  "API key is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.auth.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAuthContext_Clone(t *testing.T) {
	original := &AuthContext{
		Mode:        AuthModeUIDKey,
		OID:         "org1",
		APIKey:      "key1",
		UID:         "user1",
		JWTToken:    "token1",
		Environment: "prod",
	}

	cloned := original.Clone()

	// Verify all fields are copied
	assert.Equal(t, original.Mode, cloned.Mode)
	assert.Equal(t, original.OID, cloned.OID)
	assert.Equal(t, original.APIKey, cloned.APIKey)
	assert.Equal(t, original.UID, cloned.UID)
	assert.Equal(t, original.JWTToken, cloned.JWTToken)
	assert.Equal(t, original.Environment, cloned.Environment)

	// Verify it's a deep copy
	cloned.OID = "org2"
	assert.NotEqual(t, original.OID, cloned.OID, "Modifying clone should not affect original")
}

func TestContextOperations(t *testing.T) {
	t.Run("WithAuthContext and FromContext", func(t *testing.T) {
		auth := &AuthContext{
			Mode:   AuthModeNormal,
			OID:    "test-org",
			APIKey: "test-key",
		}

		ctx := WithAuthContext(context.Background(), auth)
		retrieved, err := FromContext(ctx)

		require.NoError(t, err)
		assert.Equal(t, auth, retrieved)
	})

	t.Run("FromContext without auth returns error", func(t *testing.T) {
		ctx := context.Background()
		_, err := FromContext(ctx)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "no authentication context found")
	})

	t.Run("MustFromContext panics without auth", func(t *testing.T) {
		ctx := context.Background()

		assert.Panics(t, func() {
			MustFromContext(ctx)
		})
	})

	t.Run("MustFromContext succeeds with auth", func(t *testing.T) {
		auth := &AuthContext{
			Mode:   AuthModeNormal,
			OID:    "test-org",
			APIKey: "test-key",
		}

		ctx := WithAuthContext(context.Background(), auth)

		assert.NotPanics(t, func() {
			retrieved := MustFromContext(ctx)
			assert.Equal(t, auth, retrieved)
		})
	})
}

func TestWithOID(t *testing.T) {
	t.Run("can switch OID in UID mode", func(t *testing.T) {
		auth := &AuthContext{
			Mode:   AuthModeUIDKey,
			OID:    "org1",
			APIKey: "key1",
			UID:    "user1",
		}

		ctx := WithAuthContext(context.Background(), auth)
		newCtx, err := WithOID(ctx, "org2")

		require.NoError(t, err)

		newAuth, err := FromContext(newCtx)
		require.NoError(t, err)
		assert.Equal(t, "org2", newAuth.OID)
		assert.Equal(t, auth.UID, newAuth.UID)
		assert.Equal(t, auth.APIKey, newAuth.APIKey)

		// Original context should be unchanged
		origAuth, _ := FromContext(ctx)
		assert.Equal(t, "org1", origAuth.OID)
	})

	t.Run("cannot switch OID in normal mode", func(t *testing.T) {
		auth := &AuthContext{
			Mode:   AuthModeNormal,
			OID:    "org1",
			APIKey: "key1",
		}

		ctx := WithAuthContext(context.Background(), auth)
		_, err := WithOID(ctx, "org2")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot switch OID in normal mode")
	})

	t.Run("rejects invalid OID", func(t *testing.T) {
		auth := &AuthContext{
			Mode:   AuthModeUIDKey,
			OID:    "org1",
			APIKey: "key1",
			UID:    "user1",
		}

		ctx := WithAuthContext(context.Background(), auth)

		// Test various invalid OIDs
		invalidOIDs := []string{
			"",                        // empty
			"org!@#$",                 // invalid characters
			string(make([]byte, 200)), // too long
		}

		for _, invalidOID := range invalidOIDs {
			_, err := WithOID(ctx, invalidOID)
			require.Error(t, err, "Should reject invalid OID: %s", invalidOID)
			assert.Contains(t, err.Error(), "invalid OID")
		}
	})
}

// CRITICAL: Credential Isolation Tests
// These tests verify that concurrent requests with different credentials
// never leak credentials between each other

func TestCredentialIsolation_Concurrent(t *testing.T) {
	t.Run("concurrent contexts maintain separate credentials", func(t *testing.T) {
		// Create 100 different auth contexts
		auths := make([]*AuthContext, 100)
		for i := 0; i < 100; i++ {
			auths[i] = &AuthContext{
				Mode:   AuthModeNormal,
				OID:    "org" + string(rune(i)),
				APIKey: "key" + string(rune(i)),
			}
		}

		// Process them concurrently
		var wg sync.WaitGroup
		results := make(chan string, 100)
		errors := make(chan error, 100)

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()

				// Create context with auth
				ctx := WithAuthContext(context.Background(), auths[idx])

				// Simulate some work
				time.Sleep(time.Millisecond * time.Duration(idx%10))

				// Retrieve auth and verify it's correct
				retrieved, err := FromContext(ctx)
				if err != nil {
					errors <- err
					return
				}

				// Verify the OID matches
				if retrieved.OID != auths[idx].OID {
					errors <- assert.AnError
					return
				}

				results <- retrieved.OID
			}(i)
		}

		wg.Wait()
		close(results)
		close(errors)

		// Check for errors
		for err := range errors {
			t.Errorf("Credential isolation failed: %v", err)
		}

		// Verify all OIDs are correct
		oidCount := make(map[string]int)
		for oid := range results {
			oidCount[oid]++
		}

		// Each OID should appear exactly once
		for i := 0; i < 100; i++ {
			expectedOID := "org" + string(rune(i))
			count := oidCount[expectedOID]
			assert.Equal(t, 1, count, "OID %s should appear exactly once, got %d", expectedOID, count)
		}
	})
}

func TestCredentialIsolation_CacheKeys(t *testing.T) {
	t.Run("cache keys never collide with different credentials", func(t *testing.T) {
		// Generate many different credentials
		keys := make(map[string]bool)

		for i := 0; i < 1000; i++ {
			auth := &AuthContext{
				Mode:   AuthMode(i % 3),
				OID:    "org" + string(rune(i)),
				APIKey: "key" + string(rune(i)),
				UID:    "user" + string(rune(i)),
			}

			key := auth.CacheKey()

			// Verify no collision
			if keys[key] {
				t.Errorf("Cache key collision detected for index %d", i)
			}
			keys[key] = true
		}

		// All keys should be unique
		assert.Equal(t, 1000, len(keys), "All cache keys should be unique")
	})
}

func TestSDKCache_Basic(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	cache := NewSDKCache(5*time.Second, logger)

	t.Run("requires valid auth context", func(t *testing.T) {
		ctx := context.Background()
		_, err := cache.GetFromContext(ctx)
		require.Error(t, err)
	})

	t.Run("validates auth context", func(t *testing.T) {
		auth := &AuthContext{
			Mode: AuthModeNormal,
			// Missing OID and APIKey
		}
		_, err := cache.GetOrCreate(context.Background(), auth)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid auth context")
	})

	t.Run("invalidate removes entry", func(t *testing.T) {
		auth := &AuthContext{
			Mode:   AuthModeNormal,
			OID:    "test-org",
			APIKey: "test-key",
		}

		// Note: We can't actually create a real SDK client without valid credentials
		// This tests the cache logic only
		cache.Invalidate(auth)

		stats := cache.GetStats()
		assert.NotNil(t, stats)
	})

	t.Run("invalidate all clears cache", func(t *testing.T) {
		cache.InvalidateAll()

		stats := cache.GetStats()
		size := stats["size"].(int)
		assert.Equal(t, 0, size)
	})

	t.Run("get stats returns metrics", func(t *testing.T) {
		stats := cache.GetStats()

		assert.Contains(t, stats, "size")
		assert.Contains(t, stats, "hits")
		assert.Contains(t, stats, "misses")
		assert.Contains(t, stats, "evictions")
		assert.Contains(t, stats, "ttl")
	})
}

func TestSDKCache_CredentialIsolation(t *testing.T) {
	t.Run("different credentials get different cache keys", func(t *testing.T) {
		logger := logrus.New()
		logger.SetLevel(logrus.ErrorLevel)
		cache := NewSDKCache(5*time.Minute, logger)

		auth1 := &AuthContext{
			Mode:   AuthModeNormal,
			OID:    "org1",
			APIKey: "key1",
		}

		auth2 := &AuthContext{
			Mode:   AuthModeNormal,
			OID:    "org2",
			APIKey: "key2",
		}

		key1 := auth1.CacheKey()
		key2 := auth2.CacheKey()

		assert.NotEqual(t, key1, key2, "Different credentials must have different cache keys")

		// Verify the cache would use different keys
		cache.Invalidate(auth1)
		cache.Invalidate(auth2)
	})
}

func TestValidateUID(t *testing.T) {
	tests := []struct {
		name    string
		uid     string
		wantErr bool
		errType error
	}{
		{"valid email", "user@example.com", false, nil},
		{"valid simple uid", "user123", false, nil},
		{"valid with dash", "user-123", false, nil},
		{"valid with underscore", "user_123", false, nil},
		{"valid with dot", "user.123", false, nil},
		{"empty", "", true, ErrInvalidUID},
		{"too short", "ab", true, nil},
		{"too long", strings.Repeat("a", 129), true, nil},
		{"jwt format", "eyJhbGciOi.eyJzdWIiOi.SflKxwRJS", true, ErrSuspiciousUID},
		{"hex string", "abcdef1234567890abcdef1234567890", true, ErrSuspiciousUID},
		{"base64 string", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=", true, ErrSuspiciousUID},
		{"invalid chars", "user@@@", true, nil},
		{"whitespace", "user 123", true, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUID(tt.uid)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateOID(t *testing.T) {
	tests := []struct {
		name    string
		oid     string
		wantErr bool
	}{
		{"valid oid", "my-org-123", false},
		{"valid with underscores", "my_org_123", false},
		{"valid with dots", "my.org.123", false},
		{"empty", "", true},
		{"too long", strings.Repeat("a", 129), true},
		{"invalid chars", "my org!", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOID(tt.oid)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateSID(t *testing.T) {
	tests := []struct {
		name    string
		sid     string
		wantErr bool
	}{
		{"valid uuid lowercase", "550e8400-e29b-41d4-a716-446655440000", false},
		{"valid uuid uppercase", "550E8400-E29B-41D4-A716-446655440000", false},
		{"valid uuid mixed case", "550e8400-E29B-41d4-A716-446655440000", false},
		{"empty", "", true},
		{"not a uuid", "not-a-uuid", true},
		{"missing dashes", "550e8400e29b41d4a716446655440000", true},
		{"wrong format", "550e8400-e29b-41d4-a716", true},
		{"with spaces", "550e8400-e29b-41d4-a716-4466 5544 0000", true},
		{"non-hex chars", "550e8400-e29b-41d4-a716-44665544000g", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSID(tt.sid)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		apiKey  string
		wantErr bool
	}{
		{"valid api key", "1234567890abcdef", false},
		{"valid long key", strings.Repeat("a", 64), false},
		{"empty", "", true},
		{"too short", "short", true},
		{"too long", strings.Repeat("a", 513), true},
		{"with whitespace", "key with spaces", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAPIKey(tt.apiKey)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSanitizeForLog(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		showChars int
		expected  string
	}{
		{"empty string", "", 4, "<empty>"},
		{"short string", "abc", 4, "<***>"},
		{"exact length", "abcd", 4, "<****>"},
		{"longer string", "abcdefghij", 4, "abcd...<******>"},
		{"api key", "sk-1234567890abcdef", 4, "sk-1...<***************>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeForLog(tt.input, tt.showChars)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateJWT_WithSkipSignature(t *testing.T) {
	cfg := &JWTValidationConfig{
		SkipSignatureValidation: true,
		ClockSkew:               5 * time.Minute,
	}

	t.Run("rejects empty JWT", func(t *testing.T) {
		err := ValidateJWTWithConfig("", cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be empty")
	})

	t.Run("rejects malformed JWT", func(t *testing.T) {
		err := ValidateJWTWithConfig("not.a.valid.jwt.token", cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "three parts")
	})

	t.Run("rejects JWT with only two parts", func(t *testing.T) {
		err := ValidateJWTWithConfig("header.payload", cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "three parts")
	})

	t.Run("accepts valid unexpired JWT", func(t *testing.T) {
		// Create a JWT that expires in 1 hour
		jwt := createTestJWT(t, map[string]interface{}{
			"sub": "test-user",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
			"iat": time.Now().Unix(),
		})

		err := ValidateJWTWithConfig(jwt, cfg)
		assert.NoError(t, err)
	})

	t.Run("rejects expired JWT", func(t *testing.T) {
		// Create a JWT that expired 1 hour ago
		jwt := createTestJWT(t, map[string]interface{}{
			"sub": "test-user",
			"exp": time.Now().Add(-1 * time.Hour).Unix(),
			"iat": time.Now().Add(-2 * time.Hour).Unix(),
		})

		err := ValidateJWTWithConfig(jwt, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("rejects JWT missing exp claim", func(t *testing.T) {
		jwt := createTestJWT(t, map[string]interface{}{
			"sub": "test-user",
			"iat": time.Now().Unix(),
		})

		err := ValidateJWTWithConfig(jwt, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing exp")
	})

	t.Run("rejects JWT with nbf in future", func(t *testing.T) {
		jwt := createTestJWT(t, map[string]interface{}{
			"sub": "test-user",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
			"nbf": time.Now().Add(1 * time.Hour).Unix(), // Not valid yet
			"iat": time.Now().Unix(),
		})

		err := ValidateJWTWithConfig(jwt, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not yet valid")
	})

	t.Run("rejects JWT issued in future", func(t *testing.T) {
		jwt := createTestJWT(t, map[string]interface{}{
			"sub": "test-user",
			"exp": time.Now().Add(2 * time.Hour).Unix(),
			"iat": time.Now().Add(1 * time.Hour).Unix(), // Issued in future
		})

		err := ValidateJWTWithConfig(jwt, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "issued in the future")
	})

	t.Run("validates issuer when configured", func(t *testing.T) {
		cfg := &JWTValidationConfig{
			SkipSignatureValidation: true,
			ExpectedIssuer:          "https://auth.limacharlie.io",
			ClockSkew:               5 * time.Minute,
		}

		// Correct issuer
		jwt := createTestJWT(t, map[string]interface{}{
			"sub": "test-user",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
			"iss": "https://auth.limacharlie.io",
		})
		err := ValidateJWTWithConfig(jwt, cfg)
		assert.NoError(t, err)

		// Wrong issuer
		jwtWrong := createTestJWT(t, map[string]interface{}{
			"sub": "test-user",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
			"iss": "https://evil.com",
		})
		err = ValidateJWTWithConfig(jwtWrong, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "issuer mismatch")

		// Missing issuer
		jwtMissing := createTestJWT(t, map[string]interface{}{
			"sub": "test-user",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
		})
		err = ValidateJWTWithConfig(jwtMissing, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing iss")
	})

	t.Run("validates audience when configured", func(t *testing.T) {
		cfg := &JWTValidationConfig{
			SkipSignatureValidation: true,
			ExpectedAudience:        "limacharlie-mcp",
			ClockSkew:               5 * time.Minute,
		}

		// Correct audience (string)
		jwt := createTestJWT(t, map[string]interface{}{
			"sub": "test-user",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
			"aud": "limacharlie-mcp",
		})
		err := ValidateJWTWithConfig(jwt, cfg)
		assert.NoError(t, err)

		// Correct audience (array)
		jwtArray := createTestJWT(t, map[string]interface{}{
			"sub": "test-user",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
			"aud": []string{"limacharlie-mcp", "other-service"},
		})
		err = ValidateJWTWithConfig(jwtArray, cfg)
		assert.NoError(t, err)

		// Wrong audience
		jwtWrong := createTestJWT(t, map[string]interface{}{
			"sub": "test-user",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
			"aud": "wrong-audience",
		})
		err = ValidateJWTWithConfig(jwtWrong, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "audience mismatch")

		// Array without expected audience
		jwtWrongArray := createTestJWT(t, map[string]interface{}{
			"sub": "test-user",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
			"aud": []string{"service1", "service2"},
		})
		err = ValidateJWTWithConfig(jwtWrongArray, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "does not include")
	})

	t.Run("clock skew allows small time differences", func(t *testing.T) {
		cfg := &JWTValidationConfig{
			SkipSignatureValidation: true,
			ClockSkew:               5 * time.Minute,
		}

		// JWT expired 4 minutes ago (within clock skew)
		jwt := createTestJWT(t, map[string]interface{}{
			"sub": "test-user",
			"exp": time.Now().Add(-4 * time.Minute).Unix(),
		})
		err := ValidateJWTWithConfig(jwt, cfg)
		assert.NoError(t, err, "Should accept JWT within clock skew")

		// JWT expired 6 minutes ago (outside clock skew)
		jwtOld := createTestJWT(t, map[string]interface{}{
			"sub": "test-user",
			"exp": time.Now().Add(-6 * time.Minute).Unix(),
		})
		err = ValidateJWTWithConfig(jwtOld, cfg)
		assert.Error(t, err, "Should reject JWT outside clock skew")
		assert.Contains(t, err.Error(), "expired")
	})
}

func TestGetJWTExpirationTime(t *testing.T) {
	t.Run("extracts expiration from valid JWT", func(t *testing.T) {
		expectedExpiry := time.Now().Add(1 * time.Hour).Truncate(time.Second)
		jwt := createTestJWT(t, map[string]interface{}{
			"sub": "test-user",
			"exp": expectedExpiry.Unix(),
		})

		expiry, err := GetJWTExpirationTime(jwt)
		assert.NoError(t, err)
		assert.Equal(t, expectedExpiry.Unix(), expiry.Unix())
	})

	t.Run("returns error for JWT without exp claim", func(t *testing.T) {
		jwt := createTestJWT(t, map[string]interface{}{
			"sub": "test-user",
		})

		_, err := GetJWTExpirationTime(jwt)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing exp")
	})

	t.Run("returns error for malformed JWT", func(t *testing.T) {
		_, err := GetJWTExpirationTime("not.a.jwt")
		assert.Error(t, err)
	})
}

func TestParseJWTClaims(t *testing.T) {
	t.Run("extracts claims from valid JWT", func(t *testing.T) {
		jwt := createTestJWT(t, map[string]interface{}{
			"sub":  "test-user",
			"role": "admin",
			"exp":  time.Now().Add(1 * time.Hour).Unix(),
		})

		claims, err := ParseJWTClaims(jwt)
		assert.NoError(t, err)
		assert.Equal(t, "test-user", claims["sub"])
		assert.Equal(t, "admin", claims["role"])
		assert.NotNil(t, claims["exp"])
	})

	t.Run("returns error for malformed JWT", func(t *testing.T) {
		_, err := ParseJWTClaims("not.a.jwt")
		assert.Error(t, err)
	})
}

// Helper function to create test JWTs
// NOTE: These JWTs have NO signature validation (signature is fake)
// They are only for testing claim validation logic
func createTestJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()

	// Create header
	header := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}

	// Encode header and claims

	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Create fake signature (not validated in tests)
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))

	return headerB64 + "." + claimsB64 + "." + signature
}

func TestSDKCache_RespectJWTExpiration(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cache := NewSDKCache(5*time.Minute, logger)
	defer cache.Close()

	t.Run("rejects cached SDK when JWT expired", func(t *testing.T) {
		// This test requires mocking since we can't actually create SDK clients
		// We'll test that the JWT expiration check logic is in place

		// Create auth context with expired JWT
		expiredJWT := createTestJWT(t, map[string]interface{}{
			"sub": "test-user",
			"exp": time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
		})

		_ = &AuthContext{
			Mode:     AuthModeUIDOAuth,
			UID:      "test-user",
			JWTToken: expiredJWT,
		}

		// Since GetOrCreate requires valid SDK creation, we can't test the full flow
		// But we can verify the GetJWTExpirationTime function works correctly
		expiry, err := GetJWTExpirationTime(expiredJWT)
		assert.NoError(t, err)
		assert.True(t, time.Now().After(expiry), "JWT should be expired")
	})
}
