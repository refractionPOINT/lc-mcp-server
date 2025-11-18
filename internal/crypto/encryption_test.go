package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to create test logger
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Helper to generate valid test key
func generateTestKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, KeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(key)
}

// TestNewTokenEncryption tests token encryption initialization
func TestNewTokenEncryption(t *testing.T) {
	t.Run("requires encryption key", func(t *testing.T) {
		// Ensure no key is set
		os.Unsetenv("REDIS_ENCRYPTION_KEY")

		te, err := NewTokenEncryption(testLogger())

		assert.Error(t, err)
		assert.Nil(t, te)
		assert.Contains(t, err.Error(), "REDIS_ENCRYPTION_KEY")
		assert.Contains(t, err.Error(), "required")
	})

	t.Run("rejects invalid base64 key", func(t *testing.T) {
		os.Setenv("REDIS_ENCRYPTION_KEY", "not-valid-base64!@#$")
		defer os.Unsetenv("REDIS_ENCRYPTION_KEY")

		te, err := NewTokenEncryption(testLogger())

		assert.Error(t, err)
		assert.Nil(t, te)
		assert.Contains(t, err.Error(), "base64")
	})

	t.Run("rejects key with wrong size", func(t *testing.T) {
		// 16 bytes (AES-128) instead of 32 bytes (AES-256)
		wrongSizeKey := make([]byte, 16)
		_, err := rand.Read(wrongSizeKey)
		require.NoError(t, err)

		os.Setenv("REDIS_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(wrongSizeKey))
		defer os.Unsetenv("REDIS_ENCRYPTION_KEY")

		te, err := NewTokenEncryption(testLogger())

		assert.Error(t, err)
		assert.Nil(t, te)
		assert.ErrorIs(t, err, ErrInvalidKeySize)
	})

	t.Run("accepts valid 256-bit key", func(t *testing.T) {
		validKey := generateTestKey(t)
		os.Setenv("REDIS_ENCRYPTION_KEY", validKey)
		defer os.Unsetenv("REDIS_ENCRYPTION_KEY")

		te, err := NewTokenEncryption(testLogger())

		assert.NoError(t, err)
		require.NotNil(t, te)
		assert.True(t, te.IsEnabled())
	})
}

// TestEncryptDecrypt tests basic encryption and decryption
func TestEncryptDecrypt(t *testing.T) {
	// Setup encryption
	os.Setenv("REDIS_ENCRYPTION_KEY", generateTestKey(t))
	defer os.Unsetenv("REDIS_ENCRYPTION_KEY")

	te, err := NewTokenEncryption(testLogger())
	require.NoError(t, err)
	require.NotNil(t, te)

	testCases := []struct {
		name      string
		plaintext string
	}{
		{"short string", "hello"},
		{"long string", strings.Repeat("a", 1000)},
		{"unicode", "Hello 世界 🔒"},
		{"special chars", "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"},
		{"jwt-like", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"},
		{"newlines", "line1\nline2\r\nline3"},
		{"spaces", "   leading and trailing   "},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := te.Encrypt(tc.plaintext)
			require.NoError(t, err)
			assert.NotEmpty(t, ciphertext)
			assert.NotEqual(t, tc.plaintext, ciphertext)

			// Verify it's base64
			_, err = base64.StdEncoding.DecodeString(ciphertext)
			assert.NoError(t, err)

			// Decrypt
			decrypted, err := te.Decrypt(ciphertext)
			require.NoError(t, err)
			assert.Equal(t, tc.plaintext, decrypted)
		})
	}
}

// TestEmptyStringHandling tests handling of empty strings
func TestEmptyStringHandling(t *testing.T) {
	os.Setenv("REDIS_ENCRYPTION_KEY", generateTestKey(t))
	defer os.Unsetenv("REDIS_ENCRYPTION_KEY")

	te, err := NewTokenEncryption(testLogger())
	require.NoError(t, err)

	t.Run("encrypt empty string", func(t *testing.T) {
		ciphertext, err := te.Encrypt("")
		assert.NoError(t, err)
		assert.Empty(t, ciphertext)
	})

	t.Run("decrypt empty string", func(t *testing.T) {
		plaintext, err := te.Decrypt("")
		assert.NoError(t, err)
		assert.Empty(t, plaintext)
	})
}

// TestNonceUniqueness verifies that each encryption uses a unique nonce
// SECURITY: Reusing nonces in GCM mode is catastrophic for security
func TestNonceUniqueness(t *testing.T) {
	os.Setenv("REDIS_ENCRYPTION_KEY", generateTestKey(t))
	defer os.Unsetenv("REDIS_ENCRYPTION_KEY")

	te, err := NewTokenEncryption(testLogger())
	require.NoError(t, err)

	plaintext := "test data"
	ciphertexts := make(map[string]bool)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		ciphertext, err := te.Encrypt(plaintext)
		require.NoError(t, err)

		// Each ciphertext should be unique due to unique nonces
		if ciphertexts[ciphertext] {
			t.Fatalf("Duplicate ciphertext detected at iteration %d - nonce reuse!", i)
		}
		ciphertexts[ciphertext] = true
	}

	assert.Equal(t, iterations, len(ciphertexts), "All ciphertexts should be unique")
}

// TestAuthenticationTag verifies that tampering is detected
// SECURITY: GCM provides authenticated encryption
func TestAuthenticationTag(t *testing.T) {
	os.Setenv("REDIS_ENCRYPTION_KEY", generateTestKey(t))
	defer os.Unsetenv("REDIS_ENCRYPTION_KEY")

	te, err := NewTokenEncryption(testLogger())
	require.NoError(t, err)

	plaintext := "sensitive data"
	ciphertext, err := te.Encrypt(plaintext)
	require.NoError(t, err)

	// Decode to manipulate
	combined, err := base64.StdEncoding.DecodeString(ciphertext)
	require.NoError(t, err)

	t.Run("tampered ciphertext rejected", func(t *testing.T) {
		// Flip a bit in the ciphertext portion (after nonce)
		tampered := make([]byte, len(combined))
		copy(tampered, combined)
		tampered[NonceSize+5] ^= 0x01 // Flip one bit

		tamperedB64 := base64.StdEncoding.EncodeToString(tampered)

		_, err := te.Decrypt(tamperedB64)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrDecryptionFailed)
	})

	t.Run("tampered nonce rejected", func(t *testing.T) {
		// Flip a bit in the nonce
		tampered := make([]byte, len(combined))
		copy(tampered, combined)
		tampered[5] ^= 0x01 // Flip bit in nonce

		tamperedB64 := base64.StdEncoding.EncodeToString(tampered)

		_, err := te.Decrypt(tamperedB64)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrDecryptionFailed)
	})

	t.Run("truncated ciphertext rejected", func(t *testing.T) {
		// Remove last bytes (part of auth tag)
		truncated := combined[:len(combined)-5]
		truncatedB64 := base64.StdEncoding.EncodeToString(truncated)

		_, err := te.Decrypt(truncatedB64)
		assert.Error(t, err)
	})

	t.Run("too short data rejected", func(t *testing.T) {
		short := []byte{1, 2, 3}
		shortB64 := base64.StdEncoding.EncodeToString(short)

		_, err := te.Decrypt(shortB64)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidCiphertext)
	})
}

// TestDecryptInvalidInput tests decryption error handling
func TestDecryptInvalidInput(t *testing.T) {
	os.Setenv("REDIS_ENCRYPTION_KEY", generateTestKey(t))
	defer os.Unsetenv("REDIS_ENCRYPTION_KEY")

	te, err := NewTokenEncryption(testLogger())
	require.NoError(t, err)

	t.Run("invalid base64", func(t *testing.T) {
		_, err := te.Decrypt("not-valid-base64!@#$")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrDecryptionFailed)
	})

	t.Run("random data", func(t *testing.T) {
		randomBytes := make([]byte, 100)
		_, err := rand.Read(randomBytes)
		require.NoError(t, err)

		randomB64 := base64.StdEncoding.EncodeToString(randomBytes)
		_, err = te.Decrypt(randomB64)
		assert.Error(t, err)
	})

	t.Run("valid base64 but wrong key", func(t *testing.T) {
		// Encrypt with one key
		ciphertext, err := te.Encrypt("test")
		require.NoError(t, err)

		// Create new encryption with different key
		os.Setenv("REDIS_ENCRYPTION_KEY", generateTestKey(t))
		te2, err := NewTokenEncryption(testLogger())
		require.NoError(t, err)

		// Try to decrypt with different key
		_, err = te2.Decrypt(ciphertext)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrDecryptionFailed)
	})
}

// TestConcurrentEncryption tests thread safety
// SECURITY: Concurrent encryption should be safe and produce unique nonces
func TestConcurrentEncryption(t *testing.T) {
	os.Setenv("REDIS_ENCRYPTION_KEY", generateTestKey(t))
	defer os.Unsetenv("REDIS_ENCRYPTION_KEY")

	te, err := NewTokenEncryption(testLogger())
	require.NoError(t, err)

	const goroutines = 100
	const iterations = 10

	var wg sync.WaitGroup
	errors := make(chan error, goroutines*iterations)
	ciphertexts := make(chan string, goroutines*iterations)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				plaintext := "concurrent test"
				ciphertext, err := te.Encrypt(plaintext)
				if err != nil {
					errors <- err
					return
				}
				ciphertexts <- ciphertext

				// Verify decryption
				decrypted, err := te.Decrypt(ciphertext)
				if err != nil {
					errors <- err
					return
				}
				if decrypted != plaintext {
					errors <- assert.AnError
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)
	close(ciphertexts)

	// Check for errors
	var errorList []error
	for err := range errors {
		errorList = append(errorList, err)
	}
	assert.Empty(t, errorList, "No errors should occur during concurrent encryption")

	// Verify all ciphertexts are unique (nonce uniqueness)
	uniqueCiphertexts := make(map[string]bool)
	for ct := range ciphertexts {
		if uniqueCiphertexts[ct] {
			t.Error("Duplicate ciphertext detected in concurrent test - nonce collision!")
		}
		uniqueCiphertexts[ct] = true
	}
}

// TestGenerateKey tests key generation utility
func TestGenerateKey(t *testing.T) {
	t.Run("generates valid key", func(t *testing.T) {
		key, err := GenerateKey()
		require.NoError(t, err)
		assert.NotEmpty(t, key)

		// Decode and verify size
		decoded, err := base64.StdEncoding.DecodeString(key)
		require.NoError(t, err)
		assert.Equal(t, KeySize, len(decoded))

		// Verify it works with encryption
		os.Setenv("REDIS_ENCRYPTION_KEY", key)
		defer os.Unsetenv("REDIS_ENCRYPTION_KEY")

		te, err := NewTokenEncryption(testLogger())
		assert.NoError(t, err)
		assert.NotNil(t, te)
	})

	t.Run("generates unique keys", func(t *testing.T) {
		keys := make(map[string]bool)
		for i := 0; i < 100; i++ {
			key, err := GenerateKey()
			require.NoError(t, err)

			if keys[key] {
				t.Fatal("Duplicate key generated")
			}
			keys[key] = true
		}
	})
}

// TestEncryptIfEnabled tests optional encryption helper
func TestEncryptIfEnabled(t *testing.T) {
	os.Setenv("REDIS_ENCRYPTION_KEY", generateTestKey(t))
	defer os.Unsetenv("REDIS_ENCRYPTION_KEY")

	te, err := NewTokenEncryption(testLogger())
	require.NoError(t, err)

	t.Run("encrypts non-empty", func(t *testing.T) {
		ciphertext, err := te.EncryptIfEnabled("test")
		assert.NoError(t, err)
		assert.NotEmpty(t, ciphertext)
		assert.NotEqual(t, "test", ciphertext)
	})

	t.Run("returns empty for empty", func(t *testing.T) {
		ciphertext, err := te.EncryptIfEnabled("")
		assert.NoError(t, err)
		assert.Empty(t, ciphertext)
	})
}

// TestDecryptIfEnabled tests optional decryption helper
func TestDecryptIfEnabled(t *testing.T) {
	os.Setenv("REDIS_ENCRYPTION_KEY", generateTestKey(t))
	defer os.Unsetenv("REDIS_ENCRYPTION_KEY")

	te, err := NewTokenEncryption(testLogger())
	require.NoError(t, err)

	t.Run("decrypts non-empty", func(t *testing.T) {
		ciphertext, err := te.Encrypt("test")
		require.NoError(t, err)

		plaintext, err := te.DecryptIfEnabled(ciphertext)
		assert.NoError(t, err)
		assert.Equal(t, "test", plaintext)
	})

	t.Run("returns empty for empty", func(t *testing.T) {
		plaintext, err := te.DecryptIfEnabled("")
		assert.NoError(t, err)
		assert.Empty(t, plaintext)
	})
}

// TestRoundTripLargeData tests encryption/decryption of large payloads
func TestRoundTripLargeData(t *testing.T) {
	os.Setenv("REDIS_ENCRYPTION_KEY", generateTestKey(t))
	defer os.Unsetenv("REDIS_ENCRYPTION_KEY")

	te, err := NewTokenEncryption(testLogger())
	require.NoError(t, err)

	sizes := []int{100, 1024, 10240, 65536}

	for _, size := range sizes {
		t.Run(string(rune(size))+" bytes", func(t *testing.T) {
			plaintext := strings.Repeat("x", size)

			ciphertext, err := te.Encrypt(plaintext)
			require.NoError(t, err)

			decrypted, err := te.Decrypt(ciphertext)
			require.NoError(t, err)

			assert.Equal(t, plaintext, decrypted)
		})
	}
}

// TestKeyConstants verifies cryptographic constants
func TestKeyConstants(t *testing.T) {
	t.Run("key size is 256 bits", func(t *testing.T) {
		assert.Equal(t, 32, KeySize, "AES-256 requires 32 bytes")
	})

	t.Run("nonce size is 96 bits", func(t *testing.T) {
		assert.Equal(t, 12, NonceSize, "GCM standard nonce is 12 bytes")
	})
}

// TestErrorConstants verifies error definitions
func TestErrorConstants(t *testing.T) {
	assert.NotNil(t, ErrInvalidKeySize)
	assert.NotNil(t, ErrInvalidCiphertext)
	assert.NotNil(t, ErrEncryptionDisabled)
	assert.NotNil(t, ErrEncryptionFailed)
	assert.NotNil(t, ErrDecryptionFailed)
}
