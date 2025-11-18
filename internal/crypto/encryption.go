package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"log/slog"
)

const (
	// KeySize is the required size for AES-256
	KeySize = 32 // 256 bits

	// NonceSize is the recommended size for GCM mode
	NonceSize = 12 // 96 bits
)

var (
	ErrInvalidKeySize     = errors.New("encryption key must be 32 bytes (256 bits)")
	ErrInvalidCiphertext  = errors.New("ciphertext is too short or invalid")
	ErrEncryptionDisabled = errors.New("encryption is disabled")
	ErrEncryptionFailed   = errors.New("encryption failed")
	ErrDecryptionFailed   = errors.New("decryption failed")
)

// TokenEncryption handles AES-256-GCM encryption/decryption for tokens
type TokenEncryption struct {
	gcm     cipher.AEAD
	enabled bool
	logger  *slog.Logger
}

// NewTokenEncryption creates a new token encryption instance
// SECURITY FIX: Encryption is now MANDATORY - returns error if REDIS_ENCRYPTION_KEY not set
func NewTokenEncryption(logger *slog.Logger) (*TokenEncryption, error) {
	// Get encryption key from environment
	keyB64 := os.Getenv("REDIS_ENCRYPTION_KEY")

	if keyB64 == "" {
		// SECURITY FIX: Return error instead of continuing without encryption
		return nil, fmt.Errorf("REDIS_ENCRYPTION_KEY environment variable is required for security (must be base64-encoded 32-byte key). Generate with: openssl rand -base64 32")
	}

	// Decode base64 key
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid REDIS_ENCRYPTION_KEY (must be base64): %w", err)
	}

	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: got %d bytes, need %d bytes", ErrInvalidKeySize, len(key), KeySize)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM (Galois/Counter Mode) for authenticated encryption
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	logger.Info("Token encryption ENABLED with AES-256-GCM")

	return &TokenEncryption{
		gcm:     gcm,
		enabled: true,
		logger:  logger,
	}, nil
}

// IsEnabled returns whether encryption is enabled
func (te *TokenEncryption) IsEnabled() bool {
	return te.enabled
}

// Encrypt encrypts a plaintext token
// Returns base64-encoded ciphertext with format: base64(nonce || ciphertext || tag)
// SECURITY FIX: Encryption is always enabled - no bypass allowed
func (te *TokenEncryption) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	// Generate random nonce (MUST be unique per encryption)
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("%w: failed to generate nonce: %v", ErrEncryptionFailed, err)
	}

	// Encrypt and authenticate
	// GCM appends authentication tag automatically
	ciphertext := te.gcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Combine nonce + ciphertext + tag
	combined := make([]byte, len(nonce)+len(ciphertext))
	copy(combined, nonce)
	copy(combined[len(nonce):], ciphertext)

	// Encode as base64 for Redis storage
	encoded := base64.StdEncoding.EncodeToString(combined)

	return encoded, nil
}

// Decrypt decrypts a base64-encoded ciphertext
// SECURITY FIX: Encryption is always enabled - no bypass allowed
func (te *TokenEncryption) Decrypt(ciphertextB64 string) (string, error) {
	if ciphertextB64 == "" {
		return "", nil
	}

	// Decode base64
	combined, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("%w: base64 decode failed: %v", ErrDecryptionFailed, err)
	}

	// Extract nonce and ciphertext
	if len(combined) < NonceSize {
		return "", fmt.Errorf("%w: data too short", ErrInvalidCiphertext)
	}

	nonce := combined[:NonceSize]
	ciphertext := combined[NonceSize:]

	// Decrypt and verify authentication tag
	plaintext, err := te.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return string(plaintext), nil
}

// EncryptIfEnabled encrypts only if encryption is enabled (helper for optional fields)
func (te *TokenEncryption) EncryptIfEnabled(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	return te.Encrypt(plaintext)
}

// DecryptIfEnabled decrypts only if encryption is enabled (helper for optional fields)
func (te *TokenEncryption) DecryptIfEnabled(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	return te.Decrypt(ciphertext)
}

// GenerateKey generates a random 256-bit encryption key
// This is a utility function for generating new keys
func GenerateKey() (string, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", fmt.Errorf("failed to generate key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(key), nil
}
