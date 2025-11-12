package token

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/refractionpoint/lc-mcp-go/internal/crypto"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/refractionpoint/lc-mcp-go/internal/redis"
	"github.com/stretchr/testify/require"
)

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
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	redisClient, err := redis.New(&redis.Config{
		URL: "redis://" + mr.Addr(),
	}, logger)
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

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	encryption, err := crypto.NewTokenEncryption(logger)
	require.NoError(t, err)

	return encryption
}

// setupTestStateManager sets up a state manager for testing
func setupTestStateManager(t *testing.T) (*state.Manager, *miniredis.Miniredis) {
	t.Helper()

	redisClient, mr := setupTestRedis(t)
	encryption := setupTestEncryption(t)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := state.NewManager(redisClient, encryption, logger)
	require.NotNil(t, manager)

	return manager, mr
}
