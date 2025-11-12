package state

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/refractionpoint/lc-mcp-go/internal/crypto"
	"github.com/refractionpoint/lc-mcp-go/internal/redis"
	"github.com/stretchr/testify/require"
)

// Helper to create test logger
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Helper to generate valid encryption key
func generateEncryptionKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(key)
}

// Helper to setup test manager with Redis and encryption
func setupTestManager(t *testing.T) (*Manager, *miniredis.Miniredis) {
	t.Helper()

	// Setup miniredis
	mr := miniredis.RunT(t)

	// Setup Redis client
	redisClient, err := redis.New(&redis.Config{
		URL: "redis://" + mr.Addr(),
	}, testLogger())
	require.NoError(t, err)

	// Setup encryption
	os.Setenv("REDIS_ENCRYPTION_KEY", generateEncryptionKey(t))
	defer os.Unsetenv("REDIS_ENCRYPTION_KEY")

	encryption, err := crypto.NewTokenEncryption(testLogger())
	require.NoError(t, err)

	// Create manager
	manager := NewManager(redisClient, encryption, testLogger())
	require.NotNil(t, manager)

	return manager, mr
}
