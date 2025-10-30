package server

import (
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Import tools to register them
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/core"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/historical"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/investigation"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/response"
)

func TestNew(t *testing.T) {
	t.Run("creates server successfully", func(t *testing.T) {
		cfg := &config.Config{
			Mode:        "stdio",
			Profile:     "core",
			LogLevel:    "info",
			SDKCacheTTL: 5 * time.Minute,
			Auth: &auth.AuthContext{
				Mode:   auth.AuthModeNormal,
				OID:    "test-org",
				APIKey: "test-key-1234567890",
			},
		}

		logger := logrus.New()
		logger.SetLevel(logrus.ErrorLevel)

		srv, err := New(cfg, logger)

		require.NoError(t, err)
		assert.NotNil(t, srv)
		assert.NotNil(t, srv.mcpServer)
		assert.NotNil(t, srv.sdkCache)
		assert.Equal(t, cfg, srv.config)
	})

	t.Run("creates server with nil logger", func(t *testing.T) {
		cfg := &config.Config{
			Mode:        "stdio",
			Profile:     "core",
			LogLevel:    "info",
			SDKCacheTTL: 5 * time.Minute,
			Auth: &auth.AuthContext{
				Mode:   auth.AuthModeNormal,
				OID:    "test-org",
				APIKey: "test-key-1234567890",
			},
		}

		srv, err := New(cfg, nil)

		require.NoError(t, err)
		assert.NotNil(t, srv)
		assert.NotNil(t, srv.logger)
	})

	t.Run("registers tools for profile", func(t *testing.T) {
		cfg := &config.Config{
			Mode:        "stdio",
			Profile:     "core",
			LogLevel:    "info",
			SDKCacheTTL: 5 * time.Minute,
			Auth: &auth.AuthContext{
				Mode:   auth.AuthModeNormal,
				OID:    "test-org",
				APIKey: "test-key-1234567890",
			},
		}

		logger := logrus.New()
		logger.SetLevel(logrus.ErrorLevel)

		srv, err := New(cfg, logger)

		require.NoError(t, err)
		assert.NotNil(t, srv)
		// Tools should be registered (we can't easily verify this without exposing internals)
	})
}

func TestGetters(t *testing.T) {
	cfg := &config.Config{
		Mode:        "stdio",
		Profile:     "core",
		LogLevel:    "info",
		SDKCacheTTL: 5 * time.Minute,
		Auth: &auth.AuthContext{
			Mode:   auth.AuthModeNormal,
			OID:    "test-org",
			APIKey: "test-key-1234567890",
		},
	}

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	srv, err := New(cfg, logger)
	require.NoError(t, err)

	t.Run("GetSDKCache", func(t *testing.T) {
		cache := srv.GetSDKCache()
		assert.NotNil(t, cache)
	})

	t.Run("GetLogger", func(t *testing.T) {
		log := srv.GetLogger()
		assert.NotNil(t, log)
		assert.Equal(t, logger, log)
	})
}

func TestServerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Run("server lifecycle", func(t *testing.T) {
		cfg := &config.Config{
			Mode:        "stdio",
			Profile:     "core",
			LogLevel:    "error",
			SDKCacheTTL: 5 * time.Minute,
			Auth: &auth.AuthContext{
				Mode:   auth.AuthModeNormal,
				OID:    "test-org",
				APIKey: "test-key-1234567890",
			},
		}

		logger := logrus.New()
		logger.SetLevel(logrus.ErrorLevel)

		srv, err := New(cfg, logger)
		require.NoError(t, err)

		// Note: We can't actually call Serve() in a test as it blocks on stdio
		// Just verify the server was created successfully
		assert.NotNil(t, srv)
	})
}
