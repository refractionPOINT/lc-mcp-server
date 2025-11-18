package server

import (
	"io"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"

	// Import tools to register them
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/core"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/historical"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/investigation"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/response"
)

func TestNew(t *testing.T) {
	t.Run("creates STDIO server successfully", func(t *testing.T) {
		cfg := &config.Config{
			Server: config.ServerConfig{
				Mode:     "stdio",
				Profile:  "core",
				LogLevel: "info",
			},
			Features: config.FeatureConfig{
				SDKCacheTTL: 5 * time.Minute,
			},
			Auth: &auth.AuthContext{
				Mode:   auth.AuthModeNormal,
				OID:    "test-org",
				APIKey: "test-key-1234567890",
			},
		}

		logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

		srv, err := New(cfg, logger)

		require.NoError(t, err)
		assert.NotNil(t, srv)

		// Verify it's a STDIO server
		stdioSrv, ok := srv.(*STDIOServer)
		assert.True(t, ok, "expected STDIOServer type")
		if ok {
			assert.NotNil(t, stdioSrv.mcpServer)
			assert.NotNil(t, stdioSrv.sdkCache)
			assert.Equal(t, cfg, stdioSrv.config)
		}
	})

	t.Run("creates HTTP server successfully", func(t *testing.T) {
		cfg := &config.Config{
			Server: config.ServerConfig{
				Mode:     "http",
				Profile:  "core",
				LogLevel: "info",
			},
			HTTP: config.HTTPConfig{
				Port: 8080,
			},
			OAuth: config.OAuthConfig{
				RedisURL: "redis://localhost:6379",
			},
			Features: config.FeatureConfig{
				SDKCacheTTL: 5 * time.Minute,
			},
			Auth: &auth.AuthContext{
				Mode:   auth.AuthModeNormal,
				OID:    "test-org",
				APIKey: "test-key-1234567890",
			},
		}

		logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

		// Note: This will fail if Redis is not available, which is expected in unit tests
		// We're just testing that the factory pattern works
		srv, err := New(cfg, logger)

		// If Redis is not available, we expect an error
		if err != nil {
			assert.Contains(t, err.Error(), "Redis", "expected Redis connection error")
			return
		}

		// If Redis is available, verify it's an HTTP server
		assert.NotNil(t, srv)
		httpSrv, ok := srv.(*HTTPServerWrapper)
		assert.True(t, ok, "expected HTTPServerWrapper type")
		if ok {
			assert.NotNil(t, httpSrv.httpServer)
		}
	})

	t.Run("creates server with nil logger", func(t *testing.T) {
		cfg := &config.Config{
			Server: config.ServerConfig{
				Mode:     "stdio",
				Profile:  "core",
				LogLevel: "info",
			},
			Features: config.FeatureConfig{
				SDKCacheTTL: 5 * time.Minute,
			},
			Auth: &auth.AuthContext{
				Mode:   auth.AuthModeNormal,
				OID:    "test-org",
				APIKey: "test-key-1234567890",
			},
		}

		srv, err := New(cfg, nil)

		require.NoError(t, err)
		assert.NotNil(t, srv)

		// Verify logger was created
		stdioSrv, ok := srv.(*STDIOServer)
		assert.True(t, ok)
		if ok {
			assert.NotNil(t, stdioSrv.logger)
		}
	})

	t.Run("registers tools for profile", func(t *testing.T) {
		cfg := &config.Config{
			Server: config.ServerConfig{
				Mode:     "stdio",
				Profile:  "core",
				LogLevel: "info",
			},
			Features: config.FeatureConfig{
				SDKCacheTTL: 5 * time.Minute,
			},
			Auth: &auth.AuthContext{
				Mode:   auth.AuthModeNormal,
				OID:    "test-org",
				APIKey: "test-key-1234567890",
			},
		}

		logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

		srv, err := New(cfg, logger)

		require.NoError(t, err)
		assert.NotNil(t, srv)
		// Tools should be registered (we can't easily verify this without exposing internals)
	})

	t.Run("returns error for unknown mode", func(t *testing.T) {
		cfg := &config.Config{
			Server: config.ServerConfig{
				Mode:     "unknown",
				Profile:  "core",
				LogLevel: "info",
			},
			Features: config.FeatureConfig{
				SDKCacheTTL: 5 * time.Minute,
			},
			Auth: &auth.AuthContext{
				Mode:   auth.AuthModeNormal,
				OID:    "test-org",
				APIKey: "test-key-1234567890",
			},
		}

		logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

		srv, err := New(cfg, logger)

		assert.Error(t, err)
		assert.Nil(t, srv)
		assert.Contains(t, err.Error(), "unknown server mode")
	})
}

func TestSTDIOServerImplementation(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:     "stdio",
			Profile:  "core",
			LogLevel: "info",
		},
		Features: config.FeatureConfig{
			SDKCacheTTL: 5 * time.Minute,
		},
		Auth: &auth.AuthContext{
			Mode:   auth.AuthModeNormal,
			OID:    "test-org",
			APIKey: "test-key-1234567890",
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	srv, err := New(cfg, logger)
	require.NoError(t, err)

	stdioSrv, ok := srv.(*STDIOServer)
	require.True(t, ok, "expected STDIOServer type")

	t.Run("has SDK cache", func(t *testing.T) {
		assert.NotNil(t, stdioSrv.sdkCache)
	})

	t.Run("has logger", func(t *testing.T) {
		assert.NotNil(t, stdioSrv.logger)
		assert.Equal(t, logger, stdioSrv.logger)
	})

	t.Run("has MCP server", func(t *testing.T) {
		assert.NotNil(t, stdioSrv.mcpServer)
	})

	t.Run("Close cleanup", func(t *testing.T) {
		err := stdioSrv.Close()
		assert.NoError(t, err)
	})
}

func TestServerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Run("server lifecycle", func(t *testing.T) {
		cfg := &config.Config{
			Server: config.ServerConfig{
				Mode:     "stdio",
				Profile:  "core",
				LogLevel: "error",
			},
			Features: config.FeatureConfig{
				SDKCacheTTL: 5 * time.Minute,
			},
			Auth: &auth.AuthContext{
				Mode:   auth.AuthModeNormal,
				OID:    "test-org",
				APIKey: "test-key-1234567890",
			},
		}

		logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

		srv, err := New(cfg, logger)
		require.NoError(t, err)

		// Note: We can't actually call Serve() in a test as it blocks on stdio
		// Just verify the server was created successfully
		assert.NotNil(t, srv)
	})
}
