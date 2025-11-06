package server

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/config"
	"github.com/refractionpoint/lc-mcp-go/internal/gcs"
	httpserver "github.com/refractionpoint/lc-mcp-go/internal/http"
)

// HTTPServerWrapper handles HTTP mode MCP server with OAuth
type HTTPServerWrapper struct {
	httpServer *httpserver.Server
	config     *config.Config
	sdkCache   *auth.SDKCache
	gcsManager *gcs.Manager
	logger     *slog.Logger
}

// NewHTTPServer creates a new HTTP mode server with OAuth support
func NewHTTPServer(cfg *config.Config, logger *slog.Logger) (*HTTPServerWrapper, error) {
	// Create SDK cache
	sdkCache := auth.NewSDKCache(cfg.Features.SDKCacheTTL, logger)

	// Initialize GCS manager for large result handling
	ctx := context.Background()
	gcsConfig := gcs.LoadConfig()
	gcsManager, err := gcs.NewManager(ctx, gcsConfig)
	if err != nil {
		logger.Warn("Failed to initialize GCS manager, large results will be returned inline", "error", err)
		gcsManager = nil
	} else if gcsConfig.Enabled {
		logger.Info("GCS manager initialized for large result handling",
			"bucket", gcsConfig.BucketName,
			"threshold", gcsConfig.TokenThreshold)
	} else {
		logger.Info("GCS disabled, large results will be returned inline")
	}

	// Create HTTP server for OAuth mode
	httpSrv, err := httpserver.New(cfg, logger, sdkCache, gcsManager, cfg.Server.Profile)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP server: %w", err)
	}

	s := &HTTPServerWrapper{
		httpServer: httpSrv,
		config:     cfg,
		sdkCache:   sdkCache,
		gcsManager: gcsManager,
		logger:     logger,
	}

	logger.Info("HTTP server initialized",
		"profile", cfg.Server.Profile,
		"port", cfg.HTTP.Port,
		"auth_mode", cfg.Auth.Mode.String())

	return s, nil
}

// Serve starts the HTTP server
func (s *HTTPServerWrapper) Serve(ctx context.Context) error {
	s.logger.Info("Starting HTTP server with OAuth", "port", s.config.HTTP.Port)
	return s.httpServer.Serve(ctx)
}

// Close gracefully shuts down the HTTP server and releases resources
func (s *HTTPServerWrapper) Close() error {
	s.logger.Info("Shutting down HTTP server, cleaning up resources...")

	// Close SDK cache
	if s.sdkCache != nil {
		s.sdkCache.Close()
	}

	// Close GCS manager
	if s.gcsManager != nil {
		if err := s.gcsManager.Close(); err != nil {
			s.logger.Warn("Failed to close GCS manager", "error", err)
		}
	}

	// Close HTTP server if running
	if s.httpServer != nil {
		if err := s.httpServer.Close(); err != nil {
			s.logger.Error("Failed to close HTTP server", "error", err)
			return err
		}
	}

	s.logger.Info("HTTP server shutdown complete")
	return nil
}
