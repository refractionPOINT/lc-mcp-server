package server

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/server"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/config"
	"github.com/refractionpoint/lc-mcp-go/internal/gcs"
	httpserver "github.com/refractionpoint/lc-mcp-go/internal/http"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// parseLogLevel converts a string log level to slog.Level
func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Server wraps the MCP server with our configuration
type Server struct {
	mcpServer  *server.MCPServer
	httpServer *httpserver.Server
	config     *config.Config
	sdkCache   *auth.SDKCache
	gcsManager *gcs.Manager
	logger     *slog.Logger
}

// New creates a new MCP server instance
func New(cfg *config.Config, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		level := parseLogLevel(cfg.LogLevel)
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: level,
		}))
	}

	// Create SDK cache
	sdkCache := auth.NewSDKCache(cfg.SDKCacheTTL, logger)

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

	s := &Server{
		config:     cfg,
		sdkCache:   sdkCache,
		gcsManager: gcsManager,
		logger:     logger,
	}

	// Initialize based on mode
	switch cfg.Mode {
	case "stdio":
		// Create MCP server for STDIO mode
		mcpServer := server.NewMCPServer(
			"LimaCharlie MCP Server",
			"1.0.0",
			server.WithToolCapabilities(false),
			server.WithRecovery(),
		)
		s.mcpServer = mcpServer

		// Register tools for the selected profile
		if err := s.registerTools(); err != nil {
			return nil, fmt.Errorf("failed to register tools: %w", err)
		}

	case "http":
		// Create HTTP server for OAuth mode
		httpSrv, err := httpserver.New(cfg, logger, sdkCache, gcsManager, cfg.Profile)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP server: %w", err)
		}
		s.httpServer = httpSrv

		// Note: HTTP server handles OAuth authentication
		// Tools will be accessible via authenticated MCP JSON-RPC requests

	default:
		return nil, fmt.Errorf("unknown server mode: %s", cfg.Mode)
	}

	logger.Info("LimaCharlie MCP server initialized",
		"profile", cfg.Profile,
		"mode", cfg.Mode,
		"auth_mode", cfg.Auth.Mode.String())

	return s, nil
}

// registerTools registers all tools for the configured profile
func (s *Server) registerTools() error {
	// Add tools to the MCP server
	if err := tools.AddToolsToServer(s.mcpServer, s.config.Profile); err != nil {
		return err
	}

	toolNames := tools.GetToolsForProfile(s.config.Profile)
	s.logger.Info("Registered tools", "count", len(toolNames))

	return nil
}

// Serve starts the server in the configured mode
func (s *Server) Serve(ctx context.Context) error {
	// Create context with auth for all requests (for STDIO mode)
	ctx = auth.WithAuthContext(ctx, s.config.Auth)

	// Store SDK cache in context for tool handlers (using typed key)
	ctx = auth.WithSDKCache(ctx, s.sdkCache)

	// Store GCS manager in context for tool handlers
	if s.gcsManager != nil {
		ctx = gcs.WithGCSManager(ctx, s.gcsManager)
	}

	s.logger.Info("Starting server", "mode", s.config.Mode)

	switch s.config.Mode {
	case "stdio":
		return s.serveStdio(ctx)
	case "http":
		return s.serveHTTP(ctx)
	default:
		return fmt.Errorf("unknown server mode: %s", s.config.Mode)
	}
}

// serveStdio starts the server in STDIO mode
func (s *Server) serveStdio(ctx context.Context) error {
	s.logger.Info("Serving via STDIO")
	return server.ServeStdio(s.mcpServer)
}

// serveHTTP starts the server in HTTP mode with OAuth
func (s *Server) serveHTTP(ctx context.Context) error {
	s.logger.Info("Serving via HTTP with OAuth", "port", s.config.HTTPPort)
	return s.httpServer.Serve(ctx)
}

// GetSDKCache returns the SDK cache for tool handlers
func (s *Server) GetSDKCache() *auth.SDKCache {
	return s.sdkCache
}

// GetLogger returns the logger
func (s *Server) GetLogger() *slog.Logger {
	return s.logger
}

// Close gracefully shuts down the server and releases resources
func (s *Server) Close() error {
	s.logger.Info("Shutting down server, cleaning up resources...")

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

	s.logger.Info("Server shutdown complete")
	return nil
}
