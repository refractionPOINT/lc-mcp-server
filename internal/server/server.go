package server

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/server"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/config"
	httpserver "github.com/refractionpoint/lc-mcp-go/internal/http"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/sirupsen/logrus"
)

// Server wraps the MCP server with our configuration
type Server struct {
	mcpServer  *server.MCPServer
	httpServer *httpserver.Server
	config     *config.Config
	sdkCache   *auth.SDKCache
	logger     *logrus.Logger
}

// New creates a new MCP server instance
func New(cfg *config.Config, logger *logrus.Logger) (*Server, error) {
	if logger == nil {
		logger = logrus.New()
		level, err := logrus.ParseLevel(cfg.LogLevel)
		if err != nil {
			level = logrus.InfoLevel
		}
		logger.SetLevel(level)
	}

	// Create SDK cache
	sdkCache := auth.NewSDKCache(cfg.SDKCacheTTL, logger)

	s := &Server{
		config:   cfg,
		sdkCache: sdkCache,
		logger:   logger,
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
		httpSrv, err := httpserver.New(cfg, logger, sdkCache, cfg.Profile)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP server: %w", err)
		}
		s.httpServer = httpSrv

		// Note: HTTP server handles OAuth authentication
		// Tools will be accessible via authenticated MCP JSON-RPC requests

	default:
		return nil, fmt.Errorf("unknown server mode: %s", cfg.Mode)
	}

	logger.WithFields(logrus.Fields{
		"profile":   cfg.Profile,
		"mode":      cfg.Mode,
		"auth_mode": cfg.Auth.Mode.String(),
	}).Info("LimaCharlie MCP server initialized")

	return s, nil
}

// registerTools registers all tools for the configured profile
func (s *Server) registerTools() error {
	// Add tools to the MCP server
	if err := tools.AddToolsToServer(s.mcpServer, s.config.Profile); err != nil {
		return err
	}

	toolNames := tools.GetToolsForProfile(s.config.Profile)
	s.logger.WithField("count", len(toolNames)).Info("Registered tools")

	return nil
}

// Serve starts the server in the configured mode
func (s *Server) Serve(ctx context.Context) error {
	// Create context with auth for all requests (for STDIO mode)
	ctx = auth.WithAuthContext(ctx, s.config.Auth)

	// Store SDK cache in context for tool handlers (using typed key)
	ctx = auth.WithSDKCache(ctx, s.sdkCache)

	s.logger.WithField("mode", s.config.Mode).Info("Starting server")

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
	s.logger.WithField("port", s.config.HTTPPort).Info("Serving via HTTP with OAuth")
	return s.httpServer.Serve(ctx)
}

// GetSDKCache returns the SDK cache for tool handlers
func (s *Server) GetSDKCache() *auth.SDKCache {
	return s.sdkCache
}

// GetLogger returns the logger
func (s *Server) GetLogger() *logrus.Logger {
	return s.logger
}

// Close gracefully shuts down the server and releases resources
func (s *Server) Close() error {
	s.logger.Info("Shutting down server, cleaning up resources...")

	// Close SDK cache
	if s.sdkCache != nil {
		s.sdkCache.Close()
	}

	// Close HTTP server if running
	if s.httpServer != nil {
		if err := s.httpServer.Close(); err != nil {
			s.logger.WithError(err).Error("Failed to close HTTP server")
			return err
		}
	}

	s.logger.Info("Server shutdown complete")
	return nil
}
