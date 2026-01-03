package server

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/mark3labs/mcp-go/server"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/config"
	"github.com/refractionpoint/lc-mcp-go/internal/gcs"
	"github.com/refractionpoint/lc-mcp-go/internal/resources"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// STDIOServer handles STDIO mode MCP server
type STDIOServer struct {
	mcpServer  *server.MCPServer
	config     *config.Config
	sdkCache   *auth.SDKCache
	gcsManager *gcs.Manager
	logger     *slog.Logger
}

// NewSTDIOServer creates a new STDIO mode server
func NewSTDIOServer(cfg *config.Config, logger *slog.Logger) (*STDIOServer, error) {
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

	// For STDIO mode, profile must come from config (no URLs)
	// Default to "all" if not explicitly set
	if cfg.Server.Profile == "" {
		cfg.Server.Profile = "all"
		logger.Info("MCP_PROFILE not set, defaulting to 'all' for STDIO mode")
	}

	// Create MCP server for STDIO mode
	mcpServer := server.NewMCPServer(
		"LimaCharlie MCP Server",
		"1.0.0",
		server.WithToolCapabilities(false),
		server.WithRecovery(),
	)

	s := &STDIOServer{
		mcpServer:  mcpServer,
		config:     cfg,
		sdkCache:   sdkCache,
		gcsManager: gcsManager,
		logger:     logger,
	}

	// Register tools for the selected profile
	if err := s.registerTools(); err != nil {
		return nil, fmt.Errorf("failed to register tools: %w", err)
	}

	logger.Info("STDIO server initialized",
		"profile", cfg.Server.Profile,
		"auth_mode", cfg.Auth.Mode.String())

	return s, nil
}

// registerTools registers all tools for the configured profile
func (s *STDIOServer) registerTools() error {
	// Add tools to the MCP server with auth mode for dynamic OID parameter handling
	if err := tools.AddToolsToServer(s.mcpServer, s.config.Server.Profile, s.config.Auth.Mode); err != nil {
		return err
	}

	toolNames := tools.GetToolsForProfile(s.config.Server.Profile)
	s.logger.Info("Registered tools", "count", len(toolNames))

	// Register resources
	resources.AddResourcesToServer(s.mcpServer)
	s.logger.Info("Registered resources")

	return nil
}

// Serve starts the STDIO server
func (s *STDIOServer) Serve(ctx context.Context) error {
	// Create context with auth for all requests (for STDIO mode)
	ctx = auth.WithAuthContext(ctx, s.config.Auth)

	// Store SDK cache in context for tool handlers (using typed key)
	ctx = auth.WithSDKCache(ctx, s.sdkCache)

	// Store GCS manager in context for tool handlers
	if s.gcsManager != nil {
		ctx = gcs.WithGCSManager(ctx, s.gcsManager)
	}

	s.logger.Info("Starting STDIO server")
	return server.ServeStdio(s.mcpServer)
}

// Close gracefully shuts down the STDIO server and releases resources
func (s *STDIOServer) Close() error {
	s.logger.Info("Shutting down STDIO server, cleaning up resources...")

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

	s.logger.Info("STDIO server shutdown complete")
	return nil
}
