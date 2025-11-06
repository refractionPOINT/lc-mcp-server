package server

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/refractionpoint/lc-mcp-go/internal/config"
)

// Server is the interface that all server implementations must satisfy
// This allows for clean separation between STDIO and HTTP server modes
type Server interface {
	// Serve starts the server and blocks until context is cancelled or an error occurs
	Serve(ctx context.Context) error

	// Close gracefully shuts down the server and releases resources
	Close() error
}

// New creates a new MCP server instance based on the configured mode
// It acts as a factory that returns the appropriate Server implementation
func New(cfg *config.Config, logger *slog.Logger) (Server, error) {
	if logger == nil {
		level := config.ParseLogLevel(cfg.Server.LogLevel)
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: level,
		}))
	}

	// Create appropriate server based on mode
	switch cfg.Server.Mode {
	case "stdio":
		return NewSTDIOServer(cfg, logger)
	case "http":
		return NewHTTPServer(cfg, logger)
	default:
		return nil, fmt.Errorf("unknown server mode: %s", cfg.Server.Mode)
	}
}
