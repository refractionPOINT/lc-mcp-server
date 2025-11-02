package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/refractionpoint/lc-mcp-go/internal/config"
	"github.com/refractionpoint/lc-mcp-go/internal/server"

	// Import tool packages to trigger init() registration
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/admin"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/ai"         // AI-powered generation tools
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/artifacts"  // Artifact tools
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/config"     // Platform configuration tools
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/core"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/forensics"      // Forensics and YARA tools
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/historical"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/investigation"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/response"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/rules"   // Detection engineering tools
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/schemas" // Event schema tools
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

func main() {
	// Load configuration first to determine log level
	cfg, err := config.Load()
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Setup logger with configured level
	level := parseLogLevel(cfg.LogLevel)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		logger.Error("Invalid configuration", "error", err)
		os.Exit(1)
	}

	logger.Info("Starting LimaCharlie MCP Server",
		"mode", cfg.Mode,
		"profile", cfg.Profile,
		"auth_mode", cfg.Auth.Mode.String())

	// Create server
	srv, err := server.New(cfg, logger)
	if err != nil {
		logger.Error("Failed to create server", "error", err)
		os.Exit(1)
	}

	// Ensure cleanup happens on exit
	defer func() {
		if err := srv.Close(); err != nil {
			logger.Error("Error during server cleanup", "error", err)
		}
	}()

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		logger.Info("Received shutdown signal")
		cancel()
	}()

	// Start server
	logger.Info("Server starting...")
	if err := srv.Serve(ctx); err != nil {
		logger.Error("Server error", "error", err)
		os.Exit(1)
	}

	logger.Info("Server stopped")
}

// printBanner prints the server banner
func printBanner() {
	banner := `
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║           LimaCharlie MCP Server - Go Edition                 ║
║                                                               ║
║  A Model Context Protocol server for LimaCharlie             ║
║  https://limacharlie.io                                       ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}
