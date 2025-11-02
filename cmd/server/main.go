package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/refractionpoint/lc-mcp-go/internal/config"
	"github.com/refractionpoint/lc-mcp-go/internal/server"
	"github.com/sirupsen/logrus"

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

func main() {
	// Setup logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.WithError(err).Fatal("Failed to load configuration")
	}

	// Set log level
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logger.WithError(err).Warn("Invalid log level, using info")
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		logger.WithError(err).Fatal("Invalid configuration")
	}

	logger.WithFields(logrus.Fields{
		"mode":      cfg.Mode,
		"profile":   cfg.Profile,
		"auth_mode": cfg.Auth.Mode.String(),
	}).Info("Starting LimaCharlie MCP Server")

	// Create server
	srv, err := server.New(cfg, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create server")
	}

	// Ensure cleanup happens on exit
	defer func() {
		if err := srv.Close(); err != nil {
			logger.WithError(err).Error("Error during server cleanup")
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
		logger.WithError(err).Fatal("Server error")
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
