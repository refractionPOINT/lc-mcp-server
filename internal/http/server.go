package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/config"
	"github.com/refractionpoint/lc-mcp-go/internal/crypto"
	"github.com/refractionpoint/lc-mcp-go/internal/gcs"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/endpoints"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/firebase"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/metadata"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/token"
	"github.com/refractionpoint/lc-mcp-go/internal/ratelimit"
	"github.com/refractionpoint/lc-mcp-go/internal/redis"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"log/slog"
)

const (
	// HeaderMCPTools is the HTTP header for specifying a CSV list of tools
	HeaderMCPTools = "X-MCP-Tools"
)

// Server represents the HTTP server for MCP OAuth mode
type Server struct {
	config           *config.Config
	logger           *slog.Logger
	mux              *http.ServeMux
	server           *http.Server
	redisClient      *redis.Client
	stateManager     *state.Manager
	tokenManager     *token.Manager
	metadataProvider *metadata.Provider
	oauthHandlers    *endpoints.Handlers
	sdkCache         *auth.SDKCache
	gcsManager       *gcs.Manager
	profile          string
	rateLimiter      *ratelimit.Limiter
}

// New creates a new HTTP server instance using standard library
func New(cfg *config.Config, logger *slog.Logger, sdkCache *auth.SDKCache, gcsManager *gcs.Manager, profile string) (*Server, error) {
	// Initialize Redis client
	redisClient, err := redis.New(&redis.Config{
		URL: cfg.OAuth.RedisURL,
	}, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis client: %w", err)
	}

	// Test Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := redisClient.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	// Initialize token encryption
	encryption, err := crypto.NewTokenEncryption(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize encryption: %w", err)
	}

	// Initialize OAuth state manager
	stateManager := state.NewManager(redisClient, encryption, logger)

	// Initialize Firebase client
	firebaseClient, err := firebase.NewClient(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create Firebase client: %w", err)
	}

	// Initialize token manager
	tokenManager := token.NewManager(stateManager, firebaseClient, logger)

	// Initialize metadata provider
	metadataProvider := metadata.NewProvider(logger)

	// Initialize rate limiter
	rateLimiter := ratelimit.NewLimiter(redisClient, logger)

	// Initialize OAuth handlers with redirect URI whitelist
	oauthHandlers, err := endpoints.NewHandlers(
		stateManager,
		tokenManager,
		firebaseClient,
		metadataProvider,
		logger,
		cfg.OAuth.AllowedRedirectURIs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuth handlers: %w", err)
	}

	mux := http.NewServeMux()

	s := &Server{
		config:           cfg,
		logger:           logger,
		mux:              mux,
		redisClient:      redisClient,
		stateManager:     stateManager,
		tokenManager:     tokenManager,
		metadataProvider: metadataProvider,
		oauthHandlers:    oauthHandlers,
		sdkCache:         sdkCache,
		gcsManager:       gcsManager,
		profile:          profile,
		rateLimiter:      rateLimiter,
	}

	// Setup routes
	s.setupRoutes()

	// Create HTTP server with security settings
	s.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTP.Port),
		Handler:           s.withMiddleware(mux),
		ReadTimeout:       10 * time.Minute, // Increased to support long-running sensor commands
		WriteTimeout:      10 * time.Minute, // Increased to support long-running sensor commands
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	// Configure TLS if enabled
	if cfg.TLS.Enable {
		s.server.TLSConfig = s.createTLSConfig()
		logger.Info("TLS/HTTPS enabled for HTTP server")
	} else {
		// Only warn if not running in Cloud Run (which handles TLS termination)
		if os.Getenv("K_SERVICE") == "" {
			logger.Warn("⚠️  TLS/HTTPS DISABLED - This is insecure for production! Enable TLS with ENABLE_TLS=true")
		}
	}

	logger.Info("HTTP server initialized", "port", cfg.HTTP.Port, "tls_enabled", cfg.TLS.Enable)

	return s, nil
}

// getActiveProfile determines the active profile for a request
// If MCP_PROFILE is explicitly set (s.profile != ""), it takes precedence
// Otherwise, extract profile from URL path
func (s *Server) getActiveProfile(r *http.Request) string {
	// If profile is explicitly configured via MCP_PROFILE env var, use it
	if s.profile != "" {
		return s.profile
	}

	// Otherwise, extract from URL path
	path := r.URL.Path

	// Handle root and /mcp paths - default to "all"
	if path == "/" || path == "/mcp" {
		return "all"
	}

	// Extract profile from path (e.g., "/historical_data" -> "historical_data")
	profile := strings.TrimPrefix(path, "/")

	// Validate that it's a real profile
	if _, exists := tools.ProfileDefinitions[profile]; exists {
		return profile
	}

	// If not a valid profile, default to "all"
	s.logger.Warn("Invalid profile in URL path, defaulting to 'all'", "path", path, "profile", profile)
	return "all"
}

// parseToolsFromHeader extracts and parses the X-MCP-Tools header
// Returns nil slice if header not present or empty after parsing
func (s *Server) parseToolsFromHeader(r *http.Request) ([]string, error) {
	headerValue := r.Header.Get(HeaderMCPTools)
	if headerValue == "" {
		return nil, nil
	}

	// Parse CSV
	parts := strings.Split(headerValue, ",")
	var toolsList []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			toolsList = append(toolsList, trimmed)
		}
	}

	// If empty after parsing, return nil (triggers fallback)
	if len(toolsList) == 0 {
		return nil, nil
	}

	return toolsList, nil
}

// getToolsForRequest determines which tools should be available for this request
// Returns tool names or error if validation fails
func (s *Server) getToolsForRequest(r *http.Request) ([]string, error) {
	// Check if profile is explicitly configured via MCP_PROFILE env var
	if s.profile != "" {
		return tools.GetToolsForProfile(s.profile), nil
	}

	// Check URL path for profile
	path := r.URL.Path

	// Skip root and /mcp paths - these don't specify a profile
	if path != "/" && path != "/mcp" {
		// Extract profile from path
		profileFromPath := strings.TrimPrefix(path, "/")

		// Validate that it's a real profile
		if _, exists := tools.ProfileDefinitions[profileFromPath]; exists {
			return tools.GetToolsForProfile(profileFromPath), nil
		}
	}

	// No explicit profile set (would default to "all")
	// Check for X-MCP-Tools header
	headerTools, err := s.parseToolsFromHeader(r)
	if err != nil {
		return nil, err
	}

	// If header provided tools, validate and use them
	if headerTools != nil {
		if err := tools.ValidateToolNames(headerTools); err != nil {
			return nil, fmt.Errorf("invalid tools in %s header: %w", HeaderMCPTools, err)
		}
		s.logger.Debug("Using tools from header", "count", len(headerTools), "tools", headerTools)
		return headerTools, nil
	}

	// Default to "all" profile
	return tools.GetToolsForProfile("all"), nil
}

// createTLSConfig creates a secure TLS configuration
func (s *Server) createTLSConfig() *tls.Config {
	return &tls.Config{
		// Minimum TLS 1.3 for maximum security
		MinVersion: tls.VersionTLS13,

		// Prefer server cipher suites
		PreferServerCipherSuites: true,

		// Strong cipher suites for TLS 1.3
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},

		// Curve preferences
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}
}

// Serve starts the HTTP server
func (s *Server) Serve(ctx context.Context) error {
	protocol := "HTTP"
	if s.config.TLS.Enable {
		protocol = "HTTPS"
	}
	s.logger.Info(fmt.Sprintf("Starting %s server", protocol), "port", s.config.HTTP.Port)

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		var err error
		if s.config.TLS.Enable {
			// Start HTTPS server with TLS
			err = s.server.ListenAndServeTLS(s.config.TLS.Cert, s.config.TLS.Key)
		} else {
			// Start HTTP server (insecure - dev only)
			err = s.server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		s.logger.Info("Shutting down HTTP server...")

		// Graceful shutdown with timeout
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server shutdown failed: %w", err)
		}

		s.logger.Info("HTTP server stopped gracefully")
		return nil

	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}
}

// Close performs cleanup
func (s *Server) Close() error {
	s.logger.Info("Closing HTTP server resources...")

	// Close Redis client
	if s.redisClient != nil {
		if err := s.redisClient.Close(); err != nil {
			s.logger.Error("Failed to close Redis client", "error", err)
			return fmt.Errorf("failed to close Redis client: %w", err)
		}
	}

	s.logger.Info("HTTP server resources closed")
	return nil
}

// writeJSON writes a JSON response using ResponseWriter
func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	rw := NewResponseWriter(w, s.logger)
	rw.WriteJSON(status, data)
}
