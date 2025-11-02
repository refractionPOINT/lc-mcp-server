package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/config"
	"github.com/refractionpoint/lc-mcp-go/internal/crypto"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/endpoints"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/firebase"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/metadata"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/token"
	"github.com/refractionpoint/lc-mcp-go/internal/redis"
	"github.com/sirupsen/logrus"
)

// Server represents the HTTP server for MCP OAuth mode
type Server struct {
	config          *config.Config
	logger          *logrus.Logger
	mux             *http.ServeMux
	server          *http.Server
	redisClient     *redis.Client
	stateManager    *state.Manager
	tokenManager    *token.Manager
	metadataProvider *metadata.Provider
	oauthHandlers   *endpoints.Handlers
}

// New creates a new HTTP server instance using standard library
func New(cfg *config.Config, logger *logrus.Logger) (*Server, error) {
	// Build Redis URL from components
	redisURL := fmt.Sprintf("redis://%s/%d", cfg.RedisAddress, cfg.RedisDB)
	if cfg.RedisPassword != "" {
		redisURL = fmt.Sprintf("redis://:%s@%s/%d", cfg.RedisPassword, cfg.RedisAddress, cfg.RedisDB)
	}

	// Initialize Redis client
	redisClient, err := redis.New(&redis.Config{
		URL: redisURL,
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

	// Initialize OAuth handlers
	oauthHandlers, err := endpoints.NewHandlers(
		stateManager,
		tokenManager,
		firebaseClient,
		metadataProvider,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuth handlers: %w", err)
	}

	mux := http.NewServeMux()

	s := &Server{
		config:          cfg,
		logger:          logger,
		mux:             mux,
		redisClient:     redisClient,
		stateManager:    stateManager,
		tokenManager:    tokenManager,
		metadataProvider: metadataProvider,
		oauthHandlers:   oauthHandlers,
	}

	// Setup routes
	s.setupRoutes()

	// Create HTTP server with security settings
	s.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:           s.withMiddleware(mux),
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	logger.WithField("port", cfg.HTTPPort).Info("HTTP server initialized with OAuth support")

	return s, nil
}

// setupRoutes configures HTTP routes
func (s *Server) setupRoutes() {
	// Health check endpoints
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/ready", s.handleReady)

	// OAuth discovery endpoints (RFC 8414, RFC 9728)
	s.mux.HandleFunc("/.well-known/oauth-protected-resource", s.handleProtectedResourceMetadata)
	s.mux.HandleFunc("/.well-known/oauth-authorization-server", s.handleAuthorizationServerMetadata)

	// OAuth endpoints
	s.mux.HandleFunc("/authorize", s.handleAuthorize)
	s.mux.HandleFunc("/oauth/callback", s.handleOAuthCallback)
	s.mux.HandleFunc("/token", s.handleToken)
	s.mux.HandleFunc("/register", s.handleRegister)
	s.mux.HandleFunc("/revoke", s.handleRevoke)
	s.mux.HandleFunc("/introspect", s.handleIntrospect)

	// Provider selection endpoints
	s.mux.HandleFunc("/oauth/select-provider", s.handleProviderSelection)

	// MFA endpoints
	s.mux.HandleFunc("/oauth/mfa-challenge", s.handleMFAChallenge)
	s.mux.HandleFunc("/oauth/mfa-verify", s.handleMFAVerify)

	// MCP JSON-RPC endpoint (protected by OAuth)
	s.mux.HandleFunc("/mcp", s.handleMCPRequest)

	// Profile-specific endpoints (for backward compatibility)
	profiles := []string{"all", "historical_data", "live_investigation", "threat_response",
		"fleet_management", "detection_engineering", "platform_admin"}
	for _, profile := range profiles {
		route := "/" + profile
		s.mux.HandleFunc(route, s.handleMCPRequest)
	}
}

// Serve starts the HTTP server
func (s *Server) Serve(ctx context.Context) error {
	s.logger.WithField("addr", s.server.Addr).Info("Starting HTTP server")

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
			s.logger.WithError(err).Error("Failed to close Redis client")
			return fmt.Errorf("failed to close Redis client: %w", err)
		}
	}

	s.logger.Info("HTTP server resources closed")
	return nil
}

// Health check handlers
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "healthy",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	// Check Redis readiness
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	status := "ready"
	checks := map[string]bool{
		"redis": false,
	}

	if err := s.redisClient.Ping(ctx); err == nil {
		checks["redis"] = true
	}

	// If any check fails, return not ready
	for _, ready := range checks {
		if !ready {
			status = "not_ready"
			break
		}
	}

	statusCode := http.StatusOK
	if status != "ready" {
		statusCode = http.StatusServiceUnavailable
	}

	s.writeJSON(w, statusCode, map[string]interface{}{
		"status": status,
		"checks": checks,
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

// OAuth Metadata endpoints
func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	s.oauthHandlers.HandleProtectedResourceMetadata(w, r)
}

func (s *Server) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	s.oauthHandlers.HandleAuthorizationServerMetadata(w, r)
}

// OAuth authorization flow
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	s.oauthHandlers.HandleAuthorize(w, r)
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	s.oauthHandlers.HandleCallback(w, r)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	s.oauthHandlers.HandleToken(w, r)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	// Dynamic client registration (OAuth 2.0 DCR)
	// Not critical for initial implementation - return not implemented
	s.writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "not_implemented",
		"error_description": "Dynamic client registration not yet supported",
	})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	s.oauthHandlers.HandleRevoke(w, r)
}

func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	s.oauthHandlers.HandleIntrospect(w, r)
}

func (s *Server) handleProviderSelection(w http.ResponseWriter, r *http.Request) {
	// Provider selection is handled within HandleAuthorize
	http.Redirect(w, r, "/authorize", http.StatusFound)
}

func (s *Server) handleMFAChallenge(w http.ResponseWriter, r *http.Request) {
	// MFA is handled within OAuth callback flow
	http.Redirect(w, r, "/authorize", http.StatusFound)
}

func (s *Server) handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	// MFA verification is handled within OAuth callback flow
	http.Redirect(w, r, "/authorize", http.StatusFound)
}

func (s *Server) handleMCPRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	s.writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "MCP handler not yet implemented"})
}

// writeJSON writes a JSON response
func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.logger.WithError(err).Error("Failed to encode JSON response")
	}
}
