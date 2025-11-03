package http

import (
	"context"
	"crypto/tls"
	"encoding/json"
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
		URL: cfg.RedisURL,
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
		Addr:              fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:           s.withMiddleware(mux),
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	// Configure TLS if enabled
	if cfg.EnableTLS {
		s.server.TLSConfig = s.createTLSConfig()
		logger.Info("TLS/HTTPS enabled for HTTP server")
	} else {
		// Only warn if not running in Cloud Run (which handles TLS termination)
		if os.Getenv("K_SERVICE") == "" {
			logger.Warn("⚠️  TLS/HTTPS DISABLED - This is insecure for production! Enable TLS with ENABLE_TLS=true")
		}
	}

	logger.Info("HTTP server initialized", "port", cfg.HTTPPort, "tls_enabled", cfg.EnableTLS)

	return s, nil
}

// setupRoutes configures HTTP routes
func (s *Server) setupRoutes() {
	// Root endpoint - handles MCP requests when URL is configured without /mcp suffix
	s.mux.HandleFunc("/", s.handleRootRequest)

	// Health check endpoints
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/ready", s.handleReady)

	// OAuth discovery endpoints (RFC 8414, RFC 9728)
	s.mux.HandleFunc("/.well-known/oauth-protected-resource", s.handleProtectedResourceMetadata)
	s.mux.HandleFunc("/.well-known/oauth-authorization-server", s.handleAuthorizationServerMetadata)
	// Claude Code also looks for the /mcp variant
	s.mux.HandleFunc("/.well-known/oauth-authorization-server/mcp", s.handleAuthorizationServerMetadata)

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
	if s.config.EnableTLS {
		protocol = "HTTPS"
	}
	s.logger.Info(fmt.Sprintf("Starting %s server", protocol), "port", s.config.HTTPPort)

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		var err error
		if s.config.EnableTLS {
			// Start HTTPS server with TLS
			err = s.server.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
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

// handleRootRequest handles requests to the root path "/"
// This allows Claude Code to connect when configured without the /mcp suffix
func (s *Server) handleRootRequest(w http.ResponseWriter, r *http.Request) {
	// Only handle the exact root path, not sub-paths
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// For POST requests, delegate to MCP JSON-RPC handler
	if r.Method == http.MethodPost {
		s.handleMCPRequest(w, r)
		return
	}

	// For GET requests, return server information
	if r.Method == http.MethodGet {
		s.writeJSON(w, http.StatusOK, map[string]interface{}{
			"type":   "lc-mcp-server",
			"status": "ok",
			"endpoints": map[string]string{
				"mcp":    "/mcp",
				"health": "/health",
				"ready":  "/ready",
			},
		})
		return
	}

	// Reject other HTTP methods
	s.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
		"error": "method not allowed",
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
	s.oauthHandlers.HandleRegister(w, r)
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
	// Extract session ID from query parameter
	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Missing session parameter",
		})
		return
	}

	// Delegate to OAuth handler which has the full implementation
	s.oauthHandlers.HandleProviderSelection(w, r, sessionID)
}

func (s *Server) handleMFAChallenge(w http.ResponseWriter, r *http.Request) {
	// Extract session ID from query parameter
	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Missing session parameter",
		})
		return
	}

	// Delegate to OAuth handler
	s.oauthHandlers.HandleMFAChallenge(w, r, sessionID)
}

func (s *Server) handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Extract parameters
	sessionID := r.FormValue("session")
	code := r.FormValue("code")

	if sessionID == "" || code == "" {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Missing session or code parameter",
		})
		return
	}

	// Delegate to OAuth handler
	s.oauthHandlers.HandleMFAVerify(w, r, sessionID, code)
}

func (s *Server) handleMCPRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Parse JSON-RPC request
	var req struct {
		JSONRPC string                 `json:"jsonrpc"`
		ID      interface{}            `json:"id"`
		Method  string                 `json:"method"`
		Params  map[string]interface{} `json:"params"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSONRPCError(w, nil, -32700, "Parse error", err.Error())
		return
	}

	// Validate JSON-RPC version
	if req.JSONRPC != "2.0" {
		s.writeJSONRPCError(w, req.ID, -32600, "Invalid Request", "jsonrpc must be '2.0'")
		return
	}

	// Handle different MCP methods
	switch req.Method {
	case "ping":
		// Heartbeat/keepalive - return empty response
		s.writeJSONRPCSuccess(w, req.ID, map[string]interface{}{})
	case "initialize":
		s.handleInitialize(w, r, req.ID, req.Params)
	case "notifications/initialized":
		// Client confirms initialization is complete - just log it
		s.logger.Info("Client initialization complete")
		// Notifications don't require a response, but we'll send success for compatibility
		s.writeJSONRPCSuccess(w, req.ID, map[string]interface{}{})
	case "tools/call":
		s.handleToolCall(w, r, req.ID, req.Params)
	case "tools/list":
		s.handleToolsList(w, r, req.ID)
	default:
		s.writeJSONRPCError(w, req.ID, -32601, "Method not found", fmt.Sprintf("Unknown method: %s", req.Method))
	}
}

func (s *Server) handleInitialize(w http.ResponseWriter, r *http.Request, id interface{}, params map[string]interface{}) {
	// Log client info if provided
	if clientInfo, ok := params["clientInfo"].(map[string]interface{}); ok {
		clientName, _ := clientInfo["name"].(string)
		clientVersion, _ := clientInfo["version"].(string)
		s.logger.Info("MCP client initializing", "client", clientName, "version", clientVersion)
	}

	// Return server capabilities per MCP protocol spec
	s.writeJSONRPCSuccess(w, id, map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{}, // We support tools
		},
		"serverInfo": map[string]interface{}{
			"name":    "LimaCharlie MCP Server",
			"version": "1.0.0",
		},
	})
}

func (s *Server) handleToolCall(w http.ResponseWriter, r *http.Request, id interface{}, params map[string]interface{}) {
	// Extract tool name and arguments
	toolName, ok := params["name"].(string)
	if !ok {
		s.writeJSONRPCError(w, id, -32602, "Invalid params", "Missing or invalid 'name' parameter")
		return
	}

	arguments, ok := params["arguments"].(map[string]interface{})
	if !ok {
		arguments = make(map[string]interface{})
	}

	// Extract authentication from Bearer token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		s.writeJSONRPCError(w, id, -32000, "Unauthorized", "Missing Authorization header")
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		s.writeJSONRPCError(w, id, -32000, "Unauthorized", "Invalid Authorization header format")
		return
	}

	bearerToken := parts[1]

	// Verify and extract UID from token
	// For now, we'll decode the JWT to extract the UID
	// In production, this should validate the signature
	uid, err := s.extractUIDFromToken(bearerToken)
	if err != nil {
		s.writeJSONRPCError(w, id, -32000, "Unauthorized", fmt.Sprintf("Invalid token: %v", err))
		return
	}

	// Extract OID from arguments if present (for UID mode)
	oid := ""
	if oidVal, ok := arguments["oid"].(string); ok {
		oid = oidVal
	}

	// Create auth context
	authCtx := &auth.AuthContext{
		Mode:     auth.AuthModeUIDOAuth,
		UID:      uid,
		JWTToken: bearerToken,
		OID:      oid,
	}

	// Create request context with auth
	ctx := r.Context()
	ctx = auth.WithAuthContext(ctx, authCtx)
	ctx = auth.WithSDKCache(ctx, s.sdkCache)
	if s.gcsManager != nil {
		ctx = gcs.WithGCSManager(ctx, s.gcsManager)
	}

	// Look up the tool
	tool, ok := tools.GetTool(toolName)
	if !ok {
		s.writeJSONRPCError(w, id, -32601, "Tool not found", fmt.Sprintf("Unknown tool: %s", toolName))
		return
	}

	// Call the tool handler
	result, err := tool.Handler(ctx, arguments)
	if err != nil {
		s.writeJSONRPCError(w, id, -32000, "Tool execution error", err.Error())
		return
	}

	// Return success response
	s.writeJSONRPCSuccess(w, id, result)
}

func (s *Server) handleToolsList(w http.ResponseWriter, r *http.Request, id interface{}) {
	// Get tools for the configured profile
	toolNames := tools.GetToolsForProfile(s.profile)

	toolList := make([]map[string]interface{}, 0, len(toolNames))
	for _, name := range toolNames {
		tool, ok := tools.GetTool(name)
		if !ok {
			continue
		}

		toolList = append(toolList, map[string]interface{}{
			"name":        tool.Name,
			"description": tool.Description,
			"inputSchema": tool.Schema.InputSchema,
		})
	}

	s.writeJSONRPCSuccess(w, id, map[string]interface{}{
		"tools": toolList,
	})
}

func (s *Server) extractUIDFromToken(token string) (string, error) {
	// SECURITY: Validate MCP OAuth access token (NOT Firebase token directly)
	// The Bearer token here is the MCP-issued access token from /token endpoint

	// Validate the MCP access token using token manager
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Validate and get token info
	validation, err := s.tokenManager.ValidateAccessToken(ctx, token, true)
	if err != nil {
		s.logger.Error("Token validation error", "error", err)
		return "", fmt.Errorf("token validation failed: %w", err)
	}

	if !validation.Valid {
		return "", fmt.Errorf("invalid or expired token: %s", validation.Error)
	}

	// Return the Firebase UID from validated token
	return validation.UID, nil
}

func (s *Server) writeJSONRPCSuccess(w http.ResponseWriter, id interface{}, result interface{}) {
	response := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	}
	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) writeJSONRPCError(w http.ResponseWriter, id interface{}, code int, message string, data string) {
	response := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
			"data":    data,
		},
	}
	s.writeJSON(w, http.StatusOK, response)
}

// writeJSON writes a JSON response
func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.logger.Error("Failed to encode JSON response", "error", err)
	}
}
