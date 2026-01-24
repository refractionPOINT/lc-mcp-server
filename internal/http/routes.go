package http

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// setupRoutes configures HTTP routes
func (s *Server) setupRoutes() {
	// Root endpoint - handles MCP requests when URL is configured without /mcp suffix
	s.mux.HandleFunc("/", s.handleRootRequest)

	// Static file serving for OAuth pages (favicon, images, etc.)
	fs := http.FileServer(http.Dir("static"))
	s.mux.Handle("/static/", http.StripPrefix("/static/", fs))

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
	s.mux.HandleFunc("/oauth/select-provider/google", s.handleProviderSelectionWithProvider)
	s.mux.HandleFunc("/oauth/select-provider/microsoft", s.handleProviderSelectionWithProvider)

	// MFA endpoints
	s.mux.HandleFunc("/oauth/mfa-challenge", s.handleMFAChallenge)
	s.mux.HandleFunc("/oauth/mfa-verify", s.handleMFAVerify)

	// MCP JSON-RPC endpoint (protected by OAuth)
	// Register both unversioned (latest) and versioned routes
	s.mux.HandleFunc("/mcp", s.handleMCPRequest)               // Unversioned -> latest
	s.mux.HandleFunc("/mcp/"+APIVersionV1, s.handleMCPRequest) // Explicit v1

	// Profile-specific endpoints - register all valid profiles
	// This allows URL-based profile routing when MCP_PROFILE is not set
	// Register both unversioned (latest) and versioned variants
	// Dynamically load profiles from tools.ProfileDefinitions
	profiles := make([]string, 0, len(tools.ProfileDefinitions)+1)
	// Add "all" profile first (special profile that includes all tools)
	profiles = append(profiles, "all")
	// Add all other profiles from ProfileDefinitions
	for profile := range tools.ProfileDefinitions {
		profiles = append(profiles, profile)
	}
	for _, profile := range profiles {
		// Unversioned route (maps to latest)
		unversionedRoute := "/mcp/" + profile
		s.mux.HandleFunc(unversionedRoute, s.handleMCPRequest)

		// Versioned route (explicit v1)
		versionedRoute := "/mcp/" + APIVersionV1 + "/" + profile
		s.mux.HandleFunc(versionedRoute, s.handleMCPRequest)
	}
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
			"api_version": map[string]string{
				"current":   LatestAPIVersion,
				"supported": APIVersionV1,
			},
			"endpoints": map[string]string{
				"mcp":    "/mcp",
				"mcp_v1": "/mcp/" + APIVersionV1,
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
	// Extract session ID from query parameter (GET) or form body (POST)
	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		// For POST requests, check form body
		sessionID = r.FormValue("session")
	}

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

func (s *Server) handleProviderSelectionWithProvider(w http.ResponseWriter, r *http.Request) {
	// Extract provider from URL path (/oauth/select-provider/{provider})
	provider := ""
	if strings.HasSuffix(r.URL.Path, "/google") {
		provider = "google"
	} else if strings.HasSuffix(r.URL.Path, "/microsoft") {
		provider = "microsoft"
	}

	if provider == "" {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Invalid provider",
		})
		return
	}

	// Extract session ID from query parameter
	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Missing session parameter",
		})
		return
	}

	// Get stored OAuth parameters from session
	params, err := s.stateManager.ConsumeSelectionSession(r.Context(), sessionID)
	if err != nil || params == nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Session expired or invalid",
		})
		return
	}

	// Add provider to parameters
	params["provider"] = provider

	// Build authorize URL with all parameters using proper URL encoding
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}

	authorizeURL := "/authorize?" + q.Encode()
	http.Redirect(w, r, authorizeURL, http.StatusFound)
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

	// Extract parameters - FormValue handles form parsing automatically
	sessionID := r.FormValue("session")
	code := r.FormValue("verification_code")

	if sessionID == "" || code == "" {
		// Log for debugging - avoid logging actual values for security
		s.logger.Warn("MFA verify missing parameters",
			"has_session", sessionID != "",
			"has_code", code != "",
			"content_type", r.Header.Get("Content-Type"),
			"content_length", r.ContentLength)

		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Missing session or code parameter",
		})
		return
	}

	// Delegate to OAuth handler
	s.oauthHandlers.HandleMFAVerify(w, r, sessionID, code)
}
