package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/gcs"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// Note: tools.GetOrganization is used for permission checking

func (s *Server) handleMCPRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Extract API version from context for observability
	apiVersion := GetVersionFromContext(r.Context())
	s.logger.Debug("Handling MCP request", "api_version", apiVersion, "path", r.URL.Path)

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
	// Generate request ID for tracking
	requestID := fmt.Sprintf("req_%d", time.Now().UnixNano())
	startTime := time.Now()

	// Extract tool name and arguments
	toolName, ok := params["name"].(string)
	if !ok {
		s.writeJSONRPCError(w, id, -32602, "Invalid params", "Missing or invalid 'name' parameter")
		return
	}

	s.logger.Info("Tool call started", "request_id", requestID, "tool", toolName)

	arguments, ok := params["arguments"].(map[string]interface{})
	if !ok {
		arguments = make(map[string]interface{})
	}

	// Determine authentication method:
	// 1. If Bearer token provided → use OAuth/JWT passthrough
	// 2. If X-LC-UID + X-LC-API-KEY headers provided → use header credentials
	// 3. If server has env var credentials → use server credentials
	// 4. None of above → Unauthorized
	var authCtx *auth.AuthContext
	var isJWTPassthrough bool

	authHeader := r.Header.Get("Authorization")
	lcUID := r.Header.Get("X-LC-UID")
	lcOID := r.Header.Get("X-LC-OID")
	lcAPIKey := r.Header.Get("X-LC-API-KEY")
	lcAllowMetaTools := r.Header.Get("X-LC-ALLOW-META-TOOLS")
	lcDenyMetaTools := r.Header.Get("X-LC-DENY-META-TOOLS")

	// Validate the credential headers at the boundary rather than relying on
	// downstream UUID checks: these values flow into cache keys and request
	// paths, so a malformed one must never get that far.
	if lcOID != "" {
		if err := auth.ValidateOID(lcOID); err != nil {
			s.writeJSONRPCError(w, id, -32000, "Unauthorized", fmt.Sprintf("Invalid X-LC-OID header: %v", err))
			return
		}
	}
	if lcUID != "" {
		if err := auth.ValidateUID(lcUID); err != nil {
			s.writeJSONRPCError(w, id, -32000, "Unauthorized", fmt.Sprintf("Invalid X-LC-UID header: %v", err))
			return
		}
	}
	if lcAPIKey != "" {
		if err := auth.ValidateAPIKey(lcAPIKey); err != nil {
			s.writeJSONRPCError(w, id, -32000, "Unauthorized", fmt.Sprintf("Invalid X-LC-API-KEY header: %v", err))
			return
		}
	}

	if authHeader != "" {
		// Bearer token provided - use OAuth/JWT passthrough
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			s.writeJSONRPCError(w, id, -32000, "Unauthorized", "Invalid Authorization header format")
			return
		}

		bearerToken := parts[1]

		// Verify and extract UID, LimaCharlie JWT, and Firebase token from MCP access token
		s.logger.Info("Extracting UID from token", "request_id", requestID)
		tokenStartTime := time.Now()
		uid, limaCharlieJWT, firebaseIDToken, err := s.extractUIDFromToken(bearerToken)
		tokenDuration := time.Since(tokenStartTime)
		if err != nil {
			s.logger.Info("Token extraction failed", "request_id", requestID, "duration_ms", tokenDuration.Milliseconds(), "error", err.Error())
			s.writeJSONRPCError(w, id, -32000, "Unauthorized", fmt.Sprintf("Invalid token: %v", err))
			return
		}
		s.logger.Info("Token extraction completed", "request_id", requestID, "duration_ms", tokenDuration.Milliseconds())

		// JWT passthrough mode detection: no Firebase token means direct JWT
		isJWTPassthrough = firebaseIDToken == ""

		// Create auth context from Bearer token
		if uid == "" && isJWTPassthrough && lcOID != "" {
			// Org API key JWT passthrough: no UID in token, use OID from header.
			// The OID comes from a header while the credential is the JWT, so
			// confirm the JWT's own claims cover that org before pinning to it —
			// otherwise a caller could present a valid token for org A and name
			// org B. (The gateway authorizes independently; this is the
			// server-side half of that boundary.)
			if !s.jwtCoversOID(limaCharlieJWT, lcOID, requestID) {
				s.writeJSONRPCError(w, id, -32000, "Unauthorized", "X-LC-OID is not covered by the presented token's organization claims")
				return
			}
			// Clear isJWTPassthrough since the OID is already pinned — passthrough
			// semantics (requiring OID in every tool call) don't apply here.
			isJWTPassthrough = false
			authCtx = &auth.AuthContext{
				Mode:     auth.AuthModeNormal,
				OID:      lcOID,
				JWTToken: limaCharlieJWT,
			}
			s.logger.Debug("Authenticated via org JWT passthrough", "request_id", requestID, "oid", lcOID)
		} else {
			authCtx = &auth.AuthContext{
				Mode:            auth.AuthModeUIDOAuth,
				UID:             uid,
				JWTToken:        limaCharlieJWT,  // LimaCharlie JWT for API authentication
				FirebaseIDToken: firebaseIDToken, // Firebase token for JWT regeneration per org
			}
			s.logger.Debug("Authenticated via Bearer token", "request_id", requestID, "uid", uid, "jwt_passthrough", isJWTPassthrough)
		}
	} else if lcUID != "" && lcAPIKey != "" {
		// Header-based user credentials (X-LC-UID + X-LC-API-KEY)
		// If X-LC-OID is also provided, pin to that org
		authCtx = &auth.AuthContext{
			Mode:   auth.AuthModeUIDKey,
			UID:    lcUID,
			APIKey: lcAPIKey,
			OID:    lcOID, // Empty if not provided, which is fine
		}
		isJWTPassthrough = false
		if lcOID != "" {
			s.logger.Debug("Authenticated via user header credentials with OID", "request_id", requestID, "uid", lcUID, "oid", lcOID)
		} else {
			s.logger.Debug("Authenticated via user header credentials", "request_id", requestID, "uid", lcUID)
		}
	} else if lcOID != "" && lcAPIKey != "" {
		// Header-based org credentials (X-LC-OID + X-LC-API-KEY)
		authCtx = &auth.AuthContext{
			Mode:   auth.AuthModeNormal,
			OID:    lcOID,
			APIKey: lcAPIKey,
		}
		isJWTPassthrough = false
		s.logger.Debug("Authenticated via org header credentials", "request_id", requestID, "oid", lcOID)
	} else if s.serverAuthCtx != nil && s.serverAuthCtx.HasCredentials() {
		// No Bearer token - use server-wide credentials (only if they have actual credentials)
		authCtx = s.serverAuthCtx
		isJWTPassthrough = false // Server credentials are not JWT passthrough
		s.logger.Debug("Using server-wide credentials", "request_id", requestID, "uid", authCtx.UID, "mode", authCtx.Mode.String())
	} else {
		// No authentication provided
		s.writeJSONRPCError(w, id, -32000, "Unauthorized", "Missing authentication: provide Authorization header, X-LC-UID + X-LC-API-KEY, or X-LC-OID + X-LC-API-KEY headers")
		return
	}

	// Create request context with auth
	ctx := r.Context()
	ctx = auth.WithRequestID(ctx, requestID)
	ctx = auth.WithAuthContext(ctx, authCtx)
	ctx = auth.WithSDKCache(ctx, s.sdkCache)
	if s.gcsManager != nil {
		ctx = gcs.WithGCSManager(ctx, s.gcsManager)
	}

	// Add permission cache for ai_agent.operate checks
	if s.permissionCache != nil {
		ctx = auth.WithPermissionCache(ctx, s.permissionCache)
	}

	// Set permission enforcement based on config
	ctx = auth.WithPermissionEnforcement(ctx, s.config.Features.EnforceAIAgentOperate)

	// Add meta-tool filter to context if headers are provided
	allowList := parseToolList(lcAllowMetaTools)
	denyList := parseToolList(lcDenyMetaTools)
	if allowList != nil || denyList != nil {
		ctx = auth.WithMetaToolFilter(ctx, &auth.MetaToolFilter{
			AllowList: allowList,
			DenyList:  denyList,
		})
	}

	// Handle OID switching if tool requires it and OID is provided
	tool, ok := tools.GetTool(toolName)
	if !ok {
		s.writeJSONRPCError(w, id, -32601, "Tool not found", fmt.Sprintf("Unknown tool: %s", toolName))
		return
	}

	// The profile (or X-MCP-Tools allowlist) must bound what can be CALLED, not
	// merely what tools/list advertises. Otherwise a caller that deliberately
	// pinned itself to a narrow endpoint — say /mcp/cloud_security_readonly —
	// could still invoke any registered tool, which is exactly the containment
	// an agent operator chose that endpoint to get.
	allowedTools, err := s.getToolsForRequest(r)
	if err != nil {
		s.writeJSONRPCError(w, id, -32000, "Invalid request", err.Error())
		return
	}
	if !slices.Contains(allowedTools, toolName) {
		s.logger.Warn("Rejected tool call outside the request's allowed set",
			"request_id", requestID,
			"tool", toolName,
			"profile", s.getActiveProfile(r))
		s.writeJSONRPCError(w, id, -32601, "Tool not available",
			fmt.Sprintf("Tool '%s' is not available on this endpoint; it is outside the active profile's tool set", toolName))
		return
	}
	// Tools reached indirectly through lc_call_tool are bounded by the same set,
	// except on the api_access endpoint whose entire contract is registry-wide
	// raw dispatch — bounding the meta-tool to a profile that contains only the
	// meta-tool would leave it able to call nothing at all.
	if s.getActiveProfile(r) != ProfileAPIAccess {
		ctx = auth.WithAllowedTools(ctx, allowedTools)
	}

	if tool.NeedsOID() {
		// Resolve the OID the call will actually execute against: the explicit
		// argument when given, otherwise the OID already pinned on the auth
		// context (in any mode). The ai_agent.operate check keys off that
		// effective OID so that omitting the argument cannot bypass it.
		effectiveOID := ""
		if oidParam, ok := arguments["oid"].(string); ok && oidParam != "" {
			var err error
			ctx, err = auth.WithOID(ctx, oidParam, s.logger)
			if err != nil {
				s.writeJSONRPCError(w, id, -32000, "Invalid OID", fmt.Sprintf("Failed to switch OID: %v", err))
				return
			}
			effectiveOID = oidParam
		} else if isJWTPassthrough {
			// JWT passthrough mode requires OID in tool arguments
			s.writeJSONRPCError(w, id, -32602, "Missing parameter",
				fmt.Sprintf("'oid' parameter is required for tool '%s' when using JWT authentication", toolName))
			return
		} else {
			effectiveOID = authCtx.OID
		}

		// This ensures organizations can block AI agent access whatever the auth
		// mode. Skip the check for tools marked with SkipsAIAgentPermission, and
		// for genuinely org-less contexts (the call fails downstream anyway).
		if effectiveOID != "" && !tool.SkipsAIAgentPermissionCheck() {
			if err := s.checkAIAgentPermission(ctx, effectiveOID); err != nil {
				s.writeJSONRPCError(w, id, -32000, "Permission denied", err.Error())
				return
			}
		}
	}

	// Call the tool handler
	s.logger.Info("Executing tool handler", "request_id", requestID, "tool", toolName)
	toolStartTime := time.Now()
	result, err := tool.Invoke(ctx, arguments)
	toolDuration := time.Since(toolStartTime)
	if err != nil {
		s.logger.Info("Tool execution failed", "request_id", requestID, "tool", toolName, "duration_ms", toolDuration.Milliseconds(), "error", err.Error())
		s.writeJSONRPCError(w, id, -32000, "Tool execution error", err.Error())
		return
	}
	s.logger.Info("Tool execution completed", "request_id", requestID, "tool", toolName, "duration_ms", toolDuration.Milliseconds())

	// Record operation metrics
	if s.metricsManager != nil {
		s.metricsManager.RecordOperation(authCtx)
	}

	// Wrap large results with GCS if available
	wrappedResult := gcs.WrapMCPResult(ctx, result, toolName)

	totalDuration := time.Since(startTime)
	s.logger.Info("Tool call completed successfully", "request_id", requestID, "tool", toolName, "total_duration_ms", totalDuration.Milliseconds())

	// Return success response
	s.writeJSONRPCSuccess(w, id, wrappedResult)
}

func (s *Server) handleToolsList(w http.ResponseWriter, r *http.Request, id interface{}) {
	// Get tools for this request (may be from profile or X-MCP-Tools header)
	toolNames, err := s.getToolsForRequest(r)
	if err != nil {
		// Error from header parsing/validation
		s.writeJSONRPCError(w, id, -32602, "Invalid params", err.Error())
		return
	}

	// Determine if we need to add OID parameter to tools
	// OID parameter is needed for multi-org modes (UID modes) but not for single-org mode (Normal)
	// If server has credentials in Normal mode, OID is fixed and not needed
	// If server has credentials in UID mode or no server credentials (OAuth), OID is needed
	needsOIDParam := true
	if s.serverAuthCtx != nil && s.serverAuthCtx.Mode == auth.AuthModeNormal {
		// Server has fixed OID credentials, no need for OID parameter
		needsOIDParam = false
	}

	toolList := make([]map[string]interface{}, 0, len(toolNames))
	for _, name := range toolNames {
		tool, ok := tools.GetTool(name)
		if !ok {
			continue
		}

		schema := tool.ToolSchema()

		// Add OID parameter for tools that require it when in multi-org mode
		if tool.NeedsOID() && needsOIDParam {
			schema = tools.AddOIDToToolSchema(schema)
		}

		toolList = append(toolList, map[string]interface{}{
			"name":        tool.ToolName(),
			"description": schema.Description,
			"inputSchema": schema.InputSchema,
		})
	}

	s.writeJSONRPCSuccess(w, id, map[string]interface{}{
		"tools": toolList,
	})
}

// jwtCoversOID reports whether a LimaCharlie JWT's own claims authorize the
// requested organization.
//
// It fails OPEN when the token carries no usable org list, which is required for
// correctness rather than laxness: thin user tokens legitimately carry oid="-"
// and no per-org claims, and those callers resolve their orgs downstream. So the
// answer is "no" only when the claims carry a concrete org list that excludes
// the requested OID — the case where the caller is naming someone else's org.
func (s *Server) jwtCoversOID(jwtString, oid, requestID string) bool {
	claims, err := auth.ParseAndValidateLimaCharlieJWT(jwtString)
	if err != nil {
		// Not a parseable LC JWT (e.g. an MCP OAuth token): nothing to compare
		// against here, and the credential was already validated upstream.
		return true
	}

	if oidCoveredByClaims(claims.OIDs, oid) {
		return true
	}

	s.logger.Warn("Rejected X-LC-OID not present in token org claims",
		"request_id", requestID,
		"requested_oid", oid,
		"token_oids", claims.OIDs)
	return false
}

// oidCoveredByClaims decides whether a token's org claims authorize the
// requested OID. Returns true when the claims list the OID, and also when the
// list holds no concrete org at all (a thin token) — see jwtCoversOID for why
// that must fail open.
func oidCoveredByClaims(claimOIDs []string, oid string) bool {
	concrete := false
	for _, claimOID := range claimOIDs {
		if claimOID == oid {
			return true
		}
		// "-" is the thin-token placeholder, not a real org.
		if claimOID != "" && claimOID != "-" {
			concrete = true
		}
	}
	return !concrete
}

func (s *Server) extractUIDFromToken(token string) (string, string, string, error) {
	// Try parsing as LimaCharlie JWT first (for API gateway / internal services)
	if auth.IsJWTFormat(token) {
		claims, err := auth.ParseAndValidateLimaCharlieJWT(token)
		if err == nil {
			// Valid LimaCharlie JWT - passthrough mode
			s.logger.Info("Authenticated via LimaCharlie JWT passthrough",
				"uid", claims.UID,
				"ident", claims.Ident,
				"is_user_token", claims.IsUserToken,
				"oids", claims.OIDs)

			// Return: (uid, jwt token itself, empty firebase token, nil)
			// Empty firebase token signals JWT passthrough mode
			return claims.UID, token, "", nil
		}
		s.logger.Debug("Not a valid LimaCharlie JWT, trying OAuth token validation", "error", err)
	}

	// Fall back to MCP OAuth access token validation (for external clients)
	// SECURITY: Validate MCP OAuth access token (NOT Firebase token directly)
	// The Bearer token here is the MCP-issued access token from /token endpoint

	// Check if OAuth is configured
	if s.tokenManager == nil {
		return "", "", "", fmt.Errorf("invalid token: OAuth not configured and token is not a valid LimaCharlie JWT")
	}

	// Validate the MCP access token using token manager
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Validate and get token info
	validation, err := s.tokenManager.ValidateAccessToken(ctx, token, true)
	if err != nil {
		s.logger.Error("Token validation error", "error", err)
		return "", "", "", fmt.Errorf("token validation failed: %w", err)
	}

	if !validation.Valid {
		return "", "", "", fmt.Errorf("invalid or expired token: %s", validation.Error)
	}

	// Return the Firebase UID, LimaCharlie JWT (exchanged from Firebase token), and Firebase ID token
	// The Firebase ID token is needed for regenerating JWTs with OID when switching orgs
	return validation.UID, validation.LimaCharlieJWT, validation.FirebaseIDToken, nil
}

func (s *Server) writeJSONRPCSuccess(w http.ResponseWriter, id interface{}, result interface{}) {
	rw := NewResponseWriter(w, s.logger)
	rw.WriteJSONRPCSuccess(id, result)
}

func (s *Server) writeJSONRPCError(w http.ResponseWriter, id interface{}, code int, message string, data string) {
	rw := NewResponseWriter(w, s.logger)
	rw.WriteJSONRPCError(id, code, message, data)
}

// parseToolList parses a comma-separated list of tool names from a header value
// Returns nil if the header is empty or only contains whitespace
func parseToolList(header string) []string {
	if header == "" {
		return nil
	}
	parts := strings.Split(header, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// checkAIAgentPermission verifies that the current credentials have the ai_agent.operate
// permission for the specified organization.
func (s *Server) checkAIAgentPermission(ctx context.Context, oid string) error {
	// Check if permission enforcement is enabled
	if !auth.IsPermissionEnforcementEnabled(ctx) {
		return nil
	}

	// Get permission cache from context
	permCache := auth.GetPermissionCache(ctx)
	if permCache == nil {
		// Permission checking not configured - allow by default
		return nil
	}

	// Get organization to call WhoAmI
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}

	// Check for ai_agent.operate permission
	hasPermission, err := permCache.CheckPermission(ctx, org, oid, "ai_agent.operate")
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}

	if !hasPermission {
		return fmt.Errorf("access denied: missing 'ai_agent.operate' permission for organization %s", oid)
	}

	return nil
}
