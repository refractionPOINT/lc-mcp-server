package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/gcs"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

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

	// Verify and extract UID, LimaCharlie JWT, and Firebase token from MCP access token
	// The JWT has been exchanged from Firebase ID token to LimaCharlie JWT
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

	// Create initial auth context with LimaCharlie JWT (exchanged from Firebase token)
	// Store Firebase ID token for JWT regeneration when switching orgs
	authCtx := &auth.AuthContext{
		Mode:            auth.AuthModeUIDOAuth,
		UID:             uid,
		JWTToken:        limaCharlieJWT,  // LimaCharlie JWT for API authentication
		FirebaseIDToken: firebaseIDToken, // Firebase token for JWT regeneration per org
	}

	// JWT passthrough mode detection: no Firebase token means direct JWT
	isJWTPassthrough := firebaseIDToken == ""

	// Create request context with auth
	ctx := r.Context()
	ctx = auth.WithRequestID(ctx, requestID)
	ctx = auth.WithAuthContext(ctx, authCtx)
	ctx = auth.WithSDKCache(ctx, s.sdkCache)
	if s.gcsManager != nil {
		ctx = gcs.WithGCSManager(ctx, s.gcsManager)
	}

	// Handle OID switching if tool requires it and OID is provided
	tool, ok := tools.GetTool(toolName)
	if !ok {
		s.writeJSONRPCError(w, id, -32601, "Tool not found", fmt.Sprintf("Unknown tool: %s", toolName))
		return
	}

	if tool.RequiresOID {
		if oidParam, ok := arguments["oid"].(string); ok && oidParam != "" {
			var err error
			ctx, err = auth.WithOID(ctx, oidParam, s.logger)
			if err != nil {
				s.writeJSONRPCError(w, id, -32000, "Invalid OID", fmt.Sprintf("Failed to switch OID: %v", err))
				return
			}
		} else if isJWTPassthrough {
			// JWT passthrough mode requires OID in tool arguments
			s.writeJSONRPCError(w, id, -32602, "Missing parameter",
				fmt.Sprintf("'oid' parameter is required for tool '%s' when using JWT authentication", toolName))
			return
		}
	}

	// Call the tool handler
	s.logger.Info("Executing tool handler", "request_id", requestID, "tool", toolName)
	toolStartTime := time.Now()
	result, err := tool.Handler(ctx, arguments)
	toolDuration := time.Since(toolStartTime)
	if err != nil {
		s.logger.Info("Tool execution failed", "request_id", requestID, "tool", toolName, "duration_ms", toolDuration.Milliseconds(), "error", err.Error())
		s.writeJSONRPCError(w, id, -32000, "Tool execution error", err.Error())
		return
	}
	s.logger.Info("Tool execution completed", "request_id", requestID, "tool", toolName, "duration_ms", toolDuration.Milliseconds())

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

	toolList := make([]map[string]interface{}, 0, len(toolNames))
	for _, name := range toolNames {
		tool, ok := tools.GetTool(name)
		if !ok {
			continue
		}

		schema := tool.Schema

		// HTTP server is always in UID OAuth mode, so dynamically add OID parameter
		// if the tool requires it
		if tool.RequiresOID {
			schema = tools.AddOIDToToolSchema(schema)
		}

		toolList = append(toolList, map[string]interface{}{
			"name":        tool.Name,
			"description": tool.Description,
			"inputSchema": schema.InputSchema,
		})
	}

	s.writeJSONRPCSuccess(w, id, map[string]interface{}{
		"tools": toolList,
	})
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
