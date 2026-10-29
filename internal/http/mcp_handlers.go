package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/gcs"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// Note: tools.GetOrganization is used for permission checking

func (s *Server) handleMCPRequest(w http.ResponseWriter, r *http.Request) {
	// DNS-rebinding defence (Streamable HTTP, all revisions): a browser
	// context from an untrusted origin must not reach the MCP endpoint.
	if origin := r.Header.Get("Origin"); !s.originAllowed(origin) {
		s.logger.Warn("Rejected MCP request from disallowed Origin", "origin", origin, "path", r.URL.Path)
		s.writeRPCError(w, nil, newRPCError(http.StatusForbidden, rpcInvalidRequest, "Forbidden", "origin not allowed"))
		return
	}

	// The endpoint only takes POST. GET (the legacy standalone SSE stream)
	// and DELETE (legacy session termination) are answered with 405, which
	// every protocol revision allows.
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Extract API version from context for observability
	apiVersion := GetVersionFromContext(r.Context())
	s.logger.Debug("Handling MCP request", "api_version", apiVersion, "path", r.URL.Path)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.writeRPCError(w, nil, newRPCError(http.StatusRequestEntityTooLarge, rpcInvalidRequest, "Invalid Request", "request body too large"))
			return
		}
		s.writeRPCError(w, nil, newRPCError(http.StatusBadRequest, rpcParseError, "Parse error", "failed to read request body"))
		return
	}

	msg, rpcErr := parseMCPMessage(body)
	if rpcErr != nil {
		var id json.RawMessage
		if msg != nil {
			id = msg.id
		}
		s.writeRPCError(w, id, rpcErr)
		return
	}

	if msg.notification {
		// Notifications get no JSON-RPC response. None of the ones clients
		// send (notifications/initialized, notifications/cancelled, ...)
		// need any action here: requests are answered synchronously and
		// carry no session state.
		s.logger.Debug("MCP notification received", "method", msg.method)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	call := msg.call
	if rpcErr := classifyEra(r, call); rpcErr != nil {
		s.writeRPCError(w, call.id, rpcErr)
		return
	}

	if call.era == eraModern {
		s.dispatchModern(w, r, call)
		return
	}
	s.dispatchLegacy(w, r, call)
}

// dispatchModern serves a 2026-07-28 request.
func (s *Server) dispatchModern(w http.ResponseWriter, r *http.Request, call *mcpCall) {
	switch call.method {
	case methodServerDiscover:
		// Mirrors initialize in the legacy era: the first thing a client
		// does, so an OAuth client learns here that it must sign in.
		if !s.requestHasCredentials(r) {
			s.writeAuthChallenge(w, r, call.id, "", "Authentication required: sign in with OAuth, or provide X-LC-UID + X-LC-API-KEY or X-LC-OID + X-LC-API-KEY headers")
			return
		}
		s.handleDiscover(w, call)
	case "tools/list":
		s.handleToolsList(w, r, call)
	case "tools/call":
		s.handleToolCall(w, r, call)
	default:
		// Includes the RPCs 2026-07-28 removed (ping, initialize,
		// logging/setLevel) and features this server does not offer.
		s.writeRPCError(w, call.id, newRPCError(http.StatusNotFound, rpcMethodNotFound, "Method not found", fmt.Sprintf("Unknown method: %s", call.method)))
	}
}

// dispatchLegacy serves a request from a client using an initialize-based
// protocol revision (2025-11-25 and earlier).
func (s *Server) dispatchLegacy(w http.ResponseWriter, r *http.Request, call *mcpCall) {
	switch call.method {
	case "ping":
		s.writeRPCResult(w, call, map[string]any{}, false)
	case "initialize":
		// Opening a session needs a credential so that an OAuth client learns,
		// before it lists or calls anything, that it must sign in. tools/list
		// stays open: the tool catalog is public and holds no org data.
		if !s.requestHasCredentials(r) {
			s.writeAuthChallenge(w, r, call.id, "", "Authentication required: sign in with OAuth, or provide X-LC-UID + X-LC-API-KEY or X-LC-OID + X-LC-API-KEY headers")
			return
		}
		s.handleInitialize(w, call)
	case methodServerDiscover:
		// Reached only when a legacy version is carried in _meta. Discovery
		// is answered for any supported version.
		if !s.requestHasCredentials(r) {
			s.writeAuthChallenge(w, r, call.id, "", "Authentication required: sign in with OAuth, or provide X-LC-UID + X-LC-API-KEY or X-LC-OID + X-LC-API-KEY headers")
			return
		}
		s.handleDiscover(w, call)
	case "tools/list":
		s.handleToolsList(w, r, call)
	case "tools/call":
		s.handleToolCall(w, r, call)
	default:
		s.writeRPCError(w, call.id, newRPCError(http.StatusOK, rpcMethodNotFound, "Method not found", fmt.Sprintf("Unknown method: %s", call.method)))
	}
}

func (s *Server) handleInitialize(w http.ResponseWriter, call *mcpCall) {
	var params struct {
		ProtocolVersion string             `json:"protocolVersion"`
		ClientInfo      mcp.Implementation `json:"clientInfo"`
	}
	// initialize params are informational here: a malformed field must not
	// stop a client from connecting, so decode errors are ignored.
	_ = json.Unmarshal(call.params, &params)

	negotiated := negotiateLegacyVersion(params.ProtocolVersion)
	s.logger.Info("MCP client initializing",
		"client", params.ClientInfo.Name,
		"version", params.ClientInfo.Version,
		"requested_protocol", params.ProtocolVersion,
		"negotiated_protocol", negotiated)

	s.writeRPCResult(w, call, map[string]any{
		"protocolVersion": negotiated,
		"capabilities":    serverCapabilities(),
		"serverInfo":      serverInfo(),
	}, false)
}

func (s *Server) handleDiscover(w http.ResponseWriter, call *mcpCall) {
	clientName, clientVersion := "", ""
	if call.clientInfo != nil {
		clientName, clientVersion = call.clientInfo.Name, call.clientInfo.Version
	}
	s.logger.Info("MCP client discovering",
		"client", clientName,
		"version", clientVersion,
		"protocol", call.protocolVersion)

	// DiscoverResult is a modern type: it always carries resultType, the
	// caching hints and the server identity in _meta, whichever version the
	// caller named.
	modern := *call
	modern.era = eraModern
	s.writeRPCResult(w, &modern, map[string]any{
		"supportedVersions": supportedProtocolVersions,
		"capabilities":      serverCapabilities(),
	}, true)
}

func (s *Server) handleToolCall(w http.ResponseWriter, r *http.Request, call *mcpCall) {
	id := call.id
	// Generate request ID for tracking
	requestID := fmt.Sprintf("req_%d", time.Now().UnixNano())
	startTime := time.Now()

	var params struct {
		Name      *string         `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(call.params, &params); err != nil || params.Name == nil || *params.Name == "" {
		s.writeRPCError(w, id, newRPCError(http.StatusOK, rpcInvalidParams, "Invalid params", "Missing or invalid 'name' parameter"))
		return
	}
	toolName := *params.Name

	// arguments must be an object. Anything else is treated as no arguments,
	// as this server always has: some client libraries encode an empty map
	// as [] and would otherwise fail every argument-less call. A tool that
	// needed arguments then reports what is missing.
	arguments := map[string]interface{}{}
	if len(params.Arguments) > 0 {
		var decoded map[string]interface{}
		if err := json.Unmarshal(params.Arguments, &decoded); err == nil && decoded != nil {
			arguments = decoded
		} else if string(params.Arguments) != "null" {
			s.logger.Debug("Ignoring non-object tool arguments", "tool", toolName)
		}
	}

	clientName := ""
	if call.clientInfo != nil {
		clientName = call.clientInfo.Name
	}
	s.logger.Info("Tool call started", "request_id", requestID, "tool", toolName, "client", clientName, "protocol", call.protocolVersion)

	lcAllowMetaTools := r.Header.Get("X-LC-ALLOW-META-TOOLS")
	lcDenyMetaTools := r.Header.Get("X-LC-DENY-META-TOOLS")

	resolved, authErr := s.resolveRequestAuth(r, requestID)
	if authErr != nil {
		authErr.write(s, w, r, id)
		return
	}
	authCtx := resolved.authCtx
	isJWTPassthrough := resolved.jwtPassthrough

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
	// Carried so indirect dispatch applies the same "oid is required" rule.
	ctx = auth.WithJWTPassthrough(ctx, isJWTPassthrough)

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
		s.writeJSONRPCError(w, id, rpcInvalidParams, fmt.Sprintf("Unknown tool: %s", toolName), "")
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
		// An unknown tool as far as this endpoint is concerned, which the
		// spec reports as invalid params.
		s.writeJSONRPCError(w, id, rpcInvalidParams, fmt.Sprintf("Unknown tool: %s", toolName),
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
		var effectiveOID, toolErr string
		ctx, effectiveOID, toolErr = s.resolveToolOID(ctx, toolName, arguments, resolved)
		if toolErr != "" {
			// Reported as a tool execution error so the model can correct the
			// argument and retry.
			s.writeToolError(w, call, toolErr)
			return
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
		// A failure inside the tool is a tool execution error (isError), not
		// a protocol error, so the model sees the reason and can adapt.
		s.writeToolError(w, call, err.Error())
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
	s.writeRPCResult(w, call, wrappedResult, false)
}

// resolveToolOID picks the organization an org-scoped tool call runs against:
// the oid argument when given (switching the context to it), otherwise the
// org the credential is pinned to. A JWT not pinned to one org must name it.
// toolErr is set, for the model to see, when the call cannot proceed.
func (s *Server) resolveToolOID(ctx context.Context, toolName string, arguments map[string]interface{}, resolved *resolvedAuth) (context.Context, string, string) {
	if oidParam, ok := arguments["oid"].(string); ok && oidParam != "" {
		switched, err := auth.WithOID(ctx, oidParam, s.logger)
		if err != nil {
			return ctx, "", fmt.Sprintf("Invalid OID: failed to switch OID: %v", err)
		}
		return switched, oidParam, ""
	}
	if resolved.jwtPassthrough {
		return ctx, "", fmt.Sprintf("Missing parameter: 'oid' parameter is required for tool '%s' when using JWT authentication", toolName)
	}
	return ctx, resolved.authCtx.OID, ""
}

// writeToolError answers a tools/call with a tool execution error.
func (s *Server) writeToolError(w http.ResponseWriter, call *mcpCall, message string) {
	s.writeRPCResult(w, call, tools.ErrorResult(message), false)
}

// parseLimaCharlieJWT verifies a LimaCharlie JWT. A variable so that tests can
// present tokens signed with a test key.
var parseLimaCharlieJWT = auth.ParseAndValidateLimaCharlieJWT

// resolvedAuth is the credential a request presents, resolved once by
// resolveRequestAuth so that tools/list and tools/call agree on it.
type resolvedAuth struct {
	authCtx *auth.AuthContext
	// jwtPassthrough is set for a LimaCharlie JWT that is not pinned to one
	// organization: every org-scoped tool call must then name its oid.
	jwtPassthrough bool
}

// pinnedOID returns the organization the credential fixes every call to, or
// "" when the caller may (or must) choose one per call. Only organization
// credentials (org API key, org JWT, server-wide org credentials) qualify:
// auth.WithOID refuses to switch them, so a listing without oid can never
// hide an org the caller could otherwise reach. A user key sent with
// X-LC-OID only defaults to that org and can still switch, so it is not
// pinned.
func (a *resolvedAuth) pinnedOID() string {
	if a == nil || a.authCtx == nil || a.jwtPassthrough || a.authCtx.Mode != auth.AuthModeNormal {
		return ""
	}
	return a.authCtx.OID
}

// authFailure describes why a request's credentials were rejected.
type authFailure struct {
	// challenge answers with HTTP 401 and a WWW-Authenticate header, so an
	// OAuth client signs in again; otherwise a JSON-RPC error is returned.
	challenge  bool
	oauthError string
	message    string
	detail     string
}

func (f *authFailure) write(s *Server, w http.ResponseWriter, r *http.Request, id json.RawMessage) {
	if f.challenge {
		s.writeAuthChallenge(w, r, id, f.oauthError, f.detail)
		return
	}
	s.writeJSONRPCError(w, id, rpcServerError, f.message, f.detail)
}

// resolveRequestAuth determines the credentials a request carries:
//  1. Bearer token → OAuth access token or LimaCharlie JWT passthrough
//  2. X-LC-UID + X-LC-API-KEY → user API key (X-LC-OID sets its default org)
//  3. X-LC-OID + X-LC-API-KEY → organization API key
//  4. server-wide credentials from the environment
//  5. none of the above → unauthorized
func (s *Server) resolveRequestAuth(r *http.Request, requestID string) (*resolvedAuth, *authFailure) {
	authHeader := r.Header.Get("Authorization")
	lcUID := r.Header.Get("X-LC-UID")
	lcOID := r.Header.Get("X-LC-OID")
	lcAPIKey := r.Header.Get("X-LC-API-KEY")

	// Validate the credential headers at the boundary rather than relying on
	// downstream UUID checks: these values flow into cache keys and request
	// paths, so a malformed one must never get that far.
	if lcOID != "" {
		if err := auth.ValidateOID(lcOID); err != nil {
			return nil, &authFailure{message: "Unauthorized", detail: fmt.Sprintf("Invalid X-LC-OID header: %v", err)}
		}
	}
	if lcUID != "" {
		if err := auth.ValidateUIDFormat(lcUID); err != nil {
			return nil, &authFailure{message: "Unauthorized", detail: fmt.Sprintf("Invalid X-LC-UID header: %v", err)}
		}
	}
	if lcAPIKey != "" {
		if err := auth.ValidateAPIKey(lcAPIKey); err != nil {
			return nil, &authFailure{message: "Unauthorized", detail: fmt.Sprintf("Invalid X-LC-API-KEY header: %v", err)}
		}
	}

	if authHeader != "" {
		// Bearer token provided - use OAuth/JWT passthrough
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			return nil, &authFailure{challenge: true, oauthError: "invalid_token", detail: "Invalid Authorization header format"}
		}

		bearerToken := parts[1]

		// Verify and extract UID, LimaCharlie JWT, and Firebase token from MCP access token
		s.logger.Info("Extracting UID from token", "request_id", requestID)
		tokenStartTime := time.Now()
		uid, limaCharlieJWT, firebaseIDToken, err := s.extractUIDFromToken(bearerToken)
		tokenDuration := time.Since(tokenStartTime)
		if err != nil {
			s.logger.Info("Token extraction failed", "request_id", requestID, "duration_ms", tokenDuration.Milliseconds(), "error", err.Error())
			if errors.Is(err, errInvalidCredentials) {
				return nil, &authFailure{challenge: true, oauthError: "invalid_token", detail: "The access token is invalid or expired"}
			}
			return nil, &authFailure{message: "Unauthorized", detail: fmt.Sprintf("Invalid token: %v", err)}
		}
		s.logger.Info("Token extraction completed", "request_id", requestID, "duration_ms", tokenDuration.Milliseconds())

		// JWT passthrough mode detection: no Firebase token means direct JWT
		isJWTPassthrough := firebaseIDToken == ""

		if uid == "" && isJWTPassthrough && lcOID != "" {
			// Org API key JWT passthrough: no UID in token, use OID from header.
			// The OID comes from a header while the credential is the JWT, so
			// confirm the JWT's own claims cover that org before pinning to it —
			// otherwise a caller could present a valid token for org A and name
			// org B. (The gateway authorizes independently; this is the
			// server-side half of that boundary.)
			if !s.jwtCoversOID(limaCharlieJWT, lcOID, requestID) {
				return nil, &authFailure{message: "Unauthorized", detail: "X-LC-OID is not covered by the presented token's organization claims"}
			}
			// The OID is pinned, so passthrough semantics (requiring OID in
			// every tool call) don't apply.
			s.logger.Debug("Authenticated via org JWT passthrough", "request_id", requestID, "oid", lcOID)
			return &resolvedAuth{authCtx: &auth.AuthContext{
				Mode:     auth.AuthModeNormal,
				OID:      lcOID,
				JWTToken: limaCharlieJWT,
			}}, nil
		}
		s.logger.Debug("Authenticated via Bearer token", "request_id", requestID, "uid", uid, "jwt_passthrough", isJWTPassthrough)
		return &resolvedAuth{
			authCtx: &auth.AuthContext{
				Mode:            auth.AuthModeUIDOAuth,
				UID:             uid,
				JWTToken:        limaCharlieJWT,  // LimaCharlie JWT for API authentication
				FirebaseIDToken: firebaseIDToken, // Firebase token for JWT regeneration per org
			},
			jwtPassthrough: isJWTPassthrough,
		}, nil
	}

	if lcUID != "" && lcAPIKey != "" {
		// Header-based user credentials (X-LC-UID + X-LC-API-KEY)
		// If X-LC-OID is also provided it becomes the default org; the key
		// can still switch to others with an oid argument.
		if lcOID != "" {
			s.logger.Debug("Authenticated via user header credentials with OID", "request_id", requestID, "uid", lcUID, "oid", lcOID)
		} else {
			s.logger.Debug("Authenticated via user header credentials", "request_id", requestID, "uid", lcUID)
		}
		return &resolvedAuth{authCtx: &auth.AuthContext{
			Mode:   auth.AuthModeUIDKey,
			UID:    lcUID,
			APIKey: lcAPIKey,
			OID:    lcOID, // Empty if not provided, which is fine
		}}, nil
	}

	if lcOID != "" && lcAPIKey != "" {
		// Header-based org credentials (X-LC-OID + X-LC-API-KEY)
		s.logger.Debug("Authenticated via org header credentials", "request_id", requestID, "oid", lcOID)
		return &resolvedAuth{authCtx: &auth.AuthContext{
			Mode:   auth.AuthModeNormal,
			OID:    lcOID,
			APIKey: lcAPIKey,
		}}, nil
	}

	if s.serverAuthCtx != nil && s.serverAuthCtx.HasCredentials() {
		// No request credentials - use server-wide credentials
		s.logger.Debug("Using server-wide credentials", "request_id", requestID, "uid", s.serverAuthCtx.UID, "mode", s.serverAuthCtx.Mode.String())
		return &resolvedAuth{authCtx: s.serverAuthCtx}, nil
	}

	return nil, &authFailure{challenge: true, detail: "Missing authentication: provide Authorization header, X-LC-UID + X-LC-API-KEY, or X-LC-OID + X-LC-API-KEY headers"}
}

func (s *Server) handleToolsList(w http.ResponseWriter, r *http.Request, call *mcpCall) {
	toolList, err := s.listTools(r, s.oidParamNeeded(r, call))
	if err != nil {
		// Error from header parsing/validation
		s.writeJSONRPCError(w, call.id, rpcInvalidParams, "Invalid params", err.Error())
		return
	}
	s.writeRPCResult(w, call, map[string]any{"tools": toolList}, true)
}

// oidParamNeeded reports whether org-scoped tools are listed with the
// injected oid parameter for this request.
//
// Legacy clients keep the listing they have always had: oid unless the server
// runs with its own org credentials.
//
// For modern (2026-07-28) requests the spec lets the tool list vary by the
// authorization presented, so the decision follows the credential the call
// would actually use (resolveRequestAuth, including the server-wide fallback):
// oid is left out only when that credential is pinned to one org, because the
// credential already names the org and asking the model to repeat it only
// invites mistakes. Credentials that fail to resolve keep oid; tools/list
// never rejects a caller.
func (s *Server) oidParamNeeded(r *http.Request, call *mcpCall) bool {
	if call.era != eraModern {
		return s.serverAuthCtx == nil || s.serverAuthCtx.Mode != auth.AuthModeNormal
	}
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		// Among Bearer tokens only an org-level LimaCharlie JWT can pin an
		// org; an MCP OAuth token always resolves to a multi-org user. Check
		// that locally first, so a listing never costs a token-store lookup.
		token, ok := strings.CutPrefix(authHeader, "Bearer ")
		if !ok || !auth.IsJWTFormat(token) {
			return true
		}
		if claims, err := parseLimaCharlieJWT(token); err != nil || claims.UID != "" {
			return true
		}
	}
	// Everything left resolves locally: header keys, a verified LimaCharlie
	// JWT, or the server-wide credentials.
	resolved, failure := s.resolveRequestAuth(r, fmt.Sprintf("list_%d", time.Now().UnixNano()))
	if failure != nil {
		return true
	}
	return resolved.pinnedOID() == ""
}

// listTools returns the tool definitions this request may see, sorted by name
// so that the listing is stable across requests (clients cache it, and a
// stable order keeps LLM prompt caches warm).
func (s *Server) listTools(r *http.Request, needsOIDParam bool) ([]mcp.Tool, error) {
	// Get tools for this request (may be from profile or X-MCP-Tools header)
	toolNames, err := s.getToolsForRequest(r)
	if err != nil {
		return nil, err
	}

	toolList := make([]mcp.Tool, 0, len(toolNames))
	seen := make(map[string]bool, len(toolNames))
	for _, name := range toolNames {
		tool, ok := tools.GetTool(name)
		if !ok || seen[tool.ToolName()] {
			continue
		}
		seen[tool.ToolName()] = true

		schema := tool.ToolSchema()

		// Add OID parameter for tools that require it when in multi-org mode
		if tool.NeedsOID() && needsOIDParam {
			schema = tools.AddOIDToToolSchema(schema)
		}
		// The registry name is the one tools/call dispatches on.
		schema.Name = tool.ToolName()

		// The full definition goes out, including annotations (read-only /
		// destructive hints, title) and any output schema, so clients can
		// gate and present tools correctly.
		toolList = append(toolList, schema)
	}
	sort.Slice(toolList, func(i, j int) bool { return toolList[i].Name < toolList[j].Name })
	return toolList, nil
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
	claims, err := parseLimaCharlieJWT(jwtString)
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
		claims, err := parseLimaCharlieJWT(token)
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
		return "", "", "", fmt.Errorf("%w: OAuth not configured and token is not a valid LimaCharlie JWT", errInvalidCredentials)
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
		if validation.Transient {
			return "", "", "", fmt.Errorf("token could not be validated: %s", validation.Error)
		}
		return "", "", "", fmt.Errorf("%w: invalid or expired token: %s", errInvalidCredentials, validation.Error)
	}

	// Return the Firebase UID, LimaCharlie JWT (exchanged from Firebase token), and Firebase ID token
	// The Firebase ID token is needed for regenerating JWTs with OID when switching orgs
	return validation.UID, validation.LimaCharlieJWT, validation.FirebaseIDToken, nil
}

// writeJSONRPCError writes a JSON-RPC error carried by an HTTP 200, the
// status for errors raised while processing a well-formed request.
func (s *Server) writeJSONRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string, data string) {
	var d any
	if data != "" {
		d = data
	}
	s.writeRPCError(w, id, newRPCError(http.StatusOK, code, message, d))
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
