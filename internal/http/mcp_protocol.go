package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

// This file holds the MCP wire protocol for the HTTP transport. The server is
// "dual-era" as defined by the 2026-07-28 specification:
//
//   - Modern requests (2026-07-28) carry their protocol version, client
//     capabilities and client info in params._meta, are validated against the
//     mirrored MCP-Protocol-Version / Mcp-Method / Mcp-Name headers, and are
//     served statelessly. There is no initialize handshake.
//   - Legacy requests (2025-11-25 and earlier) open with an initialize
//     handshake and carry no per-request metadata.
//
// The era is decided per request from the request itself, so both kinds of
// clients are served concurrently on the same endpoint. The server never held
// per-session state, so the legacy path needs no session either.

const (
	mcpServerName    = "LimaCharlie MCP Server"
	mcpServerVersion = "1.0.0"

	// headerMCPProtocolVersion is the protocol version header defined since
	// 2025-06-18. Header names are case-insensitive; this is the spelling used
	// in the specification text.
	headerMCPProtocolVersion = "MCP-Protocol-Version"

	// methodServerDiscover is the 2026-07-28 discovery RPC.
	methodServerDiscover = "server/discover"

	// toolsListTTLMs is the freshness hint on tools/list and server/discover
	// results. The tool catalog only changes on deploy, so clients may reuse a
	// listing for a few minutes.
	toolsListTTLMs int64 = 5 * 60 * 1000
)

// JSON-RPC and MCP error codes.
const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
	// rpcServerError is the implementation-defined code this server has
	// always used for auth and execution failures. The 2026-07-28 spec keeps
	// existing uses of -32000..-32019 valid.
	rpcServerError = -32000

	// MCP-defined codes (2026-07-28).
	mcpHeaderMismatch             = -32020
	mcpUnsupportedProtocolVersion = -32022
)

// modernProtocolVersions are the stateless, per-request-metadata versions
// this server implements, newest first.
var modernProtocolVersions = []string{mcp.ProtocolVersion20260728}

// legacyProtocolVersions are the initialize-handshake versions this server
// implements, newest first. Kept explicit rather than taken from the SDK so
// that an SDK upgrade can never advertise a version this handler has not been
// written for.
var legacyProtocolVersions = []string{
	mcp.ProtocolVersion20251125,
	mcp.ProtocolVersion20250618,
	mcp.ProtocolVersion20250326,
	mcp.ProtocolVersion20241105,
}

// supportedProtocolVersions lists every version this server speaks, newest
// first, as advertised by server/discover and UnsupportedProtocolVersion.
var supportedProtocolVersions = append(slices.Clone(modernProtocolVersions), legacyProtocolVersions...)

func isModernProtocolVersion(v string) bool { return slices.Contains(modernProtocolVersions, v) }
func isLegacyProtocolVersion(v string) bool { return slices.Contains(legacyProtocolVersions, v) }

// negotiateLegacyVersion picks the version for an initialize response: the
// client's requested version when this server supports it, otherwise the
// newest legacy version (the client then decides whether it can proceed).
// initialize never negotiates a modern version: those versions removed it.
func negotiateLegacyVersion(requested string) string {
	if isLegacyProtocolVersion(requested) {
		return requested
	}
	return legacyProtocolVersions[0]
}

// protocolEra says which generation of the protocol a request uses.
type protocolEra int

const (
	eraLegacy protocolEra = iota
	eraModern
)

// mcpCall is one parsed JSON-RPC request addressed to the MCP endpoint.
type mcpCall struct {
	// id is the request id exactly as sent, so it is echoed back unchanged
	// (a float64 round-trip would corrupt large integer ids).
	id     json.RawMessage
	method string
	// params is the raw params object ("{}" when the request had none).
	params json.RawMessage
	// meta is params._meta split into its top-level keys, or nil.
	meta map[string]json.RawMessage

	era protocolEra
	// protocolVersion is the version the request is served under. For legacy
	// requests it is the MCP-Protocol-Version header value when sent, else "".
	protocolVersion string
	clientInfo      *mcp.Implementation
}

// rpcError is a JSON-RPC error together with the HTTP status that carries it.
type rpcError struct {
	httpStatus int
	code       int
	message    string
	data       any
}

func (e *rpcError) Error() string { return fmt.Sprintf("%d %s", e.code, e.message) }

func newRPCError(httpStatus, code int, message string, data any) *rpcError {
	return &rpcError{httpStatus: httpStatus, code: code, message: message, data: data}
}

// rawMessage is the subset of a JSON-RPC message needed to classify it.
type rawMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  *string         `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

// parsedMessage is the outcome of reading the request body.
type parsedMessage struct {
	// id is the request id when one could be read, so that even a rejected
	// request gets an error correlated with it.
	id json.RawMessage
	// call is set for requests (a message with an id).
	call *mcpCall
	// notification is set for notifications (a message without an id).
	notification bool
	method       string
}

// parseMCPMessage reads and classifies one JSON-RPC message. Batches are
// rejected: they were only ever part of 2025-03-26 and this server never
// implemented them.
func parseMCPMessage(body []byte) (*parsedMessage, *rpcError) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, newRPCError(http.StatusBadRequest, rpcParseError, "Parse error", "empty request body")
	}
	if trimmed[0] == '[' {
		if !json.Valid(trimmed) {
			return nil, newRPCError(http.StatusBadRequest, rpcParseError, "Parse error", "request body is not valid JSON")
		}
		return nil, newRPCError(http.StatusBadRequest, rpcInvalidRequest, "Invalid Request", "JSON-RPC batch requests are not supported")
	}

	var msg rawMessage
	if err := json.Unmarshal(trimmed, &msg); err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			// The body is valid JSON with a mistyped field: still answer
			// with the request id when it can be read.
			partial := &parsedMessage{}
			var idOnly struct {
				ID json.RawMessage `json:"id"`
			}
			if json.Unmarshal(trimmed, &idOnly) == nil && len(idOnly.ID) > 0 && !bytes.Equal(idOnly.ID, []byte("null")) && isValidRequestID(idOnly.ID) {
				partial.id = idOnly.ID
			}
			return partial, newRPCError(http.StatusBadRequest, rpcInvalidRequest, "Invalid Request", fmt.Sprintf("invalid %s field", typeErr.Field))
		}
		return nil, newRPCError(http.StatusBadRequest, rpcParseError, "Parse error", err.Error())
	}

	parsed := &parsedMessage{}
	hasID := len(msg.ID) > 0 && !bytes.Equal(msg.ID, []byte("null"))
	if hasID && isValidRequestID(msg.ID) {
		parsed.id = msg.ID
	}

	if msg.JSONRPC != "2.0" {
		return parsed, newRPCError(http.StatusBadRequest, rpcInvalidRequest, "Invalid Request", "jsonrpc must be '2.0'")
	}

	if hasID && !isValidRequestID(msg.ID) {
		return parsed, newRPCError(http.StatusBadRequest, rpcInvalidRequest, "Invalid Request", "id must be a string or an integer")
	}

	if msg.Method == nil {
		// A JSON-RPC response or error from the client. This server never
		// sends requests to clients, so there is nothing it could answer.
		if len(msg.Result) > 0 || len(msg.Error) > 0 {
			return parsed, newRPCError(http.StatusBadRequest, rpcInvalidRequest, "Invalid Request", "this server does not accept JSON-RPC responses")
		}
		return parsed, newRPCError(http.StatusBadRequest, rpcInvalidRequest, "Invalid Request", "method is required")
	}
	method := *msg.Method
	if method == "" {
		return parsed, newRPCError(http.StatusBadRequest, rpcInvalidRequest, "Invalid Request", "method is required")
	}

	params := msg.Params
	if len(params) == 0 || bytes.Equal(params, []byte("null")) {
		params = json.RawMessage("{}")
	}
	var paramFields map[string]json.RawMessage
	if err := json.Unmarshal(params, &paramFields); err != nil {
		if hasID {
			return parsed, &rpcError{httpStatus: http.StatusBadRequest, code: rpcInvalidParams, message: "Invalid params", data: "params must be an object"}
		}
		return parsed, newRPCError(http.StatusBadRequest, rpcInvalidRequest, "Invalid Request", "params must be an object")
	}

	if !hasID {
		if len(msg.ID) > 0 && !strings.HasPrefix(method, "notifications/") {
			// "id": null on something that is not a notification: MCP
			// requests MUST carry a non-null id.
			return parsed, newRPCError(http.StatusBadRequest, rpcInvalidRequest, "Invalid Request", "id must not be null")
		}
		parsed.notification = true
		parsed.method = method
		return parsed, nil
	}

	call := &mcpCall{id: msg.ID, method: method, params: params}
	if rawMeta, ok := paramFields["_meta"]; ok && !bytes.Equal(rawMeta, []byte("null")) {
		if err := json.Unmarshal(rawMeta, &call.meta); err != nil {
			return parsed, call.invalidParams("params._meta must be an object")
		}
	}
	parsed.call = call
	parsed.method = method
	return parsed, nil
}

// isValidRequestID reports whether raw is a JSON string or integer, the only
// id types MCP allows.
func isValidRequestID(raw json.RawMessage) bool {
	switch raw[0] {
	case '"':
		var s string
		return json.Unmarshal(raw, &s) == nil
	default:
		var n json.Number
		if json.Unmarshal(raw, &n) != nil {
			return false
		}
		_, err := n.Int64()
		return err == nil
	}
}

func (c *mcpCall) invalidParams(detail string) *rpcError {
	return newRPCError(http.StatusBadRequest, rpcInvalidParams, "Invalid params", detail)
}

// metaString returns a string-valued _meta key. ok is false when the key is
// absent; err is set when it is present with another type.
func (c *mcpCall) metaString(key string) (value string, ok bool, err error) {
	raw, present := c.meta[key]
	if !present {
		return "", false, nil
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", true, fmt.Errorf("_meta %q must be a string", key)
	}
	return value, true, nil
}

// classifyEra decides how the request is served and validates the
// protocol-level framing for that era: the version, the mirrored HTTP
// headers, and the required per-request metadata.
func classifyEra(r *http.Request, call *mcpCall) *rpcError {
	headerVersion := strings.TrimSpace(r.Header.Get(headerMCPProtocolVersion))

	metaVersion, hasMetaVersion, err := call.metaString(mcp.MetaKeyProtocolVersion)
	if err != nil {
		return call.invalidParams(err.Error())
	}

	if !hasMetaVersion {
		// No per-request version: a legacy request, unless the client is
		// clearly speaking a modern version without the metadata it requires.
		if call.method == methodServerDiscover || isModernProtocolVersion(headerVersion) {
			return call.invalidParams(fmt.Sprintf("missing required params._meta %q", mcp.MetaKeyProtocolVersion))
		}
		if headerVersion != "" && !isLegacyProtocolVersion(headerVersion) {
			return unsupportedVersion(headerVersion)
		}
		call.era = eraLegacy
		call.protocolVersion = headerVersion
		return nil
	}

	// The header MUST be present and MUST match the body: intermediaries may
	// route on the header while this server acts on the body.
	if headerVersion == "" {
		return newRPCError(http.StatusBadRequest, mcpHeaderMismatch,
			fmt.Sprintf("Header mismatch: missing required %s header", headerMCPProtocolVersion), nil)
	}
	if headerVersion != metaVersion {
		return newRPCError(http.StatusBadRequest, mcpHeaderMismatch,
			fmt.Sprintf("Header mismatch: %s header value %q does not match body value %q", headerMCPProtocolVersion, headerVersion, metaVersion), nil)
	}

	switch {
	case isModernProtocolVersion(metaVersion):
		call.era = eraModern
	case isLegacyProtocolVersion(metaVersion):
		// A legacy version carried the modern way. This server keeps no
		// session state, so the request can be served under legacy rules
		// without a prior initialize.
		call.era = eraLegacy
	default:
		return unsupportedVersion(metaVersion)
	}
	call.protocolVersion = metaVersion

	if raw, ok := call.meta[mcp.MetaKeyClientInfo]; ok {
		var info mcp.Implementation
		if json.Unmarshal(raw, &info) == nil {
			call.clientInfo = &info
		}
	}

	if call.era != eraModern {
		return nil
	}

	if err := mcp.ValidateStandardHeaders(r.Header.Get, metaVersion, mcp.MCPMethod(call.method), call.params); err != nil {
		return newRPCError(http.StatusBadRequest, mcpHeaderMismatch, "Header mismatch: "+headerMismatchReason(err), nil)
	}

	rawCaps, ok := call.meta[mcp.MetaKeyClientCapabilities]
	if !ok {
		return call.invalidParams(fmt.Sprintf("missing required params._meta %q", mcp.MetaKeyClientCapabilities))
	}
	var caps map[string]json.RawMessage
	if json.Unmarshal(rawCaps, &caps) != nil || caps == nil {
		return call.invalidParams(fmt.Sprintf("params._meta %q must be an object", mcp.MetaKeyClientCapabilities))
	}
	return nil
}

func headerMismatchReason(err error) string {
	var mismatch mcp.HeaderMismatchError
	if errors.As(err, &mismatch) {
		return fmt.Sprintf("%s: %s", mismatch.Header, mismatch.Reason)
	}
	return err.Error()
}

func unsupportedVersion(requested string) *rpcError {
	return newRPCError(http.StatusBadRequest, mcpUnsupportedProtocolVersion, "Unsupported protocol version", map[string]any{
		"supported": supportedProtocolVersions,
		"requested": requested,
	})
}

// serverInfo identifies this server in initialize, server/discover and the
// _meta of every modern result.
func serverInfo() map[string]any {
	return map[string]any{"name": mcpServerName, "version": mcpServerVersion}
}

// serverCapabilities is the capability set advertised in both eras. Only tools
// are offered, and the tool list never changes while the process runs.
func serverCapabilities() map[string]any {
	return map[string]any{"tools": map[string]any{}}
}

// decorateModernResult adds the fields every 2026-07-28 result carries:
// resultType, the server identity in _meta and, for cacheable results, the
// caching hints. The result types this server produces are decorated in
// place on a shallow copy, so a large tool result is encoded only once, by
// the response writer.
func decorateModernResult(result any, cacheable bool) (any, error) {
	switch v := result.(type) {
	case *mcp.CallToolResult:
		if v == nil {
			return nil, errors.New("nil tool result")
		}
		out := *v
		out.ResultType = mcp.ResultTypeComplete
		meta := &mcp.Meta{}
		if v.Meta != nil {
			meta.ProgressToken = v.Meta.ProgressToken
			meta.AdditionalFields = maps.Clone(v.Meta.AdditionalFields)
		}
		if meta.AdditionalFields == nil {
			meta.AdditionalFields = map[string]any{}
		}
		meta.AdditionalFields[mcp.MetaKeyServerInfo] = serverInfo()
		out.Meta = meta
		if cacheable {
			// Tool results are never cacheable; a caller asking for hints
			// on one is a bug, so go through the generic path that adds them.
			break
		}
		return &out, nil
	case map[string]any:
		out := maps.Clone(v)
		meta := map[string]any{}
		switch existing := out["_meta"].(type) {
		case nil:
		case map[string]any:
			maps.Copy(meta, existing)
		default:
			return nil, fmt.Errorf("result _meta is %T, not an object", existing)
		}
		meta[mcp.MetaKeyServerInfo] = serverInfo()
		out["_meta"] = meta
		out["resultType"] = string(mcp.ResultTypeComplete)
		if cacheable {
			out["ttlMs"] = toolsListTTLMs
			// The tool list depends on the endpoint path, the X-MCP-Tools
			// header and the credential, so it must never be shared across
			// authorization contexts.
			out["cacheScope"] = string(mcp.CacheScopePrivate)
		}
		return out, nil
	}
	return decorateEncodedResult(result, cacheable)
}

// decorateEncodedResult is the fallback for result types the switch above
// does not know: it decorates the encoded object's top-level keys.
func decorateEncodedResult(result any, cacheable bool) (json.RawMessage, error) {
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return nil, fmt.Errorf("result is not a JSON object: %w", err)
	}
	if fields == nil {
		fields = map[string]json.RawMessage{}
	}
	fields["resultType"] = json.RawMessage(`"complete"`)

	meta := map[string]json.RawMessage{}
	if existing, ok := fields["_meta"]; ok && !bytes.Equal(existing, []byte("null")) {
		if err := json.Unmarshal(existing, &meta); err != nil {
			return nil, fmt.Errorf("result _meta is not an object: %w", err)
		}
	}
	info, _ := json.Marshal(serverInfo())
	meta[mcp.MetaKeyServerInfo] = info
	encodedMeta, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	fields["_meta"] = encodedMeta

	if cacheable {
		fields["ttlMs"] = json.RawMessage(fmt.Sprintf("%d", toolsListTTLMs))
		fields["cacheScope"] = json.RawMessage(`"private"`)
	}
	return json.Marshal(fields)
}

// writeRPCResult writes a successful response in the shape the request's era
// expects.
func (s *Server) writeRPCResult(w http.ResponseWriter, call *mcpCall, result any, cacheable bool) {
	if call.era == eraModern {
		decorated, err := decorateModernResult(result, cacheable)
		if err != nil {
			s.logger.Error("Failed to encode MCP result", "method", call.method, "error", err)
			s.writeRPCError(w, call.id, newRPCError(http.StatusInternalServerError, -32603, "Internal error", "failed to encode result"))
			return
		}
		result = decorated
	}
	NewResponseWriter(w, s.logger).WriteJSON(http.StatusOK, map[string]any{
		"jsonrpc": "2.0",
		"id":      call.id,
		"result":  result,
	})
}

// writeRPCError writes a JSON-RPC error. id may be nil when the request id
// could not be read, in which case it is omitted as the spec requires.
func (s *Server) writeRPCError(w http.ResponseWriter, id json.RawMessage, e *rpcError) {
	body := map[string]any{"jsonrpc": "2.0"}
	if len(id) > 0 {
		body["id"] = id
	}
	errObj := map[string]any{"code": e.code, "message": e.message}
	if e.data != nil {
		errObj["data"] = e.data
	}
	body["error"] = errObj
	status := e.httpStatus
	if status == 0 {
		status = http.StatusOK
	}
	NewResponseWriter(w, s.logger).WriteJSON(status, body)
}

// originAllowed implements the Streamable HTTP DNS-rebinding defence: a
// request that carries an Origin header must come from an origin this server
// trusts. Requests without Origin (every non-browser MCP client) pass.
func (s *Server) originAllowed(origin string) bool {
	if origin == "" {
		return true
	}
	if s.config != nil {
		for _, allowed := range s.config.HTTP.CORSAllowedOrigins {
			if allowed == "*" || strings.EqualFold(allowed, origin) {
				return true
			}
		}
		if own := originOf(s.config.HTTP.ServerURL); own != "" && strings.EqualFold(own, origin) {
			return true
		}
	}
	return false
}

// originOf returns the scheme://host[:port] origin of a URL, or "".
func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
