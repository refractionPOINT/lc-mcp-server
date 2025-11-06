package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// ResponseWriter wraps http.ResponseWriter with convenient JSON response methods
type ResponseWriter struct {
	w      http.ResponseWriter
	logger *slog.Logger
}

// NewResponseWriter creates a new ResponseWriter
func NewResponseWriter(w http.ResponseWriter, logger *slog.Logger) *ResponseWriter {
	return &ResponseWriter{
		w:      w,
		logger: logger,
	}
}

// WriteJSON writes a JSON response with the given status code
func (rw *ResponseWriter) WriteJSON(status int, data interface{}) {
	rw.w.Header().Set("Content-Type", "application/json")
	rw.w.WriteHeader(status)
	if err := json.NewEncoder(rw.w).Encode(data); err != nil {
		rw.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// WriteJSONRPCSuccess writes a successful JSON-RPC 2.0 response
func (rw *ResponseWriter) WriteJSONRPCSuccess(id interface{}, result interface{}) {
	response := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	}
	rw.WriteJSON(http.StatusOK, response)
}

// WriteJSONRPCError writes a JSON-RPC 2.0 error response
func (rw *ResponseWriter) WriteJSONRPCError(id interface{}, code int, message string, data string) {
	response := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
			"data":    data,
		},
	}
	rw.WriteJSON(http.StatusOK, response)
}
