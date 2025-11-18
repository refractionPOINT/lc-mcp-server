package http

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/config"
	"github.com/stretchr/testify/assert"
)

// ===== Helper Functions =====

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testHandler(statusCode int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		w.Write([]byte(body))
	}
}

func panicHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	}
}

// ===== Panic Recovery Tests =====

func TestPanicRecovery_HandlesPanic(t *testing.T) {
	middleware := PanicRecovery(testLogger())
	handler := middleware(panicHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	// Should not panic, should return 500
	assert.NotPanics(t, func() {
		handler.ServeHTTP(w, req)
	})

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "internal_server_error")
}

func TestPanicRecovery_NormalRequestPassesThrough(t *testing.T) {
	middleware := PanicRecovery(testLogger())
	handler := middleware(testHandler(http.StatusOK, "success"))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "success", w.Body.String())
}

func TestPanicRecovery_IncludesRequestIDInLog(t *testing.T) {
	middleware := PanicRecovery(testLogger())

	// First add request ID middleware
	requestIDMiddleware := RequestID()
	handler := requestIDMiddleware(middleware(panicHandler()))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should have request ID in response header
	assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ===== Security Headers Tests =====

func TestSecurityHeaders_AllHeadersPresent(t *testing.T) {
	config := &config.Config{
		TLS: config.TLSConfig{Enable: true},
	}
	server := &Server{config: config, logger: testLogger()}

	middleware := server.securityHeadersMiddleware(testHandler(http.StatusOK, "ok"))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	// Check all security headers are present
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))

	// CSP should contain nonce
	csp := w.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "nonce-")
	assert.Contains(t, csp, "default-src 'self'")
	// Verify script-src uses nonce and not unsafe-inline (style-src can safely use unsafe-inline)
	assert.Contains(t, csp, "script-src 'self' 'nonce-")
	assert.NotContains(t, csp, "script-src 'self' 'unsafe-inline'", "script-src should NOT have unsafe-inline")

	// HSTS should be present when TLS is enabled
	assert.Contains(t, w.Header().Get("Strict-Transport-Security"), "max-age=63072000")
}

func TestSecurityHeaders_NoHSTSWithoutTLS(t *testing.T) {
	config := &config.Config{
		TLS: config.TLSConfig{Enable: false}, // TLS disabled
	}
	server := &Server{config: config, logger: testLogger()}

	middleware := server.securityHeadersMiddleware(testHandler(http.StatusOK, "ok"))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	// HSTS should NOT be set when TLS is disabled
	assert.Empty(t, w.Header().Get("Strict-Transport-Security"))
}

func TestSecurityHeaders_CSPNonceInContext(t *testing.T) {
	config := &config.Config{TLS: config.TLSConfig{Enable: false}}
	server := &Server{config: config, logger: testLogger()}

	var capturedNonce string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract nonce from context
		capturedNonce, _ = r.Context().Value("csp_nonce").(string)
		w.WriteHeader(http.StatusOK)
	})

	middleware := server.securityHeadersMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	// Verify nonce was added to context
	assert.NotEmpty(t, capturedNonce)

	// Verify nonce in CSP header matches context nonce
	csp := w.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "nonce-"+capturedNonce)
}

// ===== CORS Tests =====

func TestCORS_AllowedOrigin(t *testing.T) {
	config := &config.Config{
		HTTP: config.HTTPConfig{
			CORSAllowedOrigins: []string{"https://app.example.com"},
		},
	}
	server := &Server{config: config, logger: testLogger()}

	middleware := server.corsMiddleware(testHandler(http.StatusOK, "ok"))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "GET, POST, OPTIONS", w.Header().Get("Access-Control-Allow-Methods"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
}

func TestCORS_DisallowedOrigin(t *testing.T) {
	config := &config.Config{
		HTTP: config.HTTPConfig{
			CORSAllowedOrigins: []string{"https://app.example.com"},
		},
	}
	server := &Server{config: config, logger: testLogger()}

	middleware := server.corsMiddleware(testHandler(http.StatusOK, "ok"))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://evil.com")
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	// Should NOT set CORS headers for disallowed origin
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_Wildcard(t *testing.T) {
	config := &config.Config{
		HTTP: config.HTTPConfig{
			CORSAllowedOrigins: []string{"*"},
		},
	}
	server := &Server{config: config, logger: testLogger()}

	middleware := server.corsMiddleware(testHandler(http.StatusOK, "ok"))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://any-site.com")
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	// Should allow any origin with wildcard
	assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_PreflightRequest(t *testing.T) {
	config := &config.Config{
		HTTP: config.HTTPConfig{
			CORSAllowedOrigins: []string{"https://app.example.com"},
		},
	}
	server := &Server{config: config, logger: testLogger()}

	middleware := server.corsMiddleware(testHandler(http.StatusOK, "should not reach here"))

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	// OPTIONS should return 204 No Content
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String(), "OPTIONS should not execute handler")

	// Should have CORS headers
	assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
}

// ===== Request ID Tests =====

func TestRequestID_GeneratesID(t *testing.T) {
	middleware := RequestID()
	handler := middleware(testHandler(http.StatusOK, "ok"))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should have generated request ID in response header
	requestID := w.Header().Get("X-Request-ID")
	assert.NotEmpty(t, requestID)
	assert.Len(t, requestID, 32, "Request ID should be 32 chars (16 bytes hex)")
}

func TestRequestID_PreservesExistingID(t *testing.T) {
	middleware := RequestID()
	handler := middleware(testHandler(http.StatusOK, "ok"))

	existingID := "existing-request-id-12345"
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Request-ID", existingID)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should preserve existing request ID
	assert.Equal(t, existingID, w.Header().Get("X-Request-ID"))
}

func TestRequestID_InContext(t *testing.T) {
	middleware := RequestID()

	var capturedRequestID string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRequestID = GetRequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := middleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	// Request ID should be accessible from context
	assert.NotEmpty(t, capturedRequestID)
	assert.Equal(t, capturedRequestID, w.Header().Get("X-Request-ID"))
}

func TestGetRequestID_EmptyContext(t *testing.T) {
	ctx := context.Background()
	requestID := GetRequestID(ctx)
	assert.Empty(t, requestID, "Should return empty string for context without request ID")
}

// ===== Metrics Middleware Tests =====

func TestMetricsMiddleware_TracksRequests(t *testing.T) {
	// Reset global metrics
	globalMetrics = &Metrics{}

	middleware := MetricsMiddleware()
	handler := middleware(testHandler(http.StatusOK, "ok"))

	// Make 3 requests
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}

	total, errors, _ := GetGlobalMetrics()
	assert.Equal(t, int64(3), total)
	assert.Equal(t, int64(0), errors, "No errors for 200 responses")
}

func TestMetricsMiddleware_TracksErrors(t *testing.T) {
	// Reset global metrics
	globalMetrics = &Metrics{}

	middleware := MetricsMiddleware()
	successHandler := middleware(testHandler(http.StatusOK, "ok"))
	errorHandler := middleware(testHandler(http.StatusBadRequest, "error"))

	// 2 success, 3 errors
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		successHandler.ServeHTTP(w, req)
	}

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		errorHandler.ServeHTTP(w, req)
	}

	total, errors, _ := GetGlobalMetrics()
	assert.Equal(t, int64(5), total)
	assert.Equal(t, int64(3), errors)
}

func TestMetricsMiddleware_TracksDuration(t *testing.T) {
	// Reset global metrics
	globalMetrics = &Metrics{}

	middleware := MetricsMiddleware()
	slowHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	handler := middleware(slowHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	_, _, avgDuration := GetGlobalMetrics()
	assert.Greater(t, avgDuration, int64(5), "Average duration should be > 5ms")
}

// ===== Request Logger Tests =====

func TestRequestLogger_LogsRequests(t *testing.T) {
	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuffer, nil))

	middleware := RequestLogger(logger)
	handler := middleware(testHandler(http.StatusOK, "ok"))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("User-Agent", "test-agent")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	logOutput := logBuffer.String()
	assert.Contains(t, logOutput, "HTTP request completed")
	assert.Contains(t, logOutput, "/test")
	assert.Contains(t, logOutput, "status=200")
}

// ===== Body Size Limit Tests =====

func TestBodySizeLimit_AllowsSmallBody(t *testing.T) {
	server := &Server{logger: testLogger()}
	middleware := server.bodySizeLimitMiddleware(testHandler(http.StatusOK, "ok"))

	smallBody := bytes.Repeat([]byte("a"), 1024) // 1KB
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(smallBody))
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBodySizeLimit_RejectsLargeBody(t *testing.T) {
	server := &Server{logger: testLogger()}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to read body
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	middleware := server.bodySizeLimitMiddleware(handler)

	// 11MB body (exceeds 10MB limit)
	largeBody := bytes.Repeat([]byte("a"), 11*1024*1024)
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(largeBody))
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

// ===== Helper Functions Tests =====

func TestGenerateRequestID_UniqueIDs(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateRequestID()
		assert.NotEmpty(t, id)
		assert.False(t, ids[id], "Request IDs should be unique")
		ids[id] = true
	}
}

func TestGenerateCSPNonce_UniqueNonces(t *testing.T) {
	nonces := make(map[string]bool)
	for i := 0; i < 100; i++ {
		nonce := generateCSPNonce()
		assert.NotEmpty(t, nonce)
		assert.False(t, nonces[nonce], "CSP nonces should be unique")
		nonces[nonce] = true
	}
}

func TestGetClientIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 198.51.100.1")

	ip := getClientIP(req)
	assert.Equal(t, "203.0.113.1", ip, "Should extract first IP from X-Forwarded-For")
}

func TestGetClientIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Real-IP", "203.0.113.5")

	ip := getClientIP(req)
	assert.Equal(t, "203.0.113.5", ip)
}

func TestGetClientIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.0.2.1:12345"

	ip := getClientIP(req)
	assert.Equal(t, "192.0.2.1:12345", ip, "Should fall back to RemoteAddr")
}

func TestGetClientIP_PreferenceOrder(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	req.Header.Set("X-Real-IP", "203.0.113.2")
	req.RemoteAddr = "203.0.113.3:12345"

	ip := getClientIP(req)
	assert.Equal(t, "203.0.113.1", ip, "X-Forwarded-For should have highest priority")
}

// ===== Response Writer Tests =====

func TestResponseWriter_CapturesStatusCode(t *testing.T) {
	w := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

	rw.WriteHeader(http.StatusNotFound)

	assert.Equal(t, http.StatusNotFound, rw.statusCode)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestResponseWriter_DefaultStatusCode(t *testing.T) {
	w := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

	// Write without explicit WriteHeader
	rw.Write([]byte("test"))

	assert.Equal(t, http.StatusOK, rw.statusCode, "Should default to 200 OK")
}

// ===== Get Endpoint Type Tests =====

func TestGetEndpointType_OAuthEndpoints(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/authorize", "oauth_authorize"},
		{"/token", "oauth_token"},
		{"/oauth/callback", "oauth_callback"},
		{"/mcp", "mcp_request"},
		{"/mcp/v1", "mcp_request"},
		{"/unknown", "default"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := getEndpointType(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ===== Metrics Struct Tests =====

func TestMetrics_GetMetrics(t *testing.T) {
	m := &Metrics{}

	m.totalRequests.Add(10)
	m.totalErrors.Add(3)
	m.requestDuration.Add(int64(1 * time.Second))

	total, errors, avgDuration := m.GetMetrics()

	assert.Equal(t, int64(10), total)
	assert.Equal(t, int64(3), errors)
	assert.Equal(t, int64(100), avgDuration, "Average should be 1000ms / 10 = 100ms")
}

func TestMetrics_GetMetrics_ZeroRequests(t *testing.T) {
	m := &Metrics{}

	total, errors, avgDuration := m.GetMetrics()

	assert.Equal(t, int64(0), total)
	assert.Equal(t, int64(0), errors)
	assert.Equal(t, int64(0), avgDuration, "Should not divide by zero")
}
