package http

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/ratelimit"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// contextKey is a type for context keys to avoid collisions
type contextKey string

const (
	requestIDKey contextKey = "request_id"
)

// Metrics holds simple in-memory request metrics
type Metrics struct {
	totalRequests   atomic.Int64
	totalErrors     atomic.Int64
	requestDuration atomic.Int64 // cumulative duration in nanoseconds
}

// GetMetrics returns current metrics snapshot
func (m *Metrics) GetMetrics() (total, errors, avgDurationMs int64) {
	total = m.totalRequests.Load()
	errors = m.totalErrors.Load()
	if total > 0 {
		avgDurationMs = (m.requestDuration.Load() / total) / int64(time.Millisecond)
	}
	return
}

var globalMetrics = &Metrics{}

// withMiddleware wraps the handler with middleware chain
// Uses both standalone composable middleware and server-specific middleware
func (s *Server) withMiddleware(next http.Handler) http.Handler {
	// Chain middleware (executes in order, outermost first)
	handler := next

	// Server-specific middleware (need access to server state)
	handler = s.requestIDMiddleware(handler)       // Adds request ID to context
	handler = VersionMiddleware(handler)           // Extract and validate API version
	handler = s.rateLimitMiddleware(handler)       // Rate limiting per endpoint
	handler = s.bodySizeLimitMiddleware(handler)   // Prevent large request bodies
	handler = s.securityHeadersMiddleware(handler) // Security headers
	handler = s.corsMiddleware(handler)            // CORS handling

	// Enhanced standalone middleware (production-ready observability)
	handler = MetricsMiddleware()(handler)     // Track request metrics
	handler = RequestLogger(s.logger)(handler) // Structured logging with request ID
	handler = PanicRecovery(s.logger)(handler) // Panic recovery (outermost)

	return handler
}

// recoveryMiddleware recovers from panics
func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				s.logger.Error("Panic recovered", "error", err, "method", r.Method, "path", r.URL.Path)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error":"internal_server_error","error_description":"An internal error occurred"}`))
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs HTTP requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Process request
		next.ServeHTTP(wrapped, r)

		// Log request details
		duration := time.Since(start)

		s.logger.Info("HTTP request completed",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.statusCode,
			"duration_ms", duration.Milliseconds(),
			"user_agent", r.UserAgent())
	})
}

// bodySizeLimitMiddleware limits request body size to prevent memory exhaustion
func (s *Server) bodySizeLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Limit request body to 10MB (configurable per endpoint if needed)
		const maxBodySize = 10 * 1024 * 1024 // 10 MB
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware adds security headers to all responses
// SECURITY FIX: Now uses CSP nonces instead of 'unsafe-inline' for better security
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate CSP nonce for this request
		nonce := generateCSPNonce()

		// Store nonce in context for template access (using plain string to allow cross-package access)
		ctx := context.WithValue(r.Context(), "csp_nonce", nonce)

		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// Enable browser XSS protection
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// SECURITY FIX: Content Security Policy with nonce (removed 'unsafe-inline' for scripts)
		// Nonce-based CSP provides strong protection against XSS attacks
		csp := fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; img-src 'self' data:; font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; connect-src 'self'; frame-ancestors 'none'", nonce)
		w.Header().Set("Content-Security-Policy", csp)

		// Referrer policy - limit information leakage
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions policy - disable unnecessary features
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()")

		// Strict-Transport-Security (HSTS) - ONLY if using HTTPS
		if s.config.TLS.Enable {
			// Max age: 2 years, include subdomains, allow preload list inclusion
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// corsMiddleware handles CORS headers
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get allowed origins from config
		allowedOrigins := s.config.HTTP.CORSAllowedOrigins
		origin := r.Header.Get("Origin")

		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			if origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else if len(allowedOrigins) > 0 {
				w.Header().Set("Access-Control-Allow-Origin", allowedOrigins[0])
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID, X-MCP-Tools, X-LC-UID, X-LC-OID, X-LC-API-KEY, X-LC-ALLOW-META-TOOLS, X-LC-DENY-META-TOOLS")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
		}

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// requestIDMiddleware adds a unique request ID to each request
func (s *Server) requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if request ID already exists in header
		requestID := r.Header.Get("X-Request-ID")

		// Generate new ID if not present
		if requestID == "" {
			requestID = generateRequestID()
		}

		// Store in context
		ctx := context.WithValue(r.Context(), requestIDKey, requestID)

		// Add to response header
		w.Header().Set("X-Request-ID", requestID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// rateLimitMiddleware implements rate limiting for endpoints
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if rateLimiter is not configured
		// (e.g., server-credentials-only mode without Redis)
		if s.rateLimiter == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Determine endpoint type for rate limiting
		endpointType := getEndpointType(r.URL.Path)

		// Get rate limit config for this endpoint
		cfg, ok := ratelimit.DefaultConfigs[endpointType]
		if !ok {
			cfg = ratelimit.DefaultConfigs["default"]
		}

		// Use client IP as rate limit key
		clientIP := getClientIP(r)
		rateLimitKey := clientIP + ":" + endpointType

		// Check rate limit
		allowed, err := s.rateLimiter.Allow(r.Context(), rateLimitKey, cfg)
		if err != nil {
			// Log error but continue (fail open)
			s.logger.Warn("Rate limit check error", "error", err)
		}

		if !allowed {
			// Return 429 Too Many Requests
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate_limit_exceeded","error_description":"Too many requests. Please try again later."}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// getEndpointType determines the rate limit category for a path
func getEndpointType(path string) string {
	// Strip version prefix for endpoint type detection
	// This ensures /mcp/v1 is recognized as "mcp_request" just like /mcp
	normalizedPath := StripVersionFromPath(path)

	switch {
	case strings.HasPrefix(normalizedPath, "/authorize"):
		return "oauth_authorize"
	case strings.HasPrefix(normalizedPath, "/token"):
		return "oauth_token"
	case strings.HasPrefix(normalizedPath, "/oauth/callback"):
		return "oauth_callback"
	case strings.HasPrefix(normalizedPath, "/mcp"):
		return "mcp_request"
	case isProfilePath(normalizedPath):
		return "mcp_request"
	default:
		return "default"
	}
}

// isProfilePath checks if the path contains any registered profile name
func isProfilePath(path string) bool {
	for profile := range tools.ProfileDefinitions {
		if strings.Contains(path, profile) {
			return true
		}
	}
	return false
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// generateRequestID generates a random request ID
func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp if random fails
		return time.Now().Format("20060102150405")
	}
	return hex.EncodeToString(b)
}

// generateCSPNonce generates a random CSP nonce for Content Security Policy
func generateCSPNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (for proxies/load balancers)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Get first IP in the chain
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fallback to RemoteAddr
	return r.RemoteAddr
}

// ======================================================================
// STANDALONE MIDDLEWARE FUNCTIONS (Composable, production-ready)
// ======================================================================

// RequestLogger returns middleware that logs all HTTP requests with structured fields
// including request ID, duration, status code, method, path, and user agent
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Process request
			next.ServeHTTP(wrapped, r)

			// Log request details with structured fields
			duration := time.Since(start)
			requestID := r.Context().Value(requestIDKey)

			logger.Info("HTTP request completed",
				"request_id", requestID,
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.statusCode,
				"duration_ms", duration.Milliseconds(),
				"user_agent", r.UserAgent(),
				"remote_addr", getClientIP(r))
		})
	}
}

// PanicRecovery returns middleware that recovers from panics and logs them
// This prevents the entire server from crashing due to a panic in a handler
func PanicRecovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					requestID := r.Context().Value(requestIDKey)

					logger.Error("Panic recovered in HTTP handler",
						"error", err,
						"request_id", requestID,
						"method", r.Method,
						"path", r.URL.Path,
						"remote_addr", getClientIP(r))

					// Return 500 Internal Server Error
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(`{"error":"internal_server_error","error_description":"An internal error occurred"}`))
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// RequestID returns middleware that adds a unique request ID to each request
// The request ID is either extracted from the X-Request-ID header (if present)
// or generated as a new random ID. It's added to both the request context
// and the response headers for traceability
func RequestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if request ID already exists in header
			requestID := r.Header.Get("X-Request-ID")

			// Generate new ID if not present
			if requestID == "" {
				requestID = generateRequestID()
			}

			// Store in context for use by handlers and other middleware
			ctx := context.WithValue(r.Context(), requestIDKey, requestID)

			// Add to response header for client traceability
			w.Header().Set("X-Request-ID", requestID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// MetricsMiddleware returns middleware that tracks request metrics
// It uses simple in-memory atomic counters to track:
// - Total number of requests
// - Total number of errors (status >= 400)
// - Cumulative request duration
func MetricsMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Process request
			next.ServeHTTP(wrapped, r)

			// Update metrics
			duration := time.Since(start)
			globalMetrics.totalRequests.Add(1)
			globalMetrics.requestDuration.Add(int64(duration))

			// Track errors (4xx and 5xx status codes)
			if wrapped.statusCode >= 400 {
				globalMetrics.totalErrors.Add(1)
			}
		})
	}
}

// GetRequestID extracts the request ID from the context
func GetRequestID(ctx context.Context) string {
	if reqID, ok := ctx.Value(requestIDKey).(string); ok {
		return reqID
	}
	return ""
}

// GetGlobalMetrics returns the current global metrics
func GetGlobalMetrics() (total, errors, avgDurationMs int64) {
	return globalMetrics.GetMetrics()
}
