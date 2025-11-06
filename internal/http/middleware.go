package http

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/ratelimit"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// contextKey is a type for context keys to avoid collisions
type contextKey string

const (
	requestIDKey contextKey = "request_id"
)

// withMiddleware wraps the handler with middleware chain
func (s *Server) withMiddleware(next http.Handler) http.Handler {
	// Chain middleware (executes in order)
	handler := next
	handler = s.requestIDMiddleware(handler)
	handler = s.rateLimitMiddleware(handler)
	handler = s.bodySizeLimitMiddleware(handler)
	handler = s.securityHeadersMiddleware(handler)
	handler = s.corsMiddleware(handler)
	handler = s.loggingMiddleware(handler)
	handler = s.recoveryMiddleware(handler)
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
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// Enable browser XSS protection
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Content Security Policy - strict default-src
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'")

		// Referrer policy - limit information leakage
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions policy - disable unnecessary features
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()")

		// Strict-Transport-Security (HSTS) - ONLY if using HTTPS
		if s.config.EnableTLS {
			// Max age: 2 years, include subdomains, allow preload list inclusion
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		}

		next.ServeHTTP(w, r)
	})
}

// corsMiddleware handles CORS headers
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get allowed origins from config
		allowedOrigins := s.config.CORSAllowedOrigins
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
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
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
	switch {
	case strings.HasPrefix(path, "/authorize"):
		return "oauth_authorize"
	case strings.HasPrefix(path, "/token"):
		return "oauth_token"
	case strings.HasPrefix(path, "/oauth/callback"):
		return "oauth_callback"
	case strings.HasPrefix(path, "/mcp"):
		return "mcp_request"
	case isProfilePath(path):
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

// authMiddleware validates OAuth Bearer tokens (will be implemented in Phase 4)
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement OAuth token validation
		// Extract Bearer token from Authorization header
		// Validate token with OAuth token manager
		// Auto-refresh if needed
		// Store user context (UID, OAuth creds) for downstream handlers

		next.ServeHTTP(w, r)
	})
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
