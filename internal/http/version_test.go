package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractVersionFromPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "v1 in mcp path",
			path:     "/mcp/v1",
			expected: "v1",
		},
		{
			name:     "v1 in profile path",
			path:     "/v1/all",
			expected: "v1",
		},
		{
			name:     "v1 in longer profile path",
			path:     "/v1/historical_data",
			expected: "v1",
		},
		{
			name:     "unversioned mcp path",
			path:     "/mcp",
			expected: "",
		},
		{
			name:     "unversioned profile path",
			path:     "/all",
			expected: "",
		},
		{
			name:     "root path",
			path:     "/",
			expected: "",
		},
		{
			name:     "invalid version format",
			path:     "/mcp/version1",
			expected: "",
		},
		{
			name:     "v followed by letter",
			path:     "/vabc",
			expected: "",
		},
		{
			name:     "v2 future version",
			path:     "/mcp/v2",
			expected: "v2",
		},
		{
			name:     "v10 multi-digit version",
			path:     "/mcp/v10",
			expected: "v10",
		},
		{
			name:     "version in third segment ignored",
			path:     "/mcp/something/v1",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractVersionFromPath(tt.path)
			if result != tt.expected {
				t.Errorf("ExtractVersionFromPath(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestIsValidVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected bool
	}{
		{
			name:     "v1 is valid",
			version:  "v1",
			expected: true,
		},
		{
			name:     "v2 is invalid (not yet supported)",
			version:  "v2",
			expected: false,
		},
		{
			name:     "empty version is invalid",
			version:  "",
			expected: false,
		},
		{
			name:     "invalid format",
			version:  "version1",
			expected: false,
		},
		{
			name:     "just v is invalid",
			version:  "v",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidVersion(tt.version)
			if result != tt.expected {
				t.Errorf("IsValidVersion(%q) = %v, want %v", tt.version, result, tt.expected)
			}
		})
	}
}

func TestStripVersionFromPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "strip v1 from mcp",
			path:     "/mcp/v1",
			expected: "/mcp",
		},
		{
			name:     "strip v1 from profile",
			path:     "/v1/all",
			expected: "/all",
		},
		{
			name:     "strip v1 from longer profile",
			path:     "/v1/historical_data",
			expected: "/historical_data",
		},
		{
			name:     "unversioned mcp unchanged",
			path:     "/mcp",
			expected: "/mcp",
		},
		{
			name:     "unversioned profile unchanged",
			path:     "/all",
			expected: "/all",
		},
		{
			name:     "root path unchanged",
			path:     "/",
			expected: "/",
		},
		{
			name:     "strip v2 future version",
			path:     "/mcp/v2",
			expected: "/mcp",
		},
		{
			name:     "strip v10 multi-digit",
			path:     "/v10/all",
			expected: "/all",
		},
		{
			name:     "version in third segment not stripped",
			path:     "/mcp/something/v1",
			expected: "/mcp/something/v1",
		},
		{
			name:     "invalid version format not stripped",
			path:     "/mcp/version1",
			expected: "/mcp/version1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StripVersionFromPath(tt.path)
			if result != tt.expected {
				t.Errorf("StripVersionFromPath(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestGetVersionFromContext(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		expected string
	}{
		{
			name:     "context with v1",
			ctx:      SetVersionInContext(context.Background(), "v1"),
			expected: "v1",
		},
		{
			name:     "context without version returns latest",
			ctx:      context.Background(),
			expected: LatestAPIVersion,
		},
		{
			name:     "context with v2",
			ctx:      SetVersionInContext(context.Background(), "v2"),
			expected: "v2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetVersionFromContext(tt.ctx)
			if result != tt.expected {
				t.Errorf("GetVersionFromContext() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestSetVersionInContext(t *testing.T) {
	ctx := context.Background()
	version := "v1"

	newCtx := SetVersionInContext(ctx, version)

	// Verify the version was stored
	if val := newCtx.Value(versionContextKey); val == nil {
		t.Error("SetVersionInContext did not store version in context")
	} else if val.(string) != version {
		t.Errorf("SetVersionInContext stored %q, want %q", val.(string), version)
	}

	// Verify original context is unchanged
	if val := ctx.Value(versionContextKey); val != nil {
		t.Error("SetVersionInContext modified original context")
	}
}

func TestVersionMiddleware(t *testing.T) {
	tests := []struct {
		name               string
		path               string
		expectedStatusCode int
		expectedVersion    string
	}{
		{
			name:               "valid v1 version",
			path:               "/mcp/v1",
			expectedStatusCode: http.StatusOK,
			expectedVersion:    "v1",
		},
		{
			name:               "no version defaults to latest",
			path:               "/mcp",
			expectedStatusCode: http.StatusOK,
			expectedVersion:    LatestAPIVersion,
		},
		{
			name:               "invalid version returns 404",
			path:               "/mcp/v99",
			expectedStatusCode: http.StatusNotFound,
			expectedVersion:    "",
		},
		{
			name:               "profile path with v1",
			path:               "/v1/all",
			expectedStatusCode: http.StatusOK,
			expectedVersion:    "v1",
		},
		{
			name:               "profile path without version",
			path:               "/all",
			expectedStatusCode: http.StatusOK,
			expectedVersion:    LatestAPIVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler that captures the version from context
			var capturedVersion string
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedVersion = GetVersionFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with version middleware
			middleware := VersionMiddleware(handler)

			// Create test request
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			// Execute request
			middleware.ServeHTTP(rec, req)

			// Check status code
			if rec.Code != tt.expectedStatusCode {
				t.Errorf("Status code = %d, want %d", rec.Code, tt.expectedStatusCode)
			}

			// Check captured version (only for successful requests)
			if tt.expectedStatusCode == http.StatusOK {
				if capturedVersion != tt.expectedVersion {
					t.Errorf("Captured version = %q, want %q", capturedVersion, tt.expectedVersion)
				}
			}
		})
	}
}

func TestVersionMiddlewareWithInvalidVersion(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for invalid version")
	})

	middleware := VersionMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/mcp/v999", nil)
	rec := httptest.NewRecorder()

	middleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected 404 for invalid version, got %d", rec.Code)
	}

	// Check response body contains error message
	body := rec.Body.String()
	if body == "" {
		t.Error("Expected error message in response body")
	}
}
