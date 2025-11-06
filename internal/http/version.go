package http

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// API version constants
const (
	// APIVersionV1 represents version 1 of the API
	APIVersionV1 = "v1"

	// LatestAPIVersion is the current latest API version
	// Update this constant when releasing a new version
	LatestAPIVersion = APIVersionV1
)

// Context key for storing API version in request context
// Note: contextKey type is defined in middleware.go
const versionContextKey contextKey = "api_version"

// supportedVersions is the set of valid API versions
var supportedVersions = map[string]bool{
	APIVersionV1: true,
}

// ExtractVersionFromPath extracts the API version from a request path.
// Returns the version string if found, or empty string if not present.
//
// Examples:
//   - "/mcp/v1" -> "v1"
//   - "/v1/all" -> "v1"
//   - "/mcp" -> ""
//   - "/all" -> ""
func ExtractVersionFromPath(path string) string {
	// Remove leading slash
	path = strings.TrimPrefix(path, "/")

	// Split path into segments
	segments := strings.Split(path, "/")

	// Check first two segments for version pattern
	for i := 0; i < len(segments) && i < 2; i++ {
		seg := segments[i]
		// Version must start with 'v' followed by a digit
		if len(seg) >= 2 && seg[0] == 'v' && seg[1] >= '0' && seg[1] <= '9' {
			return seg
		}
	}

	return ""
}

// IsValidVersion checks if a version string is supported
func IsValidVersion(version string) bool {
	return supportedVersions[version]
}

// GetVersionFromContext retrieves the API version from the request context
func GetVersionFromContext(ctx context.Context) string {
	if version, ok := ctx.Value(versionContextKey).(string); ok {
		return version
	}
	return LatestAPIVersion
}

// SetVersionInContext stores the API version in the request context
func SetVersionInContext(ctx context.Context, version string) context.Context {
	return context.WithValue(ctx, versionContextKey, version)
}

// StripVersionFromPath removes the version prefix from a path if present.
// This is useful for normalizing paths after version extraction.
// Only versions in the first two segments are stripped.
//
// Examples:
//   - "/mcp/v1" -> "/mcp"
//   - "/v1/all" -> "/all"
//   - "/mcp" -> "/mcp"
//   - "/mcp/something/v1" -> "/mcp/something/v1" (version in 3rd segment not stripped)
func StripVersionFromPath(path string) string {
	// Remove leading slash
	originalPath := path
	path = strings.TrimPrefix(path, "/")

	// Split path into segments
	segments := strings.Split(path, "/")
	if len(segments) == 0 {
		return originalPath
	}

	// Check first two segments for version pattern
	newSegments := []string{}

	for i := 0; i < len(segments); i++ {
		seg := segments[i]
		// Only strip version from first two segments
		if i < 2 && len(seg) >= 2 && seg[0] == 'v' && seg[1] >= '0' && seg[1] <= '9' {
			// Skip this version segment
			continue
		}
		newSegments = append(newSegments, seg)
	}

	if len(newSegments) == 0 {
		return "/"
	}

	return "/" + strings.Join(newSegments, "/")
}

// VersionMiddleware is middleware that extracts and validates the API version from the request path.
// If no version is specified, it defaults to the latest version.
// If an invalid version is specified, it returns a 404 error.
func VersionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		version := ExtractVersionFromPath(r.URL.Path)

		// If no version specified, use latest
		if version == "" {
			version = LatestAPIVersion
		} else if !IsValidVersion(version) {
			// Invalid version specified
			http.Error(w, fmt.Sprintf("API version %s is not supported", version), http.StatusNotFound)
			return
		}

		// Store version in context
		ctx := SetVersionInContext(r.Context(), version)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
