package metadata

import (
	"strings"
)

// Default scope for authorization requests
const DefaultScope = "limacharlie:read limacharlie:write"

// Supported scopes
var SupportedScopes = []string{
	"limacharlie:read",
	"limacharlie:write",
	"limacharlie:admin",
}

// ParseScopeString parses a space-separated scope string into a list
func ParseScopeString(scope string) []string {
	if scope == "" {
		return []string{}
	}
	return strings.Fields(scope)
}

// ValidateScope checks if all requested scopes are supported
func ValidateScope(scope string) bool {
	if scope == "" {
		return true
	}

	requested := ParseScopeString(scope)
	for _, s := range requested {
		if !isScopeSupported(s) {
			return false
		}
	}

	return true
}

// FilterScopeToSupported filters requested scopes to only supported ones
// Returns default scope if no valid scopes remain
func FilterScopeToSupported(scope string) string {
	if scope == "" {
		return DefaultScope
	}

	requested := ParseScopeString(scope)
	filtered := []string{}

	for _, s := range requested {
		if isScopeSupported(s) {
			filtered = append(filtered, s)
		}
	}

	if len(filtered) == 0 {
		return DefaultScope
	}

	return strings.Join(filtered, " ")
}

// isScopeSupported checks if a scope is in the supported list
func isScopeSupported(scope string) bool {
	for _, supported := range SupportedScopes {
		if scope == supported {
			return true
		}
	}
	return false
}
