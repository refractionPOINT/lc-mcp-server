package metadata

import (
	"fmt"
	"os"
	"strings"

	"log/slog"
)

// Provider provides OAuth metadata for MCP server discovery
// Implements RFC 8414 (Authorization Server Metadata) and RFC 9728 (Protected Resource Metadata)
type Provider struct {
	serverURL string
	logger    *slog.Logger
}

// NewProvider creates a new OAuth metadata provider
func NewProvider(logger *slog.Logger) *Provider {
	serverURL := os.Getenv("MCP_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}

	// Ensure no trailing slash
	serverURL = strings.TrimSuffix(serverURL, "/")

	logger.Info("OAuth metadata provider initialized")

	return &Provider{
		serverURL: serverURL,
		logger:    logger,
	}
}

// GetServerURL returns the configured server URL
func (p *Provider) GetServerURL() string {
	return p.serverURL
}

// GetProtectedResourceMetadata returns RFC 9728 Protected Resource Metadata
// This tells OAuth clients what resource this server represents and which authorization servers can issue tokens for it
func (p *Provider) GetProtectedResourceMetadata() map[string]interface{} {
	return map[string]interface{}{
		// The resource identifier for this MCP server
		"resource": p.serverURL + "/mcp",

		// Authorization servers that can issue tokens for this resource
		"authorization_servers": []string{p.serverURL},

		// Scopes supported by this resource
		"scopes_supported": []string{
			"limacharlie:read",  // Read-only access
			"limacharlie:write", // Write access (modifying resources)
			"limacharlie:admin", // Administrative operations
		},

		// How bearer tokens should be provided
		"bearer_methods_supported": []string{"header"},

		// Additional resource-specific metadata
		"resource_documentation":                p.serverURL + "/docs",
		"resource_signing_alg_values_supported": []string{"RS256"},
	}
}

// GetAuthorizationServerMetadata returns RFC 8414 Authorization Server Metadata
// This tells OAuth clients where to send authorization requests and what OAuth features are supported
func (p *Provider) GetAuthorizationServerMetadata() map[string]interface{} {
	return map[string]interface{}{
		// Issuer identifier for this authorization server
		"issuer": p.serverURL,

		// OAuth 2.0 endpoints
		"authorization_endpoint": p.serverURL + "/authorize",
		"token_endpoint":         p.serverURL + "/token",
		"registration_endpoint":  p.serverURL + "/register",

		// Optional endpoints
		"revocation_endpoint":    p.serverURL + "/revoke",
		"introspection_endpoint": p.serverURL + "/introspect",

		// Scopes supported
		"scopes_supported": []string{
			"limacharlie:read",
			"limacharlie:write",
			"limacharlie:admin",
		},

		// Response types supported (OAuth 2.1 requires code flow only)
		"response_types_supported": []string{"code"},

		// Grant types supported
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
		},

		// PKCE is required (OAuth 2.1)
		"code_challenge_methods_supported": []string{"S256"},

		// Token endpoint authentication methods
		// We support public clients (no client authentication)
		"token_endpoint_auth_methods_supported": []string{"none"},

		// Response modes
		"response_modes_supported": []string{"query", "fragment"},

		// OAuth 2.0 features
		"require_request_uri_registration":      false,
		"require_pushed_authorization_requests": false,

		// Additional metadata
		"service_documentation": p.serverURL + "/docs/oauth",
		"ui_locales_supported":  []string{"en-US"},

		// Token properties
		"token_endpoint_auth_signing_alg_values_supported": []string{"RS256"},
		"revocation_endpoint_auth_methods_supported":       []string{"none"},
		"introspection_endpoint_auth_methods_supported":    []string{"none"},

		// Provider selection (non-standard extension for multi-provider support)
		"supported_oauth_providers":    []string{"google", "microsoft"},
		"provider_selection_parameter": "provider", // Query parameter name
	}
}

// GenerateWWWAuthenticateHeader generates a WWW-Authenticate header for OAuth challenges
// Used in 401 and 403 responses to guide clients through OAuth flow
func (p *Provider) GenerateWWWAuthenticateHeader(error, errorDescription, scope string, statusCode int) string {
	// Base challenge with metadata URL
	metadataURL := p.serverURL + "/.well-known/oauth-protected-resource"
	parts := []string{fmt.Sprintf(`Bearer resource_metadata="%s"`, metadataURL)}

	// Add scope if provided
	if scope != "" {
		parts = append(parts, fmt.Sprintf(`scope="%s"`, scope))
	}

	// Add error information for 401 responses
	if statusCode == 401 || error != "" {
		if error != "" {
			parts = append(parts, fmt.Sprintf(`error="%s"`, error))
		}
		if errorDescription != "" {
			parts = append(parts, fmt.Sprintf(`error_description="%s"`, errorDescription))
		}
	}

	// Join all parts
	header := strings.Join(parts, ", ")

	// p.logger.WithField("header", header[:min(100, len(header))]).Debug("Generated WWW-Authenticate header")

	return header
}

// ValidateMetadataConsistency validates that metadata is consistent and well-formed
func (p *Provider) ValidateMetadataConsistency() map[string]interface{} {
	errors := []string{}

	// Validate server URL
	if p.serverURL == "" {
		errors = append(errors, "Server URL not configured")
	} else if !strings.HasPrefix(p.serverURL, "http://") && !strings.HasPrefix(p.serverURL, "https://") {
		errors = append(errors, fmt.Sprintf("Invalid server URL scheme: %s", p.serverURL))
	}

	// Get metadata
	resourceMeta := p.GetProtectedResourceMetadata()
	authMeta := p.GetAuthorizationServerMetadata()

	// Check that authorization server in resource metadata matches issuer
	authServers := resourceMeta["authorization_servers"].([]string)
	if len(authServers) == 0 || authServers[0] != p.serverURL {
		errors = append(errors, "Server URL not in authorization_servers list")
	}

	if authMeta["issuer"].(string) != p.serverURL {
		errors = append(errors, "Issuer does not match server URL")
	}

	// Validate endpoints are HTTPS in production
	if strings.HasPrefix(p.serverURL, "http://") && !strings.Contains(p.serverURL, "localhost") {
		errors = append(errors, "WARNING: Using HTTP for non-localhost server (should use HTTPS)")
	}

	warnings := []string{}
	for _, err := range errors {
		if strings.HasPrefix(err, "WARNING:") {
			warnings = append(warnings, err)
		}
	}

	return map[string]interface{}{
		"valid":    len(errors) == 0,
		"errors":   errors,
		"warnings": warnings,
	}
}

// Helper function (available in Go 1.21+)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
