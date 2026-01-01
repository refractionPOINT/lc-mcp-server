package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
)

// ServerConfig holds server-level configuration
type ServerConfig struct {
	Mode     string // "stdio" or "http"
	Profile  string // Profile to expose: "core", "all", etc.
	LogLevel string // "debug", "info", "warn", "error"
}

// HTTPConfig holds HTTP server configuration
type HTTPConfig struct {
	Port               int      // HTTP server port
	ServerURL          string   // Public server URL for OAuth metadata
	CORSAllowedOrigins []string // Allowed CORS origins
}

// OAuthConfig holds OAuth-specific configuration
type OAuthConfig struct {
	AllowedRedirectURIs []string // Allowed OAuth redirect URIs (exact match)
	RedisURL            string   // Redis URL (e.g., redis://user:password@host:port/db)
	EncryptionKey       string   // Base64-encoded 32-byte key for token encryption (AES-256)
}

// TLSConfig holds TLS/HTTPS configuration
type TLSConfig struct {
	Enable bool   // Enable HTTPS with TLS
	Cert   string // Path to TLS certificate file
	Key    string // Path to TLS private key file
}

// FeatureConfig holds optional feature flags
type FeatureConfig struct {
	EnableAudit bool
	AuditLevel  string
	SDKCacheTTL time.Duration
}

// Config holds all configuration for the MCP server
type Config struct {
	Server   ServerConfig
	HTTP     HTTPConfig
	OAuth    OAuthConfig
	TLS      TLSConfig
	Auth     *auth.AuthContext
	Features FeatureConfig
}

// Load loads configuration from environment variables
// Priority: environment variables > defaults
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Mode:     getEnv("MCP_MODE", "stdio"),
			Profile:  os.Getenv("MCP_PROFILE"), // Empty string if not set - enables URL-based routing
			LogLevel: getEnv("LOG_LEVEL", "info"),
		},
		HTTP: HTTPConfig{
			Port:               getIntEnv("PORT", 8080),
			ServerURL:          getEnv("MCP_SERVER_URL", "http://localhost:8080"),
			CORSAllowedOrigins: getSliceEnv("CORS_ALLOWED_ORIGINS", []string{}),
		},
		OAuth: OAuthConfig{
			AllowedRedirectURIs: getSliceEnv("ALLOWED_REDIRECT_URIS", []string{
				"http://localhost/callback",
				"http://127.0.0.1/callback",
			}),
			RedisURL:      getEnv("REDIS_URL", "redis://localhost:6379/0"),
			EncryptionKey: getEnv("REDIS_ENCRYPTION_KEY", ""),
		},
		TLS: TLSConfig{
			Enable: getBoolEnv("ENABLE_TLS", false),
			Cert:   getEnv("TLS_CERT_FILE", ""),
			Key:    getEnv("TLS_KEY_FILE", ""),
		},
		Features: FeatureConfig{
			EnableAudit: getBoolEnv("AUDIT_LOG_ENABLED", false),
			AuditLevel:  getEnv("AUDIT_LOG_LEVEL", "MEDIUM"),
			SDKCacheTTL: getDurationEnv("SDK_CACHE_TTL", 5*time.Minute),
		},
	}

	// Validate mode
	if cfg.Server.Mode != "stdio" && cfg.Server.Mode != "http" {
		return nil, fmt.Errorf("invalid MCP_MODE: %s (must be 'stdio' or 'http')", cfg.Server.Mode)
	}

	// Load authentication configuration first (needed for HTTP validation)
	authContext, err := loadAuthContext(cfg.Server.Mode)
	if err != nil {
		return nil, fmt.Errorf("failed to load authentication: %w", err)
	}
	cfg.Auth = authContext

	// For HTTP mode, validate OAuth-specific configuration
	if cfg.Server.Mode == "http" {
		// Only require Redis/OAuth config if server doesn't have credentials
		// If server has credentials, OAuth is optional (for dual-mode support)
		if !cfg.Auth.HasCredentials() && cfg.OAuth.EncryptionKey == "" {
			return nil, fmt.Errorf("REDIS_ENCRYPTION_KEY is required for HTTP mode without server credentials (LC_UID/LC_API_KEY)")
		}
		// Note: Base64 validation is done in crypto package when initializing encryption

		// Validate TLS configuration if enabled
		if cfg.TLS.Enable {
			if cfg.TLS.Cert == "" || cfg.TLS.Key == "" {
				return nil, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE are required when ENABLE_TLS=true")
			}
		}
	}

	return cfg, nil
}

// loadAuthContext loads authentication from environment variables
// For HTTP mode, returns credentials if configured (server-wide auth),
// otherwise returns a placeholder for per-request OAuth Bearer tokens
func loadAuthContext(mode string) (*auth.AuthContext, error) {
	// Load credentials from environment for ALL modes
	oid := os.Getenv("LC_OID")
	apiKey := os.Getenv("LC_API_KEY")
	uid := os.Getenv("LC_UID")
	environment := os.Getenv("LC_CURRENT_ENV")
	jwtToken := os.Getenv("LC_JWT")

	// Validate OID format if provided
	if oid != "" {
		if err := auth.ValidateOID(oid); err != nil {
			return nil, fmt.Errorf("invalid LC_OID: %w", err)
		}
	}

	// Validate UID format if provided
	if uid != "" {
		if err := auth.ValidateUID(uid); err != nil {
			return nil, fmt.Errorf("invalid LC_UID: %w", err)
		}
	}

	// Validate API key format if provided
	if apiKey != "" {
		if err := auth.ValidateAPIKey(apiKey); err != nil {
			return nil, fmt.Errorf("invalid LC_API_KEY: %w", err)
		}
	}

	// Validate JWT format if provided
	if jwtToken != "" {
		if err := auth.ValidateJWT(jwtToken); err != nil {
			return nil, fmt.Errorf("invalid LC_JWT: %w", err)
		}
	}

	// Determine authentication mode
	var authMode auth.AuthMode
	if uid != "" {
		// UID mode
		if jwtToken != "" || environment != "" {
			authMode = auth.AuthModeUIDOAuth
		} else if apiKey != "" {
			authMode = auth.AuthModeUIDKey
		} else {
			// UID set but no API key or JWT
			if mode == "http" {
				// For HTTP mode, return placeholder - auth will come from Bearer tokens
				return &auth.AuthContext{
					Mode: auth.AuthModeUIDOAuth,
					// Empty credentials - will be populated from OAuth tokens per-request
				}, nil
			}
			return nil, fmt.Errorf("UID mode requires either API key or JWT/environment")
		}
	} else {
		// Normal mode or no credentials
		if oid == "" && apiKey == "" {
			// No auth configured
			if mode == "http" {
				// For HTTP mode, return placeholder - auth will come from Bearer tokens
				return &auth.AuthContext{
					Mode: auth.AuthModeUIDOAuth,
					// Empty credentials - will be populated from OAuth tokens per-request
				}, nil
			}
			// For STDIO mode, this is an error
			return nil, fmt.Errorf("no authentication configured: set LC_OID and LC_API_KEY for normal mode, or LC_UID for UID mode")
		}
		authMode = auth.AuthModeNormal
	}

	authCtx := &auth.AuthContext{
		Mode:        authMode,
		OID:         oid,
		APIKey:      apiKey,
		UID:         uid,
		JWTToken:    jwtToken,
		Environment: environment,
	}

	// Validate the auth context
	if err := authCtx.Validate(); err != nil {
		return nil, fmt.Errorf("invalid authentication configuration: %w", err)
	}

	return authCtx, nil
}

// getEnv gets an environment variable with a default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getBoolEnv gets a boolean environment variable
func getBoolEnv(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	value = strings.ToLower(value)
	return value == "true" || value == "1" || value == "yes"
}

// getIntEnv gets an integer environment variable
func getIntEnv(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	var intValue int
	_, err := fmt.Sscanf(value, "%d", &intValue)
	if err != nil {
		return defaultValue
	}
	return intValue
}

// getDurationEnv gets a duration environment variable
func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return defaultValue
	}
	return duration
}

// getSliceEnv gets a comma-separated list environment variable
func getSliceEnv(key string, defaultValue []string) []string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return defaultValue
	}
	return result
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate profile (empty string means "not configured" - enables URL-based routing)
	validProfiles := map[string]bool{
		"":                         true, // Not configured - use URL-based routing in HTTP mode
		"core":                     true,
		"historical_data":          true,
		"historical_data_readonly": true,
		"live_investigation":       true,
		"threat_response":          true,
		"fleet_management":         true,
		"detection_engineering":    true,
		"platform_admin":           true,
		"ai_powered":               true,
		"all":                      true,
	}

	if !validProfiles[c.Server.Profile] {
		return fmt.Errorf("invalid profile: %s", c.Server.Profile)
	}

	// Validate log level
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}

	if !validLogLevels[c.Server.LogLevel] {
		return fmt.Errorf("invalid log level: %s", c.Server.LogLevel)
	}

	return nil
}
