package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
)

// Config holds all configuration for the MCP server
type Config struct {
	// Server configuration
	Mode     string // "stdio" or "http"
	Profile  string // Profile to expose: "core", "all", etc.
	LogLevel string // "debug", "info", "warn", "error"

	// HTTP server configuration (for OAuth mode)
	HTTPPort           int      // HTTP server port
	ServerURL          string   // Public server URL for OAuth metadata
	CORSAllowedOrigins []string // Allowed CORS origins

	// TLS/HTTPS configuration
	EnableTLS bool   // Enable HTTPS with TLS
	TLSCert   string // Path to TLS certificate file
	TLSKey    string // Path to TLS private key file

	// OAuth security configuration
	AllowedRedirectURIs []string // Allowed OAuth redirect URIs (exact match)

	// Redis configuration (for OAuth state management)
	RedisAddress  string // Redis server address (host:port)
	RedisPassword string // Redis password (optional)
	RedisDB       int    // Redis database number

	// OAuth configuration
	EncryptionKey string // Base64-encoded 32-byte key for token encryption (AES-256)

	// Authentication (loaded from environment or config file)
	Auth *auth.AuthContext

	// Optional features
	EnableAudit bool
	AuditLevel  string

	// SDK cache settings
	SDKCacheTTL time.Duration
}

// Load loads configuration from environment variables
// Priority: environment variables > defaults
func Load() (*Config, error) {
	cfg := &Config{
		Mode:        getEnv("MCP_MODE", "stdio"),
		Profile:     getEnv("MCP_PROFILE", "all"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),
		EnableAudit: getBoolEnv("AUDIT_LOG_ENABLED", false),
		AuditLevel:  getEnv("AUDIT_LOG_LEVEL", "MEDIUM"),
		SDKCacheTTL: getDurationEnv("SDK_CACHE_TTL", 5*time.Minute),

		// HTTP server configuration
		HTTPPort:           getIntEnv("PORT", 8080),
		ServerURL:          getEnv("MCP_SERVER_URL", "http://localhost:8080"),
		CORSAllowedOrigins: getSliceEnv("CORS_ALLOWED_ORIGINS", []string{}),

		// TLS configuration
		EnableTLS: getBoolEnv("ENABLE_TLS", false),
		TLSCert:   getEnv("TLS_CERT_FILE", ""),
		TLSKey:    getEnv("TLS_KEY_FILE", ""),

		// OAuth security configuration
		AllowedRedirectURIs: getSliceEnv("ALLOWED_REDIRECT_URIS", []string{
			"http://localhost/callback",
			"http://127.0.0.1/callback",
		}),

		// Redis configuration
		RedisAddress:  getEnv("REDIS_ADDRESS", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		RedisDB:       getIntEnv("REDIS_DB", 0),

		// OAuth configuration
		EncryptionKey: getEnv("REDIS_ENCRYPTION_KEY", ""),
	}

	// Validate mode
	if cfg.Mode != "stdio" && cfg.Mode != "http" {
		return nil, fmt.Errorf("invalid MCP_MODE: %s (must be 'stdio' or 'http')", cfg.Mode)
	}

	// For HTTP mode, validate OAuth-specific configuration
	if cfg.Mode == "http" {
		if cfg.EncryptionKey == "" {
			return nil, fmt.Errorf("REDIS_ENCRYPTION_KEY is required for HTTP mode (base64-encoded 32-byte key)")
		}
		// Note: Base64 validation is done in crypto package when initializing encryption

		// Validate TLS configuration if enabled
		if cfg.EnableTLS {
			if cfg.TLSCert == "" || cfg.TLSKey == "" {
				return nil, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE are required when ENABLE_TLS=true")
			}
		}
	}

	// Load authentication configuration
	authContext, err := loadAuthContext()
	if err != nil {
		return nil, fmt.Errorf("failed to load authentication: %w", err)
	}
	cfg.Auth = authContext

	return cfg, nil
}

// loadAuthContext loads authentication from environment variables
func loadAuthContext() (*auth.AuthContext, error) {
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
	var mode auth.AuthMode
	if uid != "" {
		// UID mode
		if jwtToken != "" || environment != "" {
			mode = auth.AuthModeUIDOAuth
		} else if apiKey != "" {
			mode = auth.AuthModeUIDKey
		} else {
			return nil, fmt.Errorf("UID mode requires either API key or JWT/environment")
		}
	} else {
		// Normal mode
		mode = auth.AuthModeNormal
		if oid == "" && apiKey == "" {
			// No auth configured - this is okay for testing
			// but tools will fail without credentials
			return nil, fmt.Errorf("no authentication configured: set LC_OID and LC_API_KEY for normal mode, or LC_UID for UID mode")
		}
	}

	authCtx := &auth.AuthContext{
		Mode:        mode,
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
	// Validate profile
	validProfiles := map[string]bool{
		"core":                  true,
		"historical_data":       true,
		"live_investigation":    true,
		"threat_response":       true,
		"fleet_management":      true,
		"detection_engineering": true,
		"platform_admin":        true,
		"all":                   true,
	}

	if !validProfiles[c.Profile] {
		return fmt.Errorf("invalid profile: %s", c.Profile)
	}

	// Validate log level
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}

	if !validLogLevels[c.LogLevel] {
		return fmt.Errorf("invalid log level: %s", c.LogLevel)
	}

	return nil
}
