package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	// Save original env vars
	origEnv := map[string]string{
		"MCP_MODE":       os.Getenv("MCP_MODE"),
		"MCP_PROFILE":    os.Getenv("MCP_PROFILE"),
		"LOG_LEVEL":      os.Getenv("LOG_LEVEL"),
		"LC_OID":         os.Getenv("LC_OID"),
		"LC_API_KEY":     os.Getenv("LC_API_KEY"),
		"LC_UID":         os.Getenv("LC_UID"),
		"LC_CURRENT_ENV": os.Getenv("LC_CURRENT_ENV"),
	}

	// Restore env vars after test
	defer func() {
		for key, value := range origEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	t.Run("default values", func(t *testing.T) {
		// Clear all env vars
		os.Unsetenv("MCP_MODE")
		os.Unsetenv("MCP_PROFILE")
		os.Unsetenv("LOG_LEVEL")
		os.Setenv("LC_OID", "test-org")
		os.Setenv("LC_API_KEY", "test-key-1234567890")

		cfg, err := Load()
		require.NoError(t, err)

		assert.Equal(t, "stdio", cfg.Mode)
		assert.Equal(t, "all", cfg.Profile)
		assert.Equal(t, "info", cfg.LogLevel)
		assert.False(t, cfg.EnableAudit)
		assert.Equal(t, 5*time.Minute, cfg.SDKCacheTTL)
	})

	t.Run("custom values", func(t *testing.T) {
		os.Setenv("MCP_MODE", "stdio")
		os.Setenv("MCP_PROFILE", "core")
		os.Setenv("LOG_LEVEL", "debug")
		os.Setenv("AUDIT_LOG_ENABLED", "true")
		os.Setenv("SDK_CACHE_TTL", "10m")
		os.Setenv("LC_OID", "test-org")
		os.Setenv("LC_API_KEY", "test-key-1234567890")

		cfg, err := Load()
		require.NoError(t, err)

		assert.Equal(t, "stdio", cfg.Mode)
		assert.Equal(t, "core", cfg.Profile)
		assert.Equal(t, "debug", cfg.LogLevel)
		assert.True(t, cfg.EnableAudit)
		assert.Equal(t, 10*time.Minute, cfg.SDKCacheTTL)
	})

	t.Run("normal mode authentication", func(t *testing.T) {
		os.Unsetenv("LC_UID")
		os.Setenv("LC_OID", "test-org")
		os.Setenv("LC_API_KEY", "test-key-1234567890")

		cfg, err := Load()
		require.NoError(t, err)

		require.NotNil(t, cfg.Auth)
		assert.Equal(t, "test-org", cfg.Auth.OID)
		assert.Equal(t, "test-key-1234567890", cfg.Auth.APIKey)
	})

	t.Run("UID mode with API key", func(t *testing.T) {
		os.Setenv("LC_UID", "user@example.com")
		os.Setenv("LC_API_KEY", "test-key-1234567890")
		os.Unsetenv("LC_OID")

		cfg, err := Load()
		require.NoError(t, err)

		require.NotNil(t, cfg.Auth)
		assert.Equal(t, "user@example.com", cfg.Auth.UID)
		assert.Equal(t, "test-key-1234567890", cfg.Auth.APIKey)
	})

	t.Run("invalid mode", func(t *testing.T) {
		os.Setenv("MCP_MODE", "invalid")
		os.Setenv("LC_OID", "test-org")
		os.Setenv("LC_API_KEY", "test-key-1234567890")

		_, err := Load()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid MCP_MODE")
	})

	t.Run("missing authentication", func(t *testing.T) {
		os.Setenv("MCP_MODE", "stdio") // Reset to valid mode
		os.Unsetenv("LC_OID")
		os.Unsetenv("LC_API_KEY")
		os.Unsetenv("LC_UID")

		_, err := Load()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no authentication configured")
	})
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: &Config{
				Mode:     "stdio",
				Profile:  "core",
				LogLevel: "info",
			},
			wantErr: false,
		},
		{
			name: "invalid profile",
			config: &Config{
				Mode:     "stdio",
				Profile:  "invalid",
				LogLevel: "info",
			},
			wantErr: true,
			errMsg:  "invalid profile",
		},
		{
			name: "invalid log level",
			config: &Config{
				Mode:     "stdio",
				Profile:  "core",
				LogLevel: "invalid",
			},
			wantErr: true,
			errMsg:  "invalid log level",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetBoolEnv(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		defaultValue bool
		expected     bool
	}{
		{"true", "true", false, true},
		{"1", "1", false, true},
		{"yes", "yes", false, true},
		{"false", "false", true, false},
		{"0", "0", true, false},
		{"no", "no", true, false},
		{"empty", "", true, true},
		{"empty default false", "", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("TEST_BOOL", tt.value)
			result := getBoolEnv("TEST_BOOL", tt.defaultValue)
			assert.Equal(t, tt.expected, result)
			os.Unsetenv("TEST_BOOL")
		})
	}
}

func TestGetDurationEnv(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		defaultValue time.Duration
		expected     time.Duration
	}{
		{"5 minutes", "5m", 1 * time.Minute, 5 * time.Minute},
		{"30 seconds", "30s", 1 * time.Minute, 30 * time.Second},
		{"1 hour", "1h", 1 * time.Minute, 1 * time.Hour},
		{"invalid", "invalid", 1 * time.Minute, 1 * time.Minute},
		{"empty", "", 5 * time.Minute, 5 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("TEST_DURATION", tt.value)
			result := getDurationEnv("TEST_DURATION", tt.defaultValue)
			assert.Equal(t, tt.expected, result)
			os.Unsetenv("TEST_DURATION")
		})
	}
}
