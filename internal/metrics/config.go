package metrics

import (
	"os"
	"strings"
	"time"
)

// Config holds configuration for GCP metrics reporting
type Config struct {
	Enabled        bool          // Whether metrics reporting is enabled
	ProjectID      string        // GCP project ID (empty = auto-detect from ADC)
	ReportInterval time.Duration // How often to report metrics to GCP
}

// LoadConfig loads metrics configuration from environment variables
func LoadConfig() *Config {
	return &Config{
		Enabled:        getBoolEnv("ENABLE_METRICS", false),
		ProjectID:      os.Getenv("METRICS_PROJECT_ID"), // Empty = auto-detect
		ReportInterval: getDurationEnv("METRICS_REPORT_INTERVAL", 60*time.Second),
	}
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
