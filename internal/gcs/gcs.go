package gcs

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

// Config holds GCS configuration
type Config struct {
	BucketName        string
	TokenThreshold    int
	URLExpiryHours    int
	SignerServiceAcct string
	Enabled           bool
}

// LoadConfig loads GCS configuration from environment variables
func LoadConfig() *Config {
	bucketName := os.Getenv("GCS_BUCKET_NAME")

	// Parse token threshold with default
	tokenThreshold := 1000
	if val := os.Getenv("GCS_TOKEN_THRESHOLD"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			tokenThreshold = parsed
		}
	}

	// Parse URL expiry with default
	urlExpiryHours := 24
	if val := os.Getenv("GCS_URL_EXPIRY_HOURS"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			urlExpiryHours = parsed
		}
	}

	signerServiceAcct := os.Getenv("GCS_SIGNER_SERVICE_ACCOUNT")
	if signerServiceAcct == "" {
		signerServiceAcct = "mcp-server@lc-api.iam.gserviceaccount.com"
	}

	return &Config{
		BucketName:        bucketName,
		TokenThreshold:    tokenThreshold,
		URLExpiryHours:    urlExpiryHours,
		SignerServiceAcct: signerServiceAcct,
		Enabled:           bucketName != "",
	}
}

// Manager handles GCS operations for large results
type Manager struct {
	config *Config
	client *storage.Client
}

// NewManager creates a new GCS manager
func NewManager(ctx context.Context, config *Config) (*Manager, error) {
	if !config.Enabled {
		return &Manager{config: config}, nil
	}

	// Create GCS client with default credentials
	client, err := storage.NewClient(ctx, option.WithScopes(storage.ScopeFullControl))
	if err != nil {
		return nil, fmt.Errorf("failed to create GCS client: %w", err)
	}

	return &Manager{
		config: config,
		client: client,
	}, nil
}

// Close closes the GCS client
func (m *Manager) Close() error {
	if m.client != nil {
		return m.client.Close()
	}
	return nil
}

// EstimateTokenCount estimates token count from JSON data (roughly 4 chars per token)
func EstimateTokenCount(data interface{}) (int, error) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return len(jsonBytes) / 4, nil
}

// UploadResult represents the result of an upload operation
type UploadResult struct {
	URL      string
	FileSize int64
	IsTemp   bool // true if saved to temp file instead of GCS
}

// UploadToGCS uploads data to GCS or saves to temp file and returns URL/path
func (m *Manager) UploadToGCS(ctx context.Context, data interface{}, toolName string) (*UploadResult, error) {
	// Convert data to JSON
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Create unique filename
	timestamp := time.Now().UTC().Format("20060102_150405")
	uniqueID := fmt.Sprintf("%x", time.Now().UnixNano()%0xFFFFFFFF)
	filename := fmt.Sprintf("%s_%s_%s.json", toolName, timestamp, uniqueID)

	// If GCS not enabled, use temp file
	if !m.config.Enabled {
		tempFile, err := os.CreateTemp("", fmt.Sprintf("lc-mcp-%s-*.json", toolName))
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file: %w", err)
		}

		if _, err := tempFile.Write(jsonBytes); err != nil {
			tempFile.Close()
			os.Remove(tempFile.Name())
			return nil, fmt.Errorf("failed to write temp file: %w", err)
		}

		tempFile.Close()

		slog.Info("Saved large result to temp file",
			"path", tempFile.Name(),
			"size", len(jsonBytes))

		return &UploadResult{
			URL:      tempFile.Name(),
			FileSize: int64(len(jsonBytes)),
			IsTemp:   true,
		}, nil
	}

	// Upload to GCS
	bucket := m.client.Bucket(m.config.BucketName)
	obj := bucket.Object(filename)

	writer := obj.NewWriter(ctx)
	writer.ContentType = "application/json"

	if _, err := writer.Write(jsonBytes); err != nil {
		writer.Close()
		return nil, fmt.Errorf("failed to write to GCS: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close GCS writer: %w", err)
	}

	// Generate signed URL
	expiryTime := time.Now().Add(time.Duration(m.config.URLExpiryHours) * time.Hour)

	// Use storage.SignedURL with the bucket and object names
	opts := &storage.SignedURLOptions{
		GoogleAccessID: m.config.SignerServiceAcct,
		Method:         "GET",
		Expires:        expiryTime,
		Scheme:         storage.SigningSchemeV4,
	}

	signedURL, err := storage.SignedURL(m.config.BucketName, filename, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signed URL: %w", err)
	}

	slog.Info("Uploaded large result to GCS",
		"filename", filename,
		"size", len(jsonBytes),
		"expires", expiryTime)

	return &UploadResult{
		URL:      signedURL,
		FileSize: int64(len(jsonBytes)),
		IsTemp:   false,
	}, nil
}

// ShouldUpload determines if a result should be uploaded based on token count
func (m *Manager) ShouldUpload(data interface{}) (bool, int, error) {
	tokenCount, err := EstimateTokenCount(data)
	if err != nil {
		return false, 0, err
	}

	return tokenCount > m.config.TokenThreshold, tokenCount, nil
}

// WrapResult wraps a tool result, uploading to GCS if it's too large
func (m *Manager) WrapResult(ctx context.Context, data interface{}, toolName string) (interface{}, error) {
	shouldUpload, tokenCount, err := m.ShouldUpload(data)
	if err != nil {
		slog.Warn("Failed to estimate token count, returning result inline",
			"tool", toolName,
			"error", err)
		return data, nil
	}

	if shouldUpload {
		slog.Info("Tool result exceeds threshold, uploading to GCS",
			"tool", toolName,
			"tokens", tokenCount,
			"threshold", m.config.TokenThreshold)

		result, err := m.UploadToGCS(ctx, data, toolName)
		if err != nil {
			slog.Warn("Failed to upload to GCS, returning result inline",
				"tool", toolName,
				"error", err)
			return data, nil
		}

		// Return alternate response
		return map[string]interface{}{
			"resource_link": result.URL,
			"resource_size": result.FileSize,
			"success":       true,
			"reason":        "results too large, see resource_link for content",
			"is_temp_file":  result.IsTemp,
		}, nil
	}

	slog.Info("Tool result within threshold, returning inline",
		"tool", toolName,
		"tokens", tokenCount,
		"threshold", m.config.TokenThreshold)

	return data, nil
}
