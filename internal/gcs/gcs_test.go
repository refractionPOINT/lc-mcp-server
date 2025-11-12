package gcs

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	// Save original env vars
	origBucket := os.Getenv("GCS_BUCKET_NAME")
	origThreshold := os.Getenv("GCS_TOKEN_THRESHOLD")
	origExpiry := os.Getenv("GCS_URL_EXPIRY_HOURS")
	origSigner := os.Getenv("GCS_SIGNER_SERVICE_ACCOUNT")

	defer func() {
		os.Setenv("GCS_BUCKET_NAME", origBucket)
		os.Setenv("GCS_TOKEN_THRESHOLD", origThreshold)
		os.Setenv("GCS_URL_EXPIRY_HOURS", origExpiry)
		os.Setenv("GCS_SIGNER_SERVICE_ACCOUNT", origSigner)
	}()

	t.Run("loads default configuration", func(t *testing.T) {
		os.Unsetenv("GCS_BUCKET_NAME")
		os.Unsetenv("GCS_TOKEN_THRESHOLD")
		os.Unsetenv("GCS_URL_EXPIRY_HOURS")
		os.Unsetenv("GCS_SIGNER_SERVICE_ACCOUNT")

		cfg := LoadConfig()

		assert.Empty(t, cfg.BucketName)
		assert.Equal(t, 1000, cfg.TokenThreshold)
		assert.Equal(t, 24, cfg.URLExpiryHours)
		assert.Equal(t, "mcp-server@lc-api.iam.gserviceaccount.com", cfg.SignerServiceAcct)
		assert.False(t, cfg.Enabled, "Should be disabled when no bucket name")
	})

	t.Run("loads custom configuration", func(t *testing.T) {
		os.Setenv("GCS_BUCKET_NAME", "my-test-bucket")
		os.Setenv("GCS_TOKEN_THRESHOLD", "500")
		os.Setenv("GCS_URL_EXPIRY_HOURS", "48")
		os.Setenv("GCS_SIGNER_SERVICE_ACCOUNT", "custom@example.iam.gserviceaccount.com")

		cfg := LoadConfig()

		assert.Equal(t, "my-test-bucket", cfg.BucketName)
		assert.Equal(t, 500, cfg.TokenThreshold)
		assert.Equal(t, 48, cfg.URLExpiryHours)
		assert.Equal(t, "custom@example.iam.gserviceaccount.com", cfg.SignerServiceAcct)
		assert.True(t, cfg.Enabled, "Should be enabled when bucket name is set")
	})

	t.Run("handles invalid threshold gracefully", func(t *testing.T) {
		os.Setenv("GCS_BUCKET_NAME", "test-bucket")
		os.Setenv("GCS_TOKEN_THRESHOLD", "invalid")

		cfg := LoadConfig()

		assert.Equal(t, 1000, cfg.TokenThreshold, "Should use default on invalid value")
	})

	t.Run("handles invalid expiry gracefully", func(t *testing.T) {
		os.Setenv("GCS_BUCKET_NAME", "test-bucket")
		os.Setenv("GCS_URL_EXPIRY_HOURS", "not-a-number")

		cfg := LoadConfig()

		assert.Equal(t, 24, cfg.URLExpiryHours, "Should use default on invalid value")
	})
}

func TestNewManager(t *testing.T) {
	ctx := context.Background()

	t.Run("creates manager when disabled", func(t *testing.T) {
		cfg := &Config{
			Enabled: false,
		}

		mgr, err := NewManager(ctx, cfg)

		require.NoError(t, err)
		assert.NotNil(t, mgr)
		assert.Nil(t, mgr.client, "Client should be nil when disabled")
		assert.Equal(t, cfg, mgr.config)
	})

	t.Run("returns manager without error when disabled", func(t *testing.T) {
		cfg := &Config{
			BucketName:     "",
			TokenThreshold: 1000,
			Enabled:        false,
		}

		mgr, err := NewManager(ctx, cfg)

		require.NoError(t, err)
		assert.NotNil(t, mgr)
	})
}

func TestManager_Close(t *testing.T) {
	ctx := context.Background()

	t.Run("closes disabled manager without error", func(t *testing.T) {
		cfg := &Config{Enabled: false}
		mgr, _ := NewManager(ctx, cfg)

		err := mgr.Close()

		assert.NoError(t, err)
	})
}

func TestEstimateTokenCount(t *testing.T) {
	tests := []struct {
		name          string
		data          interface{}
		expectedMin   int
		expectedMax   int
		shouldError   bool
	}{
		{
			name:        "empty object",
			data:        map[string]interface{}{},
			expectedMin: 0,
			expectedMax: 1,
			shouldError: false,
		},
		{
			name: "small object",
			data: map[string]interface{}{
				"key": "value",
			},
			expectedMin: 3,
			expectedMax: 6,
			shouldError: false,
		},
		{
			name: "larger object",
			data: map[string]interface{}{
				"sensor_id": "abc-123",
				"hostname":  "server1",
				"tags":      []string{"production", "web-server"},
			},
			expectedMin: 15,
			expectedMax: 30,
			shouldError: false,
		},
		{
			name:        "array",
			data:        []int{1, 2, 3, 4, 5},
			expectedMin: 2,
			expectedMax: 5,
			shouldError: false,
		},
		{
			name:        "string",
			data:        "hello world",
			expectedMin: 2,
			expectedMax: 5,
			shouldError: false,
		},
		{
			name:        "number",
			data:        12345,
			expectedMin: 1,
			expectedMax: 3,
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, err := EstimateTokenCount(tt.data)

			if tt.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.GreaterOrEqual(t, count, tt.expectedMin, "Token count should be at least minimum")
				assert.LessOrEqual(t, count, tt.expectedMax, "Token count should be at most maximum")
			}
		})
	}

	t.Run("handles unmarshalable data", func(t *testing.T) {
		// Functions can't be marshaled to JSON
		data := map[string]interface{}{
			"func": func() {},
		}

		_, err := EstimateTokenCount(data)

		assert.Error(t, err)
	})
}

func TestManager_ShouldUpload(t *testing.T) {
	ctx := context.Background()
	cfg := &Config{
		TokenThreshold: 100,
		Enabled:        false,
	}
	mgr, _ := NewManager(ctx, cfg)

	t.Run("returns false for small data", func(t *testing.T) {
		data := map[string]interface{}{
			"key": "value",
		}

		shouldUpload, tokenCount, err := mgr.ShouldUpload(data)

		assert.NoError(t, err)
		assert.False(t, shouldUpload)
		assert.Less(t, tokenCount, 100)
	})

	t.Run("returns true for large data", func(t *testing.T) {
		// Create data that will exceed threshold (need ~400+ chars for 100+ tokens)
		largeData := make(map[string]interface{})
		for i := 0; i < 50; i++ {
			largeData[string(rune('a'+i%26))+string(rune(i))] = "this is a long value that will increase the token count significantly"
		}

		shouldUpload, tokenCount, err := mgr.ShouldUpload(largeData)

		assert.NoError(t, err)
		assert.True(t, shouldUpload, "Large data should trigger upload")
		assert.Greater(t, tokenCount, 100, "Token count should exceed threshold")
	})

	t.Run("handles unmarshalable data", func(t *testing.T) {
		data := map[string]interface{}{
			"func": func() {},
		}

		shouldUpload, tokenCount, err := mgr.ShouldUpload(data)

		assert.Error(t, err)
		assert.False(t, shouldUpload)
		assert.Equal(t, 0, tokenCount)
	})
}

func TestManager_UploadToTempFile(t *testing.T) {
	ctx := context.Background()
	cfg := &Config{
		TokenThreshold: 100,
		Enabled:        false,
	}
	mgr, _ := NewManager(ctx, cfg)

	t.Run("creates temp file successfully", func(t *testing.T) {
		data := map[string]interface{}{
			"test": "data",
			"number": 123,
		}

		result, err := mgr.uploadToTempFile(data, "test_tool")

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.URL, "Should have file path")
		assert.Greater(t, result.FileSize, int64(0), "Should have file size")
		assert.True(t, result.IsTemp, "Should be marked as temp file")

		// Verify file exists and contains valid JSON
		fileContents, err := os.ReadFile(result.URL)
		require.NoError(t, err)

		var parsedData map[string]interface{}
		err = json.Unmarshal(fileContents, &parsedData)
		assert.NoError(t, err)
		assert.Equal(t, "data", parsedData["test"])
		assert.Equal(t, float64(123), parsedData["number"]) // JSON numbers are float64

		// Cleanup
		os.Remove(result.URL)
	})

	t.Run("handles unmarshalable data", func(t *testing.T) {
		data := map[string]interface{}{
			"func": func() {},
		}

		result, err := mgr.uploadToTempFile(data, "test_tool")

		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestManager_WrapResult_Disabled(t *testing.T) {
	ctx := context.Background()

	t.Run("returns small data inline", func(t *testing.T) {
		cfg := &Config{
			TokenThreshold: 1000,
			Enabled:        false,
		}
		mgr, _ := NewManager(ctx, cfg)

		data := map[string]interface{}{
			"sensor_id": "abc-123",
			"status":    "online",
		}

		wrapped, err := mgr.WrapResult(ctx, data, "test_tool")

		assert.NoError(t, err)
		assert.Equal(t, data, wrapped, "Small data should be returned inline")
	})

	t.Run("uploads large data to temp file when disabled", func(t *testing.T) {
		cfg := &Config{
			TokenThreshold: 10, // Low threshold to trigger upload
			Enabled:        false, // GCS disabled, should use temp file
		}
		mgr, _ := NewManager(ctx, cfg)

		// Create large data
		largeData := make(map[string]interface{})
		for i := 0; i < 20; i++ {
			largeData[string(rune('a'+i%26))+string(rune(i))] = "this is a long value"
		}

		wrapped, err := mgr.WrapResult(ctx, largeData, "test_tool")

		require.NoError(t, err)
		wrappedMap, ok := wrapped.(map[string]interface{})
		require.True(t, ok, "Should return wrapped response")

		assert.Contains(t, wrappedMap, "resource_link")
		assert.Contains(t, wrappedMap, "resource_size")
		assert.Equal(t, true, wrappedMap["success"])
		assert.Equal(t, true, wrappedMap["is_temp_file"])

		// Verify file exists
		filePath, ok := wrappedMap["resource_link"].(string)
		require.True(t, ok)
		assert.FileExists(t, filePath)

		// Cleanup
		os.Remove(filePath)
	})

	t.Run("handles unmarshalable data gracefully", func(t *testing.T) {
		cfg := &Config{
			TokenThreshold: 10,
			Enabled:        false,
		}
		mgr, _ := NewManager(ctx, cfg)

		data := map[string]interface{}{
			"func": func() {},
		}

		wrapped, err := mgr.WrapResult(ctx, data, "test_tool")

		// Should return data as-is when estimation fails
		assert.NoError(t, err)
		assert.Equal(t, data, wrapped)
	})
}

func TestContext_Operations(t *testing.T) {
	ctx := context.Background()

	t.Run("WithGCSManager and GetGCSManager", func(t *testing.T) {
		cfg := &Config{Enabled: false}
		mgr, _ := NewManager(ctx, cfg)

		newCtx := WithGCSManager(ctx, mgr)
		retrieved := GetGCSManager(newCtx)

		assert.Equal(t, mgr, retrieved)
	})

	t.Run("GetGCSManager returns nil when not set", func(t *testing.T) {
		retrieved := GetGCSManager(ctx)

		assert.Nil(t, retrieved)
	})
}

func TestMaybeWrapResult(t *testing.T) {
	ctx := context.Background()

	t.Run("returns data as-is when no GCS manager in context", func(t *testing.T) {
		data := map[string]interface{}{
			"key": "value",
		}

		result, err := MaybeWrapResult(ctx, data, "test_tool")

		assert.NoError(t, err)
		assert.Equal(t, data, result)
	})

	t.Run("uses GCS manager when available in context", func(t *testing.T) {
		cfg := &Config{
			TokenThreshold: 1000,
			Enabled:        false,
		}
		mgr, _ := NewManager(ctx, cfg)
		ctxWithMgr := WithGCSManager(ctx, mgr)

		data := map[string]interface{}{
			"key": "value",
		}

		result, err := MaybeWrapResult(ctxWithMgr, data, "test_tool")

		assert.NoError(t, err)
		// Should return inline since data is small
		assert.Equal(t, data, result)
	})
}

func TestWrapMCPResult(t *testing.T) {
	ctx := context.Background()
	cfg := &Config{
		TokenThreshold: 1000,
		Enabled:        false,
	}
	mgr, _ := NewManager(ctx, cfg)
	ctxWithMgr := WithGCSManager(ctx, mgr)

	t.Run("returns non-MCP result as-is", func(t *testing.T) {
		data := "simple string"

		result := WrapMCPResult(ctxWithMgr, data, "test_tool")

		assert.Equal(t, data, result)
	})

	t.Run("returns error result as-is", func(t *testing.T) {
		errorResult := map[string]interface{}{
			"isError": true,
			"content": []interface{}{
				map[string]interface{}{
					"type": "text",
					"text": "Error occurred",
				},
			},
		}

		result := WrapMCPResult(ctxWithMgr, errorResult, "test_tool")

		assert.Equal(t, errorResult, result)
	})

	t.Run("processes MCP success result with JSON content", func(t *testing.T) {
		jsonData := map[string]interface{}{
			"sensor_id": "abc-123",
			"hostname":  "server1",
		}
		jsonText, _ := json.Marshal(jsonData)

		mcpResult := map[string]interface{}{
			"isError": false,
			"content": []interface{}{
				map[string]interface{}{
					"type": "text",
					"text": string(jsonText),
				},
			},
		}

		result := WrapMCPResult(ctxWithMgr, mcpResult, "test_tool")

		// Since data is small, should return inline (just reformatted)
		resultMap, ok := result.(map[string]interface{})
		assert.True(t, ok)
		assert.Contains(t, resultMap, "content")
	})

	t.Run("handles non-JSON text content", func(t *testing.T) {
		mcpResult := map[string]interface{}{
			"isError": false,
			"content": []interface{}{
				map[string]interface{}{
					"type": "text",
					"text": "plain text, not JSON",
				},
			},
		}

		result := WrapMCPResult(ctxWithMgr, mcpResult, "test_tool")

		// Should return as-is since text is not JSON
		assert.Equal(t, mcpResult, result)
	})

	t.Run("handles empty content array", func(t *testing.T) {
		mcpResult := map[string]interface{}{
			"isError": false,
			"content": []interface{}{},
		}

		result := WrapMCPResult(ctxWithMgr, mcpResult, "test_tool")

		assert.Equal(t, mcpResult, result)
	})

	t.Run("processes without GCS manager in context", func(t *testing.T) {
		jsonData := map[string]interface{}{
			"test": "data",
		}
		jsonText, _ := json.Marshal(jsonData)

		mcpResult := map[string]interface{}{
			"isError": false,
			"content": []interface{}{
				map[string]interface{}{
					"type": "text",
					"text": string(jsonText),
				},
			},
		}

		// Use context WITHOUT GCS manager
		result := WrapMCPResult(ctx, mcpResult, "test_tool")

		// Should still process and return formatted result
		resultMap, ok := result.(map[string]interface{})
		assert.True(t, ok)
		assert.Contains(t, resultMap, "content")
	})
}

// Benchmark token estimation
func BenchmarkEstimateTokenCount(b *testing.B) {
	data := map[string]interface{}{
		"sensor_id":    "abc-123-def-456",
		"hostname":     "server1.example.com",
		"ip_address":   "192.168.1.100",
		"status":       "online",
		"tags":         []string{"production", "web-server", "us-east-1"},
		"last_seen":    "2025-11-11T12:00:00Z",
		"agent_version": "1.2.3",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EstimateTokenCount(data)
	}
}

// Benchmark temp file creation
func BenchmarkUploadToTempFile(b *testing.B) {
	ctx := context.Background()
	cfg := &Config{Enabled: false}
	mgr, _ := NewManager(ctx, cfg)

	data := map[string]interface{}{
		"key": "value",
		"number": 123,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, _ := mgr.uploadToTempFile(data, "bench_tool")
		if result != nil {
			os.Remove(result.URL)
		}
	}
}
