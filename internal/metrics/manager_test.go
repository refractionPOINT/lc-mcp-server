package metrics

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// createTestManager creates a manager with isEnabled=true for testing
// This simulates enabled mode without actually connecting to GCP
func createTestManager(t *testing.T) *Manager {
	t.Helper()
	return &Manager{
		config: &Config{
			Enabled:        true,
			ReportInterval: time.Second,
		},
		logger:        testLogger(),
		isEnabled:     true, // Enable tracking without GCP client
		uniqueUsers:   make(map[string]struct{}),
		oauthUsers:    make(map[string]struct{}),
		nonOAuthUsers: make(map[string]struct{}),
		startTime:     time.Now(),
		stopCh:        make(chan struct{}),
		// client is nil - we won't report to GCP in tests
	}
}

func TestLoadConfig(t *testing.T) {
	// Test default config (no env vars set)
	config := LoadConfig()
	assert.False(t, config.Enabled, "metrics should be disabled by default")
	assert.Equal(t, 60*time.Second, config.ReportInterval, "default report interval should be 60s")
}

func TestNewManager_Disabled(t *testing.T) {
	config := &Config{
		Enabled: false,
	}

	// Create a no-op manager when disabled
	mgr, err := NewManager(context.Background(), config, testLogger())
	require.NoError(t, err)
	require.NotNil(t, mgr)
	assert.Nil(t, mgr.client, "client should be nil when disabled")

	// Should not panic when recording operations (no-op)
	authCtx := &auth.AuthContext{
		Mode:   auth.AuthModeUIDOAuth,
		UID:    "test-user",
		APIKey: "test-key",
	}
	mgr.RecordOperation(authCtx)

	// Nothing should be tracked when disabled
	assert.Equal(t, int64(0), mgr.operationCount)
	assert.Empty(t, mgr.uniqueUsers)

	// Close should be no-op
	err = mgr.Close()
	assert.NoError(t, err)
}

func TestManager_RecordOperation_NoOp(t *testing.T) {
	// When isEnabled is false, RecordOperation should be a no-op
	mgr := &Manager{
		isEnabled:     false,
		uniqueUsers:   make(map[string]struct{}),
		oauthUsers:    make(map[string]struct{}),
		nonOAuthUsers: make(map[string]struct{}),
	}

	authCtx := &auth.AuthContext{
		Mode: auth.AuthModeUIDOAuth,
		UID:  "test-user",
	}
	mgr.RecordOperation(authCtx)

	assert.Equal(t, int64(0), mgr.operationCount)
	assert.Empty(t, mgr.uniqueUsers)
}

func TestManager_RecordOperation_NilAuthContext(t *testing.T) {
	mgr := createTestManager(t)

	// Should not panic with nil auth context
	mgr.RecordOperation(nil)
	assert.Equal(t, int64(0), mgr.operationCount)
}

func TestManager_RecordOperation_OAuth(t *testing.T) {
	mgr := createTestManager(t)

	authCtx := &auth.AuthContext{
		Mode: auth.AuthModeUIDOAuth,
		UID:  "oauth-user-1",
	}
	mgr.RecordOperation(authCtx)

	assert.Equal(t, int64(1), mgr.operationCount)
	assert.Len(t, mgr.uniqueUsers, 1)
	assert.Len(t, mgr.oauthUsers, 1)
	assert.Empty(t, mgr.nonOAuthUsers)
	assert.Contains(t, mgr.oauthUsers, "oauth-user-1")
}

func TestManager_RecordOperation_UIDKey(t *testing.T) {
	mgr := createTestManager(t)

	authCtx := &auth.AuthContext{
		Mode:   auth.AuthModeUIDKey,
		UID:    "key-user-1",
		APIKey: "test-key",
	}
	mgr.RecordOperation(authCtx)

	assert.Equal(t, int64(1), mgr.operationCount)
	assert.Len(t, mgr.uniqueUsers, 1)
	assert.Empty(t, mgr.oauthUsers)
	assert.Len(t, mgr.nonOAuthUsers, 1)
	assert.Contains(t, mgr.nonOAuthUsers, "uid:key-user-1")
}

func TestManager_RecordOperation_Normal(t *testing.T) {
	mgr := createTestManager(t)

	authCtx := &auth.AuthContext{
		Mode:   auth.AuthModeNormal,
		OID:    "test-org-1",
		APIKey: "test-key",
	}
	mgr.RecordOperation(authCtx)

	assert.Equal(t, int64(1), mgr.operationCount)
	assert.Len(t, mgr.uniqueUsers, 1)
	assert.Empty(t, mgr.oauthUsers)
	assert.Len(t, mgr.nonOAuthUsers, 1)
	assert.Contains(t, mgr.nonOAuthUsers, "oid:test-org-1")
}

func TestManager_DuplicateUsers(t *testing.T) {
	mgr := createTestManager(t)

	authCtx := &auth.AuthContext{
		Mode: auth.AuthModeUIDOAuth,
		UID:  "same-user",
	}

	// Record the same user multiple times
	mgr.RecordOperation(authCtx)
	mgr.RecordOperation(authCtx)
	mgr.RecordOperation(authCtx)

	// Operation count should be 3
	assert.Equal(t, int64(3), mgr.operationCount)
	// But unique users should be 1 (deduped)
	assert.Len(t, mgr.uniqueUsers, 1)
	assert.Len(t, mgr.oauthUsers, 1)
}

func TestManager_MultipleUsers(t *testing.T) {
	mgr := createTestManager(t)

	// Add different users
	mgr.RecordOperation(&auth.AuthContext{Mode: auth.AuthModeUIDOAuth, UID: "oauth-1"})
	mgr.RecordOperation(&auth.AuthContext{Mode: auth.AuthModeUIDOAuth, UID: "oauth-2"})
	mgr.RecordOperation(&auth.AuthContext{Mode: auth.AuthModeUIDKey, UID: "key-1", APIKey: "k"})
	mgr.RecordOperation(&auth.AuthContext{Mode: auth.AuthModeNormal, OID: "org-1", APIKey: "k"})

	assert.Equal(t, int64(4), mgr.operationCount)
	assert.Len(t, mgr.uniqueUsers, 4)
	assert.Len(t, mgr.oauthUsers, 2)
	assert.Len(t, mgr.nonOAuthUsers, 2)
}

func TestGetUserIdentifier(t *testing.T) {
	mgr := createTestManager(t)

	tests := []struct {
		name     string
		authCtx  *auth.AuthContext
		expected string
	}{
		{
			name: "uid takes precedence",
			authCtx: &auth.AuthContext{
				UID: "user123",
				OID: "org456",
			},
			expected: "uid:user123",
		},
		{
			name: "oid when no uid",
			authCtx: &auth.AuthContext{
				OID: "org456",
			},
			expected: "oid:org456",
		},
		{
			name:     "unknown when empty",
			authCtx:  &auth.AuthContext{},
			expected: "unknown",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := mgr.getUserIdentifier(tc.authCtx)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractProjectID(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"projects/my-project-123", "my-project-123"},
		{"projects/", ""},
		{"short", ""},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			result := extractProjectID(tc.path)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestDetectProjectID(t *testing.T) {
	// Clear any existing env vars
	originalGCP := os.Getenv("GOOGLE_CLOUD_PROJECT")
	originalGCloud := os.Getenv("GCLOUD_PROJECT")
	originalGCPProject := os.Getenv("GCP_PROJECT")
	defer func() {
		os.Setenv("GOOGLE_CLOUD_PROJECT", originalGCP)
		os.Setenv("GCLOUD_PROJECT", originalGCloud)
		os.Setenv("GCP_PROJECT", originalGCPProject)
	}()

	// Clear all
	os.Unsetenv("GOOGLE_CLOUD_PROJECT")
	os.Unsetenv("GCLOUD_PROJECT")
	os.Unsetenv("GCP_PROJECT")

	// Test empty - only when not running on GCE (metadata server provides project ID on GCE)
	if !metadata.OnGCE() {
		assert.Empty(t, detectProjectID())
	}

	// Test GOOGLE_CLOUD_PROJECT
	os.Setenv("GOOGLE_CLOUD_PROJECT", "test-project-1")
	assert.Equal(t, "test-project-1", detectProjectID())
	os.Unsetenv("GOOGLE_CLOUD_PROJECT")

	// Test GCLOUD_PROJECT
	os.Setenv("GCLOUD_PROJECT", "test-project-2")
	assert.Equal(t, "test-project-2", detectProjectID())
	os.Unsetenv("GCLOUD_PROJECT")

	// Test GCP_PROJECT
	os.Setenv("GCP_PROJECT", "test-project-3")
	assert.Equal(t, "test-project-3", detectProjectID())
}
