package admin

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/refractionpoint/lc-mcp-go/internal/tools/testutil"
)

// extractResultText extracts the text content from an MCP CallToolResult
func extractResultText(result *mcp.CallToolResult) (string, bool) {
	if len(result.Content) == 0 {
		return "", false
	}
	if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
		return textContent.Text, true
	}
	return "", false
}

// setupTestContext creates a context with auth for testing
func setupTestContext() context.Context {
	authCtx := &auth.AuthContext{
		Mode:   auth.AuthModeNormal,
		OID:    "test-org",
		APIKey: "test-key",
	}
	return auth.WithAuthContext(context.Background(), authCtx)
}

func TestGetOrgOIDByName_Found(t *testing.T) {
	// Clear the global cache before test
	GetGlobalOrgCache().InvalidateAll()

	ctx := setupTestContext()

	// Setup mock with orgs
	mock := &testutil.MockOrganization{
		ListUserOrgsFunc: func(offset, limit *int, filter, sortBy, sortOrder *string, withNames bool) ([]lc.UserOrgInfo, error) {
			return []lc.UserOrgInfo{
				{OID: "oid-1", Name: "TestOrg"},
				{OID: "oid-2", Name: "AnotherOrg"},
			}, nil
		},
	}

	// Inject mock into context
	ctx = tools.WithOrganizationClient(ctx, mock)

	// Get the handler
	reg, ok := tools.GetTool("get_org_oid_by_name")
	if !ok {
		t.Fatal("get_org_oid_by_name tool not registered")
	}

	// Call with name that exists
	result, err := reg.Handler(ctx, map[string]interface{}{
		"name": "TestOrg",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse the result
	text, ok := extractResultText(result)
	if !ok {
		t.Fatal("failed to extract result text")
	}
	var resultData map[string]interface{}
	if err := json.Unmarshal([]byte(text), &resultData); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}

	if resultData["found"] != true {
		t.Error("expected found=true")
	}
	if resultData["oid"] != "oid-1" {
		t.Errorf("expected oid=oid-1, got %v", resultData["oid"])
	}
	if resultData["name"] != "TestOrg" {
		t.Errorf("expected name=TestOrg, got %v", resultData["name"])
	}
}

func TestGetOrgOIDByName_NotFound(t *testing.T) {
	// Clear the global cache before test
	GetGlobalOrgCache().InvalidateAll()

	ctx := setupTestContext()

	// Setup mock with orgs (less than page size to indicate last page)
	mock := &testutil.MockOrganization{
		ListUserOrgsFunc: func(offset, limit *int, filter, sortBy, sortOrder *string, withNames bool) ([]lc.UserOrgInfo, error) {
			return []lc.UserOrgInfo{
				{OID: "oid-1", Name: "TestOrg"},
				{OID: "oid-2", Name: "AnotherOrg"},
			}, nil
		},
	}

	ctx = tools.WithOrganizationClient(ctx, mock)

	reg, ok := tools.GetTool("get_org_oid_by_name")
	if !ok {
		t.Fatal("get_org_oid_by_name tool not registered")
	}

	// Call with name that doesn't exist
	result, err := reg.Handler(ctx, map[string]interface{}{
		"name": "NonExistentOrg",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text, ok := extractResultText(result)
	if !ok {
		t.Fatal("failed to extract result text")
	}
	var resultData map[string]interface{}
	if err := json.Unmarshal([]byte(text), &resultData); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}

	if resultData["found"] != false {
		t.Error("expected found=false")
	}
	if resultData["error"] != "organization not found" {
		t.Errorf("expected error='organization not found', got %v", resultData["error"])
	}
}

func TestGetOrgOIDByName_CaseInsensitive(t *testing.T) {
	// Clear the global cache before test
	GetGlobalOrgCache().InvalidateAll()

	ctx := setupTestContext()

	mock := &testutil.MockOrganization{
		ListUserOrgsFunc: func(offset, limit *int, filter, sortBy, sortOrder *string, withNames bool) ([]lc.UserOrgInfo, error) {
			return []lc.UserOrgInfo{
				{OID: "oid-1", Name: "TestOrg"},
			}, nil
		},
	}

	ctx = tools.WithOrganizationClient(ctx, mock)

	reg, ok := tools.GetTool("get_org_oid_by_name")
	if !ok {
		t.Fatal("get_org_oid_by_name tool not registered")
	}

	// Call with lowercase name and exact_match=false
	result, err := reg.Handler(ctx, map[string]interface{}{
		"name":        "testorg",
		"exact_match": false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text, ok := extractResultText(result)
	if !ok {
		t.Fatal("failed to extract result text")
	}
	var resultData map[string]interface{}
	if err := json.Unmarshal([]byte(text), &resultData); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}

	if resultData["found"] != true {
		t.Error("expected found=true for case-insensitive match")
	}
	if resultData["oid"] != "oid-1" {
		t.Errorf("expected oid=oid-1, got %v", resultData["oid"])
	}
}

func TestGetOrgOIDByName_ExactMatchFails(t *testing.T) {
	// Clear the global cache before test
	GetGlobalOrgCache().InvalidateAll()

	ctx := setupTestContext()

	mock := &testutil.MockOrganization{
		ListUserOrgsFunc: func(offset, limit *int, filter, sortBy, sortOrder *string, withNames bool) ([]lc.UserOrgInfo, error) {
			return []lc.UserOrgInfo{
				{OID: "oid-1", Name: "TestOrg"},
			}, nil
		},
	}

	ctx = tools.WithOrganizationClient(ctx, mock)

	reg, ok := tools.GetTool("get_org_oid_by_name")
	if !ok {
		t.Fatal("get_org_oid_by_name tool not registered")
	}

	// Call with lowercase name and exact_match=true (default) - should NOT find
	result, err := reg.Handler(ctx, map[string]interface{}{
		"name":        "testorg",
		"exact_match": true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text, ok := extractResultText(result)
	if !ok {
		t.Fatal("failed to extract result text")
	}
	var resultData map[string]interface{}
	if err := json.Unmarshal([]byte(text), &resultData); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}

	if resultData["found"] != false {
		t.Error("expected found=false for exact match with wrong case")
	}
}

func TestGetOrgOIDByName_CacheHit(t *testing.T) {
	// Clear the global cache before test
	GetGlobalOrgCache().InvalidateAll()

	ctx := setupTestContext()

	// Track API calls
	var apiCallCount int32

	mock := &testutil.MockOrganization{
		ListUserOrgsFunc: func(offset, limit *int, filter, sortBy, sortOrder *string, withNames bool) ([]lc.UserOrgInfo, error) {
			atomic.AddInt32(&apiCallCount, 1)
			return []lc.UserOrgInfo{
				{OID: "oid-1", Name: "TestOrg"},
				{OID: "oid-2", Name: "AnotherOrg"},
			}, nil
		},
	}

	ctx = tools.WithOrganizationClient(ctx, mock)

	reg, ok := tools.GetTool("get_org_oid_by_name")
	if !ok {
		t.Fatal("get_org_oid_by_name tool not registered")
	}

	// First call - should hit API
	_, err := reg.Handler(ctx, map[string]interface{}{
		"name": "TestOrg",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	firstCallCount := atomic.LoadInt32(&apiCallCount)
	if firstCallCount != 1 {
		t.Errorf("expected 1 API call on first request, got %d", firstCallCount)
	}

	// Second call - should use cache, no additional API call
	result, err := reg.Handler(ctx, map[string]interface{}{
		"name": "AnotherOrg",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	secondCallCount := atomic.LoadInt32(&apiCallCount)
	if secondCallCount != 1 {
		t.Errorf("expected no additional API calls on cache hit, got %d total", secondCallCount)
	}

	// Verify we got the right result from cache
	text, ok := extractResultText(result)
	if !ok {
		t.Fatal("failed to extract result text")
	}
	var resultData map[string]interface{}
	if err := json.Unmarshal([]byte(text), &resultData); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}

	if resultData["found"] != true {
		t.Error("expected found=true from cache")
	}
	if resultData["oid"] != "oid-2" {
		t.Errorf("expected oid=oid-2, got %v", resultData["oid"])
	}
}

func TestGetOrgOIDByName_MissingName(t *testing.T) {
	ctx := setupTestContext()

	reg, ok := tools.GetTool("get_org_oid_by_name")
	if !ok {
		t.Fatal("get_org_oid_by_name tool not registered")
	}

	// Call without name parameter
	result, err := reg.Handler(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be an error result
	if !result.IsError {
		t.Error("expected error result when name is missing")
	}
}

func TestGetOrgOIDByName_Pagination(t *testing.T) {
	// Clear the global cache before test
	GetGlobalOrgCache().InvalidateAll()

	ctx := setupTestContext()

	var callCount int32

	// Mock that returns orgs in multiple pages
	mock := &testutil.MockOrganization{
		ListUserOrgsFunc: func(offset, limit *int, filter, sortBy, sortOrder *string, withNames bool) ([]lc.UserOrgInfo, error) {
			count := atomic.AddInt32(&callCount, 1)

			// Return 100 orgs for first page (full page), less for second (last page)
			if *offset == 0 {
				// First page - return exactly page size to indicate more pages
				orgs := make([]lc.UserOrgInfo, 100)
				for i := 0; i < 100; i++ {
					orgs[i] = lc.UserOrgInfo{
						OID:  "oid-page1-" + string(rune('A'+i)),
						Name: "Org" + string(rune('A'+i)),
					}
				}
				return orgs, nil
			}

			// Second page - return the target org + a few more (less than page size)
			_ = count // silence unused warning
			return []lc.UserOrgInfo{
				{OID: "oid-target", Name: "TargetOrg"},
				{OID: "oid-final", Name: "FinalOrg"},
			}, nil
		},
	}

	ctx = tools.WithOrganizationClient(ctx, mock)

	reg, ok := tools.GetTool("get_org_oid_by_name")
	if !ok {
		t.Fatal("get_org_oid_by_name tool not registered")
	}

	// Search for org that's on the second page
	result, err := reg.Handler(ctx, map[string]interface{}{
		"name": "TargetOrg",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text, ok := extractResultText(result)
	if !ok {
		t.Fatal("failed to extract result text")
	}
	var resultData map[string]interface{}
	if err := json.Unmarshal([]byte(text), &resultData); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}

	if resultData["found"] != true {
		t.Error("expected found=true")
	}
	if resultData["oid"] != "oid-target" {
		t.Errorf("expected oid=oid-target, got %v", resultData["oid"])
	}

	// Should have made 2 API calls
	finalCount := atomic.LoadInt32(&callCount)
	if finalCount != 2 {
		t.Errorf("expected 2 API calls for paginated search, got %d", finalCount)
	}
}

func TestGetOrgOIDByName_CacheTTL(t *testing.T) {
	// Create a cache with very short TTL for testing
	shortTTLCache := NewOrgCache(50 * time.Millisecond)

	// Store the original cache and restore it after test
	origCache := globalOrgCache
	globalOrgCache = shortTTLCache
	defer func() { globalOrgCache = origCache }()

	ctx := setupTestContext()

	var callCount int32

	mock := &testutil.MockOrganization{
		ListUserOrgsFunc: func(offset, limit *int, filter, sortBy, sortOrder *string, withNames bool) ([]lc.UserOrgInfo, error) {
			atomic.AddInt32(&callCount, 1)
			return []lc.UserOrgInfo{
				{OID: "oid-1", Name: "TestOrg"},
			}, nil
		},
	}

	ctx = tools.WithOrganizationClient(ctx, mock)

	reg, ok := tools.GetTool("get_org_oid_by_name")
	if !ok {
		t.Fatal("get_org_oid_by_name tool not registered")
	}

	// First call
	_, err := reg.Handler(ctx, map[string]interface{}{
		"name": "TestOrg",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	firstCount := atomic.LoadInt32(&callCount)
	if firstCount != 1 {
		t.Errorf("expected 1 API call, got %d", firstCount)
	}

	// Wait for cache to expire
	time.Sleep(60 * time.Millisecond)

	// Second call after TTL - should make another API call
	_, err = reg.Handler(ctx, map[string]interface{}{
		"name": "TestOrg",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	secondCount := atomic.LoadInt32(&callCount)
	if secondCount != 2 {
		t.Errorf("expected 2 API calls after TTL expiry, got %d", secondCount)
	}
}
