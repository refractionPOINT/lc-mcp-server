package admin

import (
	"sync"
	"testing"
	"time"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

func TestOrgCache_LookupByName_ExactMatch(t *testing.T) {
	cache := NewOrgCache(5 * time.Minute)

	orgs := []lc.UserOrgInfo{
		{OID: "oid-1", Name: "TestOrg"},
		{OID: "oid-2", Name: "AnotherOrg"},
	}

	cache.AddOrgs("cred-key-1", orgs, true)

	// Test exact match - should find
	oid, info, found := cache.LookupByName("cred-key-1", "TestOrg", true)
	if !found {
		t.Fatal("expected to find TestOrg")
	}
	if oid != "oid-1" {
		t.Errorf("expected oid-1, got %s", oid)
	}
	if info == nil {
		t.Fatal("expected info to not be nil")
	}
	if info.Name != "TestOrg" {
		t.Errorf("expected info.Name=TestOrg, got %s", info.Name)
	}

	// Test exact match with wrong case - should not find
	_, _, found = cache.LookupByName("cred-key-1", "testorg", true)
	if found {
		t.Error("exact match should not find 'testorg' when org is 'TestOrg'")
	}

	// Test with different credential key - should not find
	_, _, found = cache.LookupByName("cred-key-2", "TestOrg", true)
	if found {
		t.Error("should not find org with different credential key")
	}
}

func TestOrgCache_LookupByName_CaseInsensitive(t *testing.T) {
	cache := NewOrgCache(5 * time.Minute)

	orgs := []lc.UserOrgInfo{
		{OID: "oid-1", Name: "TestOrg"},
		{OID: "oid-2", Name: "UPPERCASE"},
	}

	cache.AddOrgs("cred-key-1", orgs, true)

	testCases := []struct {
		name        string
		searchName  string
		expectOID   string
		expectFound bool
	}{
		{"exact case", "TestOrg", "oid-1", true},
		{"lowercase", "testorg", "oid-1", true},
		{"uppercase", "TESTORG", "oid-1", true},
		{"mixed case", "TeStOrG", "oid-1", true},
		{"uppercase org lowercase search", "uppercase", "oid-2", true},
		{"non-existent", "nonexistent", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			oid, _, found := cache.LookupByName("cred-key-1", tc.searchName, false)
			if found != tc.expectFound {
				t.Errorf("expected found=%v, got %v", tc.expectFound, found)
			}
			if found && oid != tc.expectOID {
				t.Errorf("expected oid=%s, got %s", tc.expectOID, oid)
			}
		})
	}
}

func TestOrgCache_TTLExpiration(t *testing.T) {
	// Use a very short TTL for testing
	cache := NewOrgCache(50 * time.Millisecond)

	orgs := []lc.UserOrgInfo{
		{OID: "oid-1", Name: "TestOrg"},
	}

	cache.AddOrgs("cred-key-1", orgs, true)

	// Should find immediately
	_, _, found := cache.LookupByName("cred-key-1", "TestOrg", true)
	if !found {
		t.Fatal("expected to find TestOrg immediately after adding")
	}

	// Should be complete
	if !cache.IsComplete("cred-key-1") {
		t.Error("expected cache to be complete")
	}

	// Wait for TTL to expire
	time.Sleep(60 * time.Millisecond)

	// Should not find after expiration
	_, _, found = cache.LookupByName("cred-key-1", "TestOrg", true)
	if found {
		t.Error("should not find TestOrg after TTL expiration")
	}

	// Should not be complete after expiration
	if cache.IsComplete("cred-key-1") {
		t.Error("cache should not be complete after TTL expiration")
	}
}

func TestOrgCache_AddOrgs(t *testing.T) {
	cache := NewOrgCache(5 * time.Minute)

	// Add first batch (incomplete)
	orgs1 := []lc.UserOrgInfo{
		{OID: "oid-1", Name: "Org1"},
	}
	cache.AddOrgs("cred-key-1", orgs1, false)

	// Should not be complete
	if cache.IsComplete("cred-key-1") {
		t.Error("cache should not be complete after incomplete add")
	}

	// Should find the org
	oid, _, found := cache.LookupByName("cred-key-1", "Org1", true)
	if !found {
		t.Fatal("expected to find Org1")
	}
	if oid != "oid-1" {
		t.Errorf("expected oid-1, got %s", oid)
	}

	// Add second batch (complete)
	orgs2 := []lc.UserOrgInfo{
		{OID: "oid-2", Name: "Org2"},
	}
	cache.AddOrgs("cred-key-1", orgs2, true)

	// Should now be complete
	if !cache.IsComplete("cred-key-1") {
		t.Error("cache should be complete after complete add")
	}

	// Should find both orgs
	_, _, found = cache.LookupByName("cred-key-1", "Org1", true)
	if !found {
		t.Error("expected to still find Org1")
	}
	_, _, found = cache.LookupByName("cred-key-1", "Org2", true)
	if !found {
		t.Error("expected to find Org2")
	}
}

func TestOrgCache_ConcurrentAccess(t *testing.T) {
	cache := NewOrgCache(5 * time.Minute)

	// Pre-populate with some data
	orgs := []lc.UserOrgInfo{
		{OID: "oid-1", Name: "Org1"},
		{OID: "oid-2", Name: "Org2"},
	}
	cache.AddOrgs("cred-key-1", orgs, true)

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	// Concurrent reads
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _, found := cache.LookupByName("cred-key-1", "Org1", true)
				if !found {
					errors <- nil // Just count as successful access
				}
				cache.IsComplete("cred-key-1")
			}
		}()
	}

	// Concurrent writes
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				newOrgs := []lc.UserOrgInfo{
					{OID: "oid-new", Name: "NewOrg"},
				}
				cache.AddOrgs("cred-key-1", newOrgs, true)
			}
		}(i)
	}

	// Wait for all goroutines
	wg.Wait()
	close(errors)

	// If we get here without deadlock or panic, the test passes
}

func TestOrgCache_Invalidate(t *testing.T) {
	cache := NewOrgCache(5 * time.Minute)

	orgs := []lc.UserOrgInfo{
		{OID: "oid-1", Name: "Org1"},
	}
	cache.AddOrgs("cred-key-1", orgs, true)
	cache.AddOrgs("cred-key-2", orgs, true)

	// Both should exist
	_, _, found := cache.LookupByName("cred-key-1", "Org1", true)
	if !found {
		t.Fatal("expected to find Org1 for cred-key-1")
	}
	_, _, found = cache.LookupByName("cred-key-2", "Org1", true)
	if !found {
		t.Fatal("expected to find Org1 for cred-key-2")
	}

	// Invalidate only one
	cache.Invalidate("cred-key-1")

	// Should not find for invalidated key
	_, _, found = cache.LookupByName("cred-key-1", "Org1", true)
	if found {
		t.Error("should not find Org1 for invalidated cred-key-1")
	}

	// Should still find for other key
	_, _, found = cache.LookupByName("cred-key-2", "Org1", true)
	if !found {
		t.Error("should still find Org1 for cred-key-2")
	}
}

func TestOrgCache_InvalidateAll(t *testing.T) {
	cache := NewOrgCache(5 * time.Minute)

	orgs := []lc.UserOrgInfo{
		{OID: "oid-1", Name: "Org1"},
	}
	cache.AddOrgs("cred-key-1", orgs, true)
	cache.AddOrgs("cred-key-2", orgs, true)

	// Invalidate all
	cache.InvalidateAll()

	// Neither should be found
	_, _, found := cache.LookupByName("cred-key-1", "Org1", true)
	if found {
		t.Error("should not find Org1 for cred-key-1 after InvalidateAll")
	}
	_, _, found = cache.LookupByName("cred-key-2", "Org1", true)
	if found {
		t.Error("should not find Org1 for cred-key-2 after InvalidateAll")
	}
}

func TestOrgCache_Stats(t *testing.T) {
	cache := NewOrgCache(5 * time.Minute)

	stats := cache.Stats()
	if stats["entries"].(int) != 0 {
		t.Errorf("expected 0 entries, got %v", stats["entries"])
	}

	orgs := []lc.UserOrgInfo{{OID: "oid-1", Name: "Org1"}}
	cache.AddOrgs("cred-key-1", orgs, true)
	cache.AddOrgs("cred-key-2", orgs, true)

	stats = cache.Stats()
	if stats["entries"].(int) != 2 {
		t.Errorf("expected 2 entries, got %v", stats["entries"])
	}
}
