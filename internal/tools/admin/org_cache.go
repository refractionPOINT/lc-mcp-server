package admin

import (
	"strings"
	"sync"
	"time"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

// OrgCacheEntry holds cached org mappings for a credential
type OrgCacheEntry struct {
	NameToOID      map[string]string         // name -> OID (case-sensitive)
	NameLowerToOID map[string]string         // lowercase name -> OID (case-insensitive)
	OrgInfo        map[string]lc.UserOrgInfo // OID -> full info
	CreatedAt      time.Time
	Complete       bool // true if all orgs have been loaded
}

// OrgCache caches org name->OID mappings per credential
// This is thread-safe and credential-isolated
type OrgCache struct {
	mu    sync.RWMutex
	cache map[string]*OrgCacheEntry // keyed by auth.CacheKey()
	ttl   time.Duration
}

// DefaultOrgCacheTTL is the default time-to-live for cached org data
const DefaultOrgCacheTTL = 5 * time.Minute

var (
	globalOrgCache = NewOrgCache(DefaultOrgCacheTTL)
)

// NewOrgCache creates a new OrgCache with the specified TTL
func NewOrgCache(ttl time.Duration) *OrgCache {
	return &OrgCache{
		cache: make(map[string]*OrgCacheEntry),
		ttl:   ttl,
	}
}

// GetGlobalOrgCache returns the global org cache instance
func GetGlobalOrgCache() *OrgCache {
	return globalOrgCache
}

// LookupByName looks up an org by name and returns (oid, orgInfo, found)
// If exactMatch is true, matches case-sensitively; otherwise case-insensitive
func (c *OrgCache) LookupByName(cacheKey, name string, exactMatch bool) (string, *lc.UserOrgInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.cache[cacheKey]
	if !exists {
		return "", nil, false
	}

	// Check if cache has expired
	if time.Since(entry.CreatedAt) > c.ttl {
		return "", nil, false
	}

	var oid string
	var found bool

	if exactMatch {
		oid, found = entry.NameToOID[name]
	} else {
		oid, found = entry.NameLowerToOID[strings.ToLower(name)]
	}

	if !found {
		return "", nil, false
	}

	// Get full org info
	orgInfo, exists := entry.OrgInfo[oid]
	if !exists {
		return oid, nil, true
	}

	return oid, &orgInfo, true
}

// IsComplete returns true if the cache has complete org data for the given credential
func (c *OrgCache) IsComplete(cacheKey string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.cache[cacheKey]
	if !exists {
		return false
	}

	// Check if cache has expired
	if time.Since(entry.CreatedAt) > c.ttl {
		return false
	}

	return entry.Complete
}

// AddOrgs adds orgs to the cache
// If complete is true, marks the cache as having all orgs loaded
func (c *OrgCache) AddOrgs(cacheKey string, orgs []lc.UserOrgInfo, complete bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.cache[cacheKey]

	// If entry doesn't exist or has expired, create new entry
	if !exists || time.Since(entry.CreatedAt) > c.ttl {
		entry = &OrgCacheEntry{
			NameToOID:      make(map[string]string),
			NameLowerToOID: make(map[string]string),
			OrgInfo:        make(map[string]lc.UserOrgInfo),
			CreatedAt:      time.Now(),
			Complete:       false,
		}
		c.cache[cacheKey] = entry
	}

	// Add orgs to the entry
	for _, org := range orgs {
		entry.NameToOID[org.Name] = org.OID
		entry.NameLowerToOID[strings.ToLower(org.Name)] = org.OID
		entry.OrgInfo[org.OID] = org
	}

	if complete {
		entry.Complete = true
	}
}

// Invalidate removes the cache entry for a specific credential
func (c *OrgCache) Invalidate(cacheKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.cache, cacheKey)
}

// InvalidateAll clears all cache entries
func (c *OrgCache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]*OrgCacheEntry)
}

// Stats returns cache statistics
func (c *OrgCache) Stats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"entries": len(c.cache),
		"ttl":     c.ttl.String(),
	}
}
