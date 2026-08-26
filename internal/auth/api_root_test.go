package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The override is the only reason a request from this process can leave production, so
// its precedence and its rejection rule are pinned rather than assumed.
func TestResolveAPIRoot(t *testing.T) {
	t.Run("unset is production", func(t *testing.T) {
		assert.Equal(t, defaultAPIRoot, resolveAPIRoot(""))
		assert.Equal(t, defaultAPIRoot, resolveAPIRoot("   "))
	})

	t.Run("an https host is honored and trailing-slash trimmed", func(t *testing.T) {
		// Trimmed because every caller joins it with "/v1/...", so a kept slash
		// produces "//v1/" — which some proxies normalize and some 404 on.
		assert.Equal(t, "https://lc-api-go-exp.example.run.app",
			resolveAPIRoot("https://lc-api-go-exp.example.run.app/"))
		assert.Equal(t, "http://localhost:8081", resolveAPIRoot("http://localhost:8081"))
	})

	t.Run("anything that is not an http(s) URL falls back to production", func(t *testing.T) {
		// Ignored rather than honored: a malformed override would turn every call
		// into an opaque transport failure, and production is both the safe
		// direction and the visible one.
		for _, bad := range []string{
			"lc-api-go-exp.example.run.app",
			"ftp://example.com",
			"file:///etc/passwd",
			"//example.com",
		} {
			assert.Equal(t, defaultAPIRoot, resolveAPIRoot(bad), bad)
		}
	})
}

// The SDK is handed "" for production so this server does not hardcode a URL the SDK
// is entitled to change, and the real value only when it differs.
func TestOverrideURLOnlySpeaksWhenItDiffers(t *testing.T) {
	assert.Equal(t, defaultAPIRoot, APIRoot(),
		"the test process must not carry LC_API_URL; APIRoot is resolved once per process")
	assert.False(t, IsAPIRootOverridden())
	assert.Equal(t, "", overrideURL())
}
