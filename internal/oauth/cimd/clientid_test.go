package cimd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateClientID(t *testing.T) {
	valid := []string{
		"https://app.example.com/oauth/client.json",
		"https://example.com/client",
		"https://example.com:443/client.json",
		"https://sub.domain.example.co.uk/a/b/c",
		"https://example.com/client.json%20x",
		"https://xn--bcher-kva.example/client.json",
	}
	for _, id := range valid {
		t.Run("valid/"+id, func(t *testing.T) {
			u, err := ValidateClientID(id)
			require.NoError(t, err)
			assert.Equal(t, "https", u.Scheme)
		})
	}

	invalid := map[string]string{
		"http scheme":         "http://example.com/client.json",
		"no scheme":           "example.com/client.json",
		"uppercase scheme":    "HTTPS://example.com/client.json",
		"ftp scheme":          "ftp://example.com/client.json",
		"no path":             "https://example.com",
		"root path":           "https://example.com/",
		"userinfo":            "https://user@example.com/client.json",
		"userinfo password":   "https://user:pw@example.com/client.json",
		"userinfo trick":      "https://example.com@evil.example/client.json",
		"fragment":            "https://example.com/client.json#frag",
		"empty fragment":      "https://example.com/client.json#",
		"query":               "https://example.com/client.json?x=1",
		"empty query":         "https://example.com/client.json?",
		"dot segment":         "https://example.com/a/./client.json",
		"dotdot segment":      "https://example.com/a/../client.json",
		"non-default port":    "https://example.com:8443/client.json",
		"ipv4 literal":        "https://127.0.0.1/client.json",
		"public ipv4 literal": "https://8.8.8.8/client.json",
		"ipv6 literal":        "https://[::1]/client.json",
		"decimal ipv4":        "https://2130706433/client.json",
		"hex ipv4":            "https://0x7f.0.0.1/client.json",
		"numeric tld":         "https://example.123/client.json",
		"single label":        "https://metadata/client.json",
		"localhost":           "https://localhost/client.json",
		"internal suffix":     "https://db.internal/client.json",
		"local suffix":        "https://printer.local/client.json",
		"trailing dot":        "https://example.com./client.json",
		"empty label":         "https://example..com/client.json",
		"underscore host":     "https://exa_mple.com/client.json",
		"unicode host":        "https://bücher.example/client.json",
		"backslash":           "https://example.com\\@evil.example/client.json",
		"space":               "https://example.com/client .json",
		"newline":             "https://example.com/client.json\n",
		"empty":               "",
		"too long":            "https://example.com/" + strings.Repeat("a", 2100),
	}
	for name, id := range invalid {
		t.Run("invalid/"+name, func(t *testing.T) {
			_, err := ValidateClientID(id)
			require.Error(t, err, id)
			var ce *Error
			require.ErrorAs(t, err, &ce)
			assert.Equal(t, KindInvalidClientID, ce.Kind)
		})
	}
}

func TestLooksLikeURL(t *testing.T) {
	assert.True(t, LooksLikeURL("https://example.com/x"))
	assert.True(t, LooksLikeURL("http://example.com"))
	assert.True(t, LooksLikeURL("https://"))
	assert.False(t, LooksLikeURL("mcp_AbCdEf123"))
	assert.False(t, LooksLikeURL("test-client"))
	assert.False(t, LooksLikeURL(""))
}

func TestValidateRedirectURI(t *testing.T) {
	for _, ok := range []string{
		"https://app.example.com/callback",
		"https://app.example.com:8443/cb?x=1",
		"http://localhost:3000/callback",
		"http://127.0.0.1:8080/cb",
		"http://localhost/callback",
	} {
		assert.NoError(t, ValidateRedirectURI(ok), ok)
	}
	for _, bad := range []string{
		"",
		"http://app.example.com/callback",
		"http://[::1]:3000/cb",
		"http://localhost.evil.example/cb",
		"ftp://example.com/cb",
		"javascript:alert(1)",
		"com.example.app:/callback",
		"/relative/path",
		"https:///nohost",
		"https://user@app.example.com/cb",
		"https://app.example.com/cb#frag",
		"https://" + strings.Repeat("a", 2100) + ".example.com/cb",
	} {
		assert.Error(t, ValidateRedirectURI(bad), bad)
	}
}

func TestIsLoopbackRedirect(t *testing.T) {
	assert.True(t, IsLoopbackRedirect("http://localhost:3000/cb"))
	assert.True(t, IsLoopbackRedirect("http://127.0.0.1/cb"))
	assert.True(t, IsLoopbackRedirect("http://[::1]:1/cb"))
	assert.False(t, IsLoopbackRedirect("https://app.example.com/cb"))
	assert.False(t, IsLoopbackRedirect("https://localhost.example.com/cb"))
}
