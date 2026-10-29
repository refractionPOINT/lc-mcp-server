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
		// bidi / format / control characters in the host
		"https://app.example.com\u202e/callback",
		"https://app.example.com\u202d/callback",
		"https://app\u2066.example.com/callback",
		"https://app\u200b.example.com/callback",
		"https://app\u00ad.example.com/callback",
		"https://app.example.com\u2028/callback",
		"https://app\u00a0.example.com/callback",
		"https://app.example.com%e2%80%ae/callback",
		"https://app.example.com\x00/callback",
		// not in canonical IDNA form (fullwidth letters would be mapped), or invalid IDNA
		"https://\uff41pple.com/callback",
		"https://b\u00fccher.example.com\u3002com/cb",
		"https://xn--.\u0430.com/cb",
	} {
		assert.Error(t, ValidateRedirectURI(bad), bad)
	}
	// Internationalised hosts that convert cleanly are accepted; they are
	// displayed as punycode (see TestDisplayHost).
	for _, ok := range []string{
		"https://b\u00fccher.example.com/cb",
		"https://xn--pple-43d.com/cb",
		"https://\u0430pple.com/callback",
		"https://%d0%b0pple.com/callback",
	} {
		assert.NoError(t, ValidateRedirectURI(ok), ok)
	}
}

func TestDisplayHost(t *testing.T) {
	good := map[string]string{
		"app.example.com":         "app.example.com",
		"APP.Example.com":         "APP.Example.com",
		"localhost":               "localhost",
		"127.0.0.1":               "127.0.0.1",
		"::1":                     "::1",
		"under_score.example.com": "under_score.example.com",
		"\u0430pple.com":          "xn--pple-43d.com",
		"b\u00fccher.example.com": "xn--bcher-kva.example.com",
		"B\u00dcCHER.example.com": "xn--bcher-kva.example.com",
		"\u4f8b\u3048.jp":         "xn--r8jz45g.jp",
	}
	for in, want := range good {
		got, err := DisplayHost(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
		for _, r := range got {
			assert.Less(t, r, rune(0x80), "display form must be ASCII: %q", got)
		}
	}
	for _, bad := range []string{
		"app.example.com\u202e", "\u202eapp.example.com", "a\u2066b.com", "a\u200db.com", "a\u200cb.com",
		"a\ufeffb.com", "a\u2028b.com", "a\u2029b.com", "a b.com", "a\tb.com", "a\x00b.com", "a\x7fb.com",
		"a\u0085b.com", "a\u00a0b.com", "a\u3000b.com", "\uff41pple.com", "a\xffb.com",
		"\u0430.\u0430\u202e.com", "xn--a.\u0430.com",
	} {
		_, err := DisplayHost(bad)
		assert.Error(t, err, "%q", bad)
	}
}

func TestIsLoopbackRedirect(t *testing.T) {
	assert.True(t, IsLoopbackRedirect("http://localhost:3000/cb"))
	assert.True(t, IsLoopbackRedirect("http://127.0.0.1/cb"))
	assert.True(t, IsLoopbackRedirect("http://[::1]:1/cb"))
	assert.False(t, IsLoopbackRedirect("https://app.example.com/cb"))
	assert.False(t, IsLoopbackRedirect("https://localhost.example.com/cb"))
}
