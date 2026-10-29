package resource

import (
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testPolicy(serverURL string) *Policy {
	return NewPolicy(serverURL).WithProfiles(func(name string) bool {
		return name == "all" || name == "api_access" || name == "social"
	})
}

func TestCanonicalize(t *testing.T) {
	p := testPolicy("https://mcp.example.com")

	valid := map[string]string{
		// bare origin
		"https://mcp.example.com":  "https://mcp.example.com",
		"https://mcp.example.com/": "https://mcp.example.com",
		// MCP endpoint, trailing slash, versioned alias
		"https://mcp.example.com/mcp":     "https://mcp.example.com/mcp",
		"https://mcp.example.com/mcp/":    "https://mcp.example.com/mcp",
		"https://mcp.example.com/mcp/v1":  "https://mcp.example.com/mcp",
		"https://mcp.example.com/mcp/v1/": "https://mcp.example.com/mcp",
		// profiles
		"https://mcp.example.com/mcp/api_access":    "https://mcp.example.com/mcp/api_access",
		"https://mcp.example.com/mcp/v1/api_access": "https://mcp.example.com/mcp/api_access",
		"https://mcp.example.com/mcp/all":           "https://mcp.example.com/mcp/all",
		"https://mcp.example.com/mcp/v1/all/":       "https://mcp.example.com/mcp/all",
		// scheme and host are case-insensitive, the path is not
		"HTTPS://MCP.Example.COM/mcp": "https://mcp.example.com/mcp",
		// default port is elided
		"https://mcp.example.com:443/mcp": "https://mcp.example.com/mcp",
	}
	for in, want := range valid {
		t.Run("valid "+in, func(t *testing.T) {
			got, err := p.Canonicalize(in)
			require.NoError(t, err)
			assert.Equal(t, want, got)
			// canonical form is a fixed point
			again, err := p.Canonicalize(got)
			require.NoError(t, err)
			assert.Equal(t, got, again)
		})
	}

	invalid := []string{
		"",
		"mcp.example.com",               // not absolute
		"/mcp",                          // not absolute
		"ftp://mcp.example.com/mcp",     // scheme
		"http://mcp.example.com/mcp",    // other scheme: a different origin
		"https://other.example.com/mcp", // foreign origin
		"https://mcp.example.com.evil.com/mcp",
		"https://evil.com/https://mcp.example.com/mcp",
		"https://user@mcp.example.com/mcp", // userinfo
		"https://mcp.example.com:8443/mcp", // port is part of the origin
		"https://mcp.example.com:80/mcp",
		"https://mcp.example.com/mcp#frag", // fragment (RFC 8707)
		"https://mcp.example.com/mcp#",
		"https://mcp.example.com#frag",
		"https://mcp.example.com/mcp?x=1", // query
		"https://mcp.example.com/mcp?",
		"https://mcp.example.com/?x=1",
		"https://mcp.example.com/mcp/unknown_profile",
		"https://mcp.example.com/mcp/api_access/extra",
		"https://mcp.example.com/mcp/v1/unknown_profile",
		"https://mcp.example.com/mcp/v1/v1",
		"https://mcp.example.com/mcp/v2",
		"https://mcp.example.com/other",
		"https://mcp.example.com/mcpx",
		"https://mcp.example.com/MCP", // path is case-sensitive
		"https://mcp.example.com/mcp/API_ACCESS",
		// path tricks
		"https://mcp.example.com/mcp/../mcp",
		"https://mcp.example.com/mcp/./api_access",
		"https://mcp.example.com/foo/../mcp",
		"https://mcp.example.com//mcp",
		"https://mcp.example.com/mcp//api_access",
		"https://mcp.example.com/mcp/api_access//",
		`https://mcp.example.com/mcp\api_access`,
		// percent-encoding tricks
		"https://mcp.example.com/mcp%2Fapi_access",
		"https://mcp.example.com/mcp%2fapi_access",
		"https://mcp.example.com/%6dcp",
		"https://mcp.example.com/mcp/api%5Faccess",
		"https://mcp.example.com/mcp%00",
		"https://mcp.example.com/mcp%2e%2e/mcp",
		"https://mcp.example.com/mcp/%2e%2e/mcp",
		"https://mcp.example.com/mcp ",
	}
	for _, in := range invalid {
		t.Run("invalid "+in, func(t *testing.T) {
			got, err := p.Canonicalize(in)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidResource)
			assert.Empty(t, got)
		})
	}
}

func TestCanonicalizeNonDefaultPort(t *testing.T) {
	p := testPolicy("http://localhost:8080")

	got, err := p.Canonicalize("http://LOCALHOST:8080/mcp/v1/api_access")
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8080/mcp/api_access", got)

	for _, in := range []string{"http://localhost/mcp", "http://localhost:8081/mcp", "https://localhost:8080/mcp", "http://127.0.0.1:8080/mcp"} {
		_, err := p.Canonicalize(in)
		assert.Error(t, err, in)
	}
}

func TestCanonicalizeServerURLNormalization(t *testing.T) {
	// The configured URL is normalized the same way as a resource.
	p := testPolicy("HTTPS://MCP.Example.com:443/")
	got, err := p.Canonicalize("https://mcp.example.com/mcp")
	require.NoError(t, err)
	assert.Equal(t, "https://mcp.example.com/mcp", got)
	assert.Equal(t, "https://mcp.example.com", p.Origin())
}

func TestCanonicalizeBasePath(t *testing.T) {
	p := testPolicy("https://example.com/lc")

	got, err := p.Canonicalize("https://example.com/lc/mcp/v1/social")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/lc/mcp/social", got)

	got, err = p.Canonicalize("https://example.com/lc/")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/lc", got)
	assert.Equal(t, got, p.Origin())

	for _, in := range []string{"https://example.com/mcp", "https://example.com", "https://example.com/lcx/mcp", "https://example.com/other/mcp"} {
		_, err := p.Canonicalize(in)
		assert.Error(t, err, in)
	}

	// Request paths are routed without the base path.
	r, ok := p.ForRequestPath("/mcp/v1/social")
	require.True(t, ok)
	assert.Equal(t, "https://example.com/lc/mcp/social", r)
	assert.True(t, p.Covers("https://example.com/lc/mcp", r))
	assert.True(t, p.Covers("https://example.com/lc", r))
}

func TestPolicyWithoutUsableServerURLRejectsEverything(t *testing.T) {
	for _, serverURL := range []string{"", "not a url", "ftp://x", "://"} {
		p := testPolicy(serverURL)
		_, err := p.Canonicalize("https://mcp.example.com/mcp")
		assert.ErrorIs(t, err, ErrInvalidResource, serverURL)
		_, ok := p.ForRequestPath("/mcp")
		assert.False(t, ok, serverURL)
	}
}

func TestForRequestPath(t *testing.T) {
	p := testPolicy("https://mcp.example.com")

	ok := map[string]string{
		"/":                  "https://mcp.example.com/mcp", // the root serves /mcp
		"/mcp":               "https://mcp.example.com/mcp",
		"/mcp/v1":            "https://mcp.example.com/mcp",
		"/mcp/api_access":    "https://mcp.example.com/mcp/api_access",
		"/mcp/v1/api_access": "https://mcp.example.com/mcp/api_access",
		"/mcp/all":           "https://mcp.example.com/mcp/all",
		"/mcp/v1/all":        "https://mcp.example.com/mcp/all",
		"/mcp/social":        "https://mcp.example.com/mcp/social",
	}
	for path, want := range ok {
		got, found := p.ForRequestPath(path)
		assert.True(t, found, path)
		assert.Equal(t, want, got, path)
	}

	for _, path := range []string{
		"", "/foo", "/mcpx", "/mcp/unknown", "/mcp/v1/unknown", "/mcp/api_access/x",
		"/mcp/../mcp", "//mcp", "/mcp//api_access", "/mcp%2Fapi_access", "/mcp/api%5Faccess", `/mcp\x`,
		"/.well-known/oauth-protected-resource",
	} {
		_, found := p.ForRequestPath(path)
		assert.False(t, found, path)
	}
}

func TestCovers(t *testing.T) {
	p := testPolicy("https://mcp.example.com")
	const (
		origin = "https://mcp.example.com"
		mcp    = "https://mcp.example.com/mcp"
		api    = "https://mcp.example.com/mcp/api_access"
		social = "https://mcp.example.com/mcp/social"
	)

	tests := []struct {
		name       string
		authorized string
		requested  string
		want       bool
	}{
		{"origin covers itself", origin, origin, true},
		{"origin covers mcp", origin, mcp, true},
		{"origin covers a profile", origin, api, true},
		{"mcp covers itself", mcp, mcp, true},
		{"mcp covers a profile", mcp, api, true},
		{"mcp does not cover the bare origin", mcp, origin, false},
		{"profile covers itself", api, api, true},
		{"profile does not cover mcp", api, mcp, false},
		{"profile does not cover another profile", api, social, false},
		{"profile does not cover the origin", api, origin, false},
		{"foreign origin", "https://other.example.com/mcp", mcp, false},
		{"foreign origin requested", mcp, "https://other.example.com/mcp", false},
		{"same host other port", "https://mcp.example.com:8443/mcp", mcp, false},
		{"port-prefixed origin is not the origin", origin, "https://mcp.example.com:8443/mcp", false},
		{"sibling path with shared prefix", "https://mcp.example.com/mcpx", mcp, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, p.Covers(tc.authorized, tc.requested))
		})
	}
}

func TestCheckToken(t *testing.T) {
	p := testPolicy("https://mcp.example.com")
	const (
		mcp = "https://mcp.example.com/mcp"
		api = "https://mcp.example.com/mcp/api_access"
	)

	assert.NoError(t, p.CheckToken("", mcp), "legacy token without a resource is accepted")
	assert.NoError(t, p.CheckToken("", api))
	assert.NoError(t, p.CheckToken("https://mcp.example.com", api), "bare origin covers everything")
	assert.NoError(t, p.CheckToken(mcp, api))
	assert.NoError(t, p.CheckToken(api, api))
	assert.NoError(t, p.CheckToken("https://mcp.example.com/mcp/v1/api_access", api), "a stored alias is canonicalized")

	err := p.CheckToken(api, mcp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), mcp)
	assert.NotContains(t, err.Error(), `"`, "text goes into a quoted header parameter")

	err = p.CheckToken("https://old.example.com/mcp", mcp)
	require.Error(t, err, "token minted for another server URL")
	assert.NotContains(t, err.Error(), "old.example.com")
	assert.NotContains(t, err.Error(), `"`)

	assert.Error(t, p.CheckToken("garbage", mcp))
	assert.Error(t, p.CheckToken("https://mcp.example.com/mcp?x=1", mcp))
}

func TestDefaultProfilesComeFromTheRegistry(t *testing.T) {
	require.NotEmpty(t, tools.ProfileDefinitions)
	p := NewPolicy("https://mcp.example.com")

	got, err := p.Canonicalize("https://mcp.example.com/mcp/all")
	require.NoError(t, err)
	assert.Equal(t, "https://mcp.example.com/mcp/all", got)

	for name := range tools.ProfileDefinitions {
		got, err := p.Canonicalize("https://mcp.example.com/mcp/v1/" + name)
		require.NoError(t, err, name)
		assert.Equal(t, "https://mcp.example.com/mcp/"+name, got)
	}
	_, err = p.Canonicalize("https://mcp.example.com/mcp/definitely_not_a_profile")
	assert.Error(t, err)
}
