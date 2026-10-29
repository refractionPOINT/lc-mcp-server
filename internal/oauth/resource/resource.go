// Package resource implements RFC 8707 resource indicators for the MCP
// endpoints this server exposes: which resource identifiers are valid for it,
// their canonical form, and when a token bound to one resource may be used at
// another.
//
// The protected resources are the MCP endpoint (/mcp), its profile endpoints
// (/mcp/<profile>) and their versioned aliases (/mcp/v1, /mcp/v1/<profile>).
// The bare server origin is also accepted as a resource and covers all of
// them, because some clients send the server URL rather than the MCP URL.
package resource

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

const (
	mcpSegment     = "mcp"
	versionSegment = "v1"
	allProfile     = "all"
	mcpPath        = "/" + mcpSegment
)

// ErrInvalidResource is wrapped by every error Canonicalize returns, so callers
// can map it to the RFC 8707 "invalid_target" error.
var ErrInvalidResource = errors.New("invalid resource")

// Policy decides which resource identifiers are valid for one server.
type Policy struct {
	origin    string // scheme://host[:port], normalized; empty when the server URL is unusable
	basePath  string // path prefix of the server URL, without a trailing slash; usually empty
	isProfile func(string) bool
}

// NewPolicy builds the policy for a server whose public base URL is serverURL
// (MCP_SERVER_URL). If serverURL cannot be parsed the policy rejects every
// resource, failing closed.
func NewPolicy(serverURL string) *Policy {
	p := &Policy{isProfile: isKnownProfile}
	origin, basePath, err := splitServerURL(serverURL)
	if err == nil {
		p.origin, p.basePath = origin, basePath
	}
	return p
}

// WithProfiles replaces the set of valid profile names; for tests.
func (p *Policy) WithProfiles(isProfile func(string) bool) *Policy {
	p.isProfile = isProfile
	return p
}

func isKnownProfile(name string) bool {
	if name == allProfile {
		return true
	}
	_, ok := tools.ProfileDefinitions[name]
	return ok
}

// Origin returns the server's normalized origin, which is also the resource
// that covers every endpoint.
func (p *Policy) Origin() string {
	return p.origin + p.basePath
}

// Canonicalize validates raw as a resource identifier of this server and
// returns its canonical form: lowercase scheme and host, no default port, no
// trailing slash, versioned aliases folded into the unversioned path. The
// result is one of the bare server origin, <origin>/mcp or <origin>/mcp/<profile>.
// Canonicalize is idempotent.
func (p *Policy) Canonicalize(raw string) (string, error) {
	if p.origin == "" {
		return "", invalidf("server URL is not configured")
	}
	if raw == "" {
		return "", invalidf("empty resource")
	}
	if strings.ContainsAny(raw, "#?") {
		return "", invalidf("resource must not contain a query or fragment")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", invalidf("not an absolute URI")
	}
	if u.User != nil || u.Opaque != "" {
		return "", invalidf("not an absolute URI")
	}
	origin, err := normalizeOrigin(u)
	if err != nil {
		return "", err
	}
	if origin != p.origin {
		return "", invalidf("resource is not served by this server")
	}

	segments, err := pathSegments(u.EscapedPath())
	if err != nil {
		return "", err
	}
	if base := splitPath(p.basePath); len(base) > 0 {
		if len(segments) < len(base) || !equalSegments(segments[:len(base)], base) {
			return "", invalidf("resource is not served by this server")
		}
		segments = segments[len(base):]
	}
	rel, ok := p.mcpPath(segments, false)
	if !ok {
		return "", invalidf("resource is not an MCP endpoint of this server")
	}
	return p.origin + p.basePath + rel, nil
}

// ForRequestPath returns the canonical resource a request for urlPath is
// made to. It reports false for a path that is not an MCP endpoint. The bare
// root "/" is served as /mcp.
func (p *Policy) ForRequestPath(urlPath string) (string, bool) {
	if p.origin == "" || urlPath == "" || strings.ContainsAny(urlPath, "%\\") {
		return "", false
	}
	segments, err := pathSegments(urlPath)
	if err != nil {
		return "", false
	}
	rel, ok := p.mcpPath(segments, true)
	if !ok {
		return "", false
	}
	return p.origin + p.basePath + rel, true
}

// mcpPath maps path segments (after the server's base path) to a canonical
// path: "" for the bare origin when allowBare, else "/mcp" or "/mcp/<profile>".
// With rootIsMCP the empty path is the MCP endpoint itself (request paths);
// otherwise it is the bare origin resource.
func (p *Policy) mcpPath(segments []string, rootIsMCP bool) (string, bool) {
	if len(segments) == 0 {
		if rootIsMCP {
			return mcpPath, true
		}
		return "", true
	}
	if segments[0] != mcpSegment {
		return "", false
	}
	segments = segments[1:]
	if len(segments) > 0 && segments[0] == versionSegment {
		segments = segments[1:]
	}
	switch len(segments) {
	case 0:
		return mcpPath, true
	case 1:
		if p.isProfile(segments[0]) {
			return mcpPath + "/" + segments[0], true
		}
	}
	return "", false
}

// Covers reports whether a token authorized for resource authorized may be
// used for resource requested. Both must be canonical. The bare origin covers
// everything, /mcp covers /mcp/<profile>, and anything else covers only itself.
func (p *Policy) Covers(authorized, requested string) bool {
	aRel, ok := p.relative(authorized)
	if !ok {
		return false
	}
	rRel, ok := p.relative(requested)
	if !ok {
		return false
	}
	switch {
	case aRel == "" || aRel == rRel:
		return true
	case aRel == mcpPath:
		return strings.HasPrefix(rRel, mcpPath+"/")
	}
	return false
}

// relative returns the part of a canonical resource after the server's origin
// and base path: "", "/mcp" or "/mcp/<profile>".
func (p *Policy) relative(canonical string) (string, bool) {
	rel, ok := strings.CutPrefix(canonical, p.origin+p.basePath)
	if !ok || (rel != "" && rel[0] != '/') {
		return "", false
	}
	return rel, true
}

// CheckToken reports whether a token bound to tokenResource may be used for a
// request to requestResource (the canonical resource of the request path). An
// empty tokenResource is a token issued before resource binding existed; it is
// accepted (legacy). The token's resource must itself be valid for this
// server, so a token minted under a different MCP_SERVER_URL is rejected.
//
// The error text is shown to the client in a WWW-Authenticate challenge, so it
// never repeats the token's own resource.
func (p *Policy) CheckToken(tokenResource, requestResource string) error {
	if tokenResource == "" {
		return nil
	}
	canonical, err := p.Canonicalize(tokenResource)
	if err != nil {
		return errors.New("The access token was issued for a different resource; sign in again")
	}
	if !p.Covers(canonical, requestResource) {
		return fmt.Errorf("The access token was not issued for %s; sign in again for the endpoint you are connecting to", requestResource)
	}
	return nil
}

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidResource, fmt.Sprintf(format, args...))
}

// splitServerURL returns the normalized origin and base path of a server URL.
func splitServerURL(serverURL string) (string, string, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", "", err
	}
	origin, err := normalizeOrigin(u)
	if err != nil {
		return "", "", err
	}
	segments, err := pathSegments(u.EscapedPath())
	if err != nil {
		return "", "", err
	}
	basePath := ""
	if len(segments) > 0 {
		basePath = "/" + strings.Join(segments, "/")
	}
	return origin, basePath, nil
}

// normalizeOrigin returns scheme://host[:port] with the scheme and host in
// lowercase and the scheme's default port removed.
func normalizeOrigin(u *url.URL) (string, error) {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", invalidf("resource must be an http(s) URI")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", invalidf("resource has no host")
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if port == "" || (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return scheme + "://" + host, nil
	}
	return scheme + "://" + host + ":" + port, nil
}

// pathSegments splits an escaped URL path into segments, ignoring one leading
// and one trailing slash. Percent-encoding, backslashes, empty segments and
// dot segments are rejected outright: no legitimate resource needs them, and
// accepting them invites two spellings of one path.
func pathSegments(escaped string) ([]string, error) {
	if strings.ContainsAny(escaped, "%\\") {
		return nil, invalidf("resource path must not be percent-encoded")
	}
	trimmed := strings.TrimSuffix(strings.TrimPrefix(escaped, "/"), "/")
	if trimmed == "" {
		return nil, nil
	}
	segments := strings.Split(trimmed, "/")
	for _, s := range segments {
		if s == "" || s == "." || s == ".." {
			return nil, invalidf("resource path is not normalized")
		}
	}
	return segments, nil
}

func splitPath(p string) []string {
	if p == "" {
		return nil
	}
	return strings.Split(strings.TrimPrefix(p, "/"), "/")
}

func equalSegments(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
