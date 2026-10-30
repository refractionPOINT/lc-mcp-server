// Package cimd implements OAuth Client ID Metadata Documents
// (draft-ietf-oauth-client-id-metadata-document): an https URL used as an OAuth
// client_id, resolved by fetching the JSON document it points to.
package cimd

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode"
)

const maxClientIDLen = 2048

// LooksLikeURL reports whether a client_id is shaped like a URL. Such a
// client_id is either a valid CIMD client_id or it is rejected; it must never
// fall back to dynamic registration or a static allow-list.
func LooksLikeURL(clientID string) bool {
	return strings.Contains(clientID, "://")
}

// hostSuffixDenylist are DNS suffixes that only make sense on private networks.
var hostSuffixDenylist = []string{
	".local", ".localhost", ".localdomain", ".internal", ".intranet",
	".lan", ".home", ".corp", ".private", ".home.arpa",
}

// urlPolicy holds the knobs that tests relax; production uses the zero value.
type urlPolicy struct {
	allowAnyPort   bool
	allowIPLiteral bool
}

// ValidateClientID checks that clientID is acceptable as a CIMD client_id and
// returns the parsed URL. Rules: https scheme, a real path, no userinfo,
// fragment or query, no dot segments, a public-looking DNS name (no IP
// literal, no single-label or private-suffix names) and the default port only.
//
// Only the default port is accepted: the fetcher is a way to make our servers
// issue requests, and a client has no need for anything but 443. Non-default
// ports are where internal admin and database ports live.
func ValidateClientID(clientID string) (*url.URL, error) {
	return validateClientID(clientID, urlPolicy{})
}

func validateClientID(clientID string, pol urlPolicy) (*url.URL, error) {
	bad := func(format string, args ...any) (*url.URL, error) {
		return nil, &Error{Kind: KindInvalidClientID, Message: "invalid client_id URL: " + fmt.Sprintf(format, args...)}
	}
	if len(clientID) > maxClientIDLen {
		return bad("too long")
	}
	for _, r := range clientID {
		if r <= 0x20 || r == 0x7f || r == '\\' || r > unicode.MaxASCII {
			return bad("contains forbidden characters")
		}
	}
	if !strings.HasPrefix(clientID, "https://") {
		return bad("scheme must be https")
	}
	if strings.Contains(clientID, "#") {
		return bad("must not contain a fragment")
	}
	u, err := url.Parse(clientID)
	if err != nil {
		return bad("not parseable")
	}
	if u.Scheme != "https" || u.Opaque != "" {
		return bad("scheme must be https")
	}
	if u.User != nil || strings.Contains(u.Host, "@") {
		return bad("must not contain credentials")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return bad("must not contain a query")
	}
	if u.Path == "" || u.Path == "/" {
		return bad("must contain a path")
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return bad("must not contain dot segments")
		}
	}

	host := u.Hostname()
	if host == "" {
		return bad("missing host")
	}
	if port := u.Port(); port != "" && port != "443" && !pol.allowAnyPort {
		return bad("only the default https port is allowed")
	}
	if net.ParseIP(host) != nil || strings.ContainsAny(host, "[]:") {
		if !pol.allowIPLiteral {
			return bad("host must be a DNS name")
		}
		return u, nil
	}
	if !validDNSName(host) {
		return bad("host is not a valid public DNS name")
	}
	return u, nil
}

func validDNSName(host string) bool {
	if len(host) > 253 || strings.HasSuffix(host, ".") || !strings.Contains(host, ".") {
		return false
	}
	lower := strings.ToLower(host)
	for _, suf := range hostSuffixDenylist {
		if strings.HasSuffix(lower, suf) {
			return false
		}
	}
	for _, label := range strings.Split(lower, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	// A purely numeric final label would let odd IPv4 spellings (2130706433,
	// 0x7f.1) through as a "name".
	last := lower[strings.LastIndex(lower, ".")+1:]
	if last[0] >= '0' && last[0] <= '9' {
		return false
	}
	return true
}
