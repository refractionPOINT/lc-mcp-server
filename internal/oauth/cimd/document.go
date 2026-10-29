package cimd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// Limits on what we accept from a document, all to keep what we store, cache
// and render bounded.
const (
	maxClientNameRunes = 100
	maxRedirectURIs    = 20
	maxRedirectURILen  = 2048
)

// Document is the part of a client metadata document we use. Everything else
// in the document is ignored and never stored.
type Document struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
}

// HasRedirectURI reports whether uri is one of the document's redirect URIs,
// by exact string match.
func (d *Document) HasRedirectURI(uri string) bool {
	for _, r := range d.RedirectURIs {
		if r == uri {
			return true
		}
	}
	return false
}

func invalidDoc(format string, args ...any) *Error {
	return &Error{Kind: KindInvalidDocument, Message: "invalid client metadata document: " + fmt.Sprintf(format, args...)}
}

// parseDocument validates body as the metadata document for clientID.
func parseDocument(clientID string, body []byte) (*Document, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil || raw == nil {
		return nil, invalidDoc("not a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, invalidDoc("trailing data after JSON object")
	}

	// draft-ietf-oauth-client-id-metadata-document §4.1: documents MUST NOT
	// carry shared secrets. Refuse them outright rather than ignore them.
	for _, k := range []string{"client_secret", "client_secret_expires_at"} {
		if _, ok := raw[k]; ok {
			return nil, invalidDoc("%s must not be present", k)
		}
	}

	var doc Document
	if err := getString(raw, "client_id", &doc.ClientID); err != nil {
		return nil, err
	}
	if doc.ClientID != clientID {
		return nil, invalidDoc("client_id does not match the document URL")
	}
	if err := getString(raw, "client_name", &doc.ClientName); err != nil {
		return nil, err
	}
	if err := validateClientName(doc.ClientName); err != nil {
		return nil, err
	}

	// We only operate public clients (PKCE, no client authentication).
	if v, ok := raw["token_endpoint_auth_method"]; ok {
		var method string
		if err := json.Unmarshal(v, &method); err != nil {
			return nil, invalidDoc("token_endpoint_auth_method must be a string")
		}
		if method != "none" {
			return nil, &Error{Kind: KindUnsupported, Message: fmt.Sprintf("token_endpoint_auth_method %q is not supported; only public clients (\"none\") are", truncate(method, 40))}
		}
	}
	if err := requireContains(raw, "grant_types", "authorization_code"); err != nil {
		return nil, err
	}
	if err := requireContains(raw, "response_types", "code"); err != nil {
		return nil, err
	}

	v, ok := raw["redirect_uris"]
	if !ok {
		return nil, invalidDoc("redirect_uris is required")
	}
	if err := json.Unmarshal(v, &doc.RedirectURIs); err != nil {
		return nil, invalidDoc("redirect_uris must be an array of strings")
	}
	if len(doc.RedirectURIs) == 0 {
		return nil, invalidDoc("redirect_uris must not be empty")
	}
	if len(doc.RedirectURIs) > maxRedirectURIs {
		return nil, invalidDoc("too many redirect_uris")
	}
	for _, uri := range doc.RedirectURIs {
		if err := ValidateRedirectURI(uri); err != nil {
			return nil, invalidDoc("redirect_uri %q: %v", truncate(uri, 80), err)
		}
	}
	return &doc, nil
}

func getString(raw map[string]json.RawMessage, key string, dst *string) error {
	v, ok := raw[key]
	if !ok {
		return invalidDoc("%s is required", key)
	}
	if err := json.Unmarshal(v, dst); err != nil {
		return invalidDoc("%s must be a string", key)
	}
	if strings.TrimSpace(*dst) == "" {
		return invalidDoc("%s must not be empty", key)
	}
	return nil
}

// requireContains fails when key is present but does not list want. An absent
// key means the default, which is what we need.
func requireContains(raw map[string]json.RawMessage, key, want string) error {
	v, ok := raw[key]
	if !ok {
		return nil
	}
	var vals []string
	if err := json.Unmarshal(v, &vals); err != nil {
		return invalidDoc("%s must be an array of strings", key)
	}
	for _, s := range vals {
		if s == want {
			return nil
		}
	}
	return invalidDoc("%s must include %q", key, want)
}

// validateClientName keeps what we show to the user plain: bounded, and free of
// control and bidi/format characters that can be used to spoof the consent text.
func validateClientName(name string) error {
	if !utf8.ValidString(name) {
		return invalidDoc("client_name is not valid UTF-8")
	}
	if utf8.RuneCountInString(name) > maxClientNameRunes {
		return invalidDoc("client_name is too long")
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return invalidDoc("client_name contains control or formatting characters")
		}
	}
	return nil
}

// ValidateRedirectURI applies the same rules as dynamic client registration:
// https, or http only for localhost / 127.0.0.1 (MCP authorization,
// "Communication Security"). It additionally refuses userinfo and fragments.
func ValidateRedirectURI(uri string) error {
	if len(uri) == 0 || len(uri) > maxRedirectURILen {
		return fmt.Errorf("invalid length")
	}
	u, err := url.Parse(uri)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("invalid format")
	}
	if u.User != nil {
		return fmt.Errorf("must not contain credentials")
	}
	// The host is what the user is shown to decide where their sign-in goes,
	// so it must have an unambiguous ASCII form to show.
	if _, err := DisplayHost(u.Hostname()); err != nil {
		return err
	}
	if u.Fragment != "" || strings.Contains(uri, "#") {
		return fmt.Errorf("must not contain a fragment")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if h := u.Hostname(); h == "localhost" || h == "127.0.0.1" {
			return nil
		}
		return fmt.Errorf("http is only allowed for localhost")
	default:
		return fmt.Errorf("only https (or http for localhost) is allowed")
	}
}

// DisplayHost returns the form of a URL host (without port) that is shown to
// the user: the ASCII form, punycode for internationalised names, so that a
// look-alike such as a Cyrillic "а" in "аpple.com" shows as "xn--pple-43d.com"
// and cannot pass for the real thing. Hosts containing control, format (which
// includes the bidi overrides and isolates) or space characters, hosts that
// are not in canonical IDNA form, and hosts that fail IDNA conversion are
// refused. Plain ASCII hosts (names and IP literals) are returned as they are.
func DisplayHost(host string) (string, error) {
	ascii := true
	for _, r := range host {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zs, r) ||
			unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) || r == utf8.RuneError {
			return "", fmt.Errorf("host contains control, formatting or invalid characters")
		}
		if r > unicode.MaxASCII {
			ascii = false
		}
	}
	if ascii {
		return host, nil
	}
	out, err := idna.Lookup.ToASCII(host)
	if err != nil || out == "" {
		return "", fmt.Errorf("host is not a valid internationalised domain name")
	}
	// The conversion maps characters (case, width, compatibility forms); the
	// user must be shown exactly the host the URI contains, so refuse any host
	// that is not already in its mapped form.
	if back, err := idna.Lookup.ToUnicode(out); err != nil || back != strings.ToLower(host) {
		return "", fmt.Errorf("host is not in canonical internationalised form")
	}
	return out, nil
}

// IsLoopbackRedirect reports whether uri points at the user's own machine,
// which a client document cannot prove ownership of.
func IsLoopbackRedirect(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}
