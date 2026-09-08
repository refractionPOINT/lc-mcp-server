package auth

import (
	"os"
	"strings"
	"sync"
)

// defaultAPIRoot mirrors the SDK's own rootURL (go-limacharlie limacharlie/client.go)
// so this package can state the default without importing an unexported constant.
const defaultAPIRoot = "https://api.limacharlie.io"

// apiRootEnv names the environment variable that repoints every LimaCharlie REST call
// this server makes.
//
// It exists for one reason: staging. The gateway that serves a route is not always
// api.limacharlie.io — a route lands on the experimental gateway (a Cloud Run service
// with its own hostname) days or weeks before it is deployed to production, and a tool
// written against it cannot be exercised end to end at all without a way to say so.
// The alternative was a build-time fork of the server, which is worse: the thing you
// then test is not the thing you ship.
//
// It is a SERVER-level setting, read once from the process environment, and
// deliberately not a per-request or per-tool argument. A tenant-supplied API host would
// let a caller redirect this server's credentialed requests at a host of their
// choosing, which is a credential-exfiltration primitive; the operator who starts the
// process is the only party who may choose it.
const apiRootEnv = "LC_API_URL"

var (
	apiRootOnce  sync.Once
	apiRootValue string
)

// APIRoot returns the REST base URL every request from this process targets: the
// LimaCharlie production gateway unless the operator set LC_API_URL.
//
// The value is trailing-slash trimmed so callers can join it with "/v1/..." the way the
// SDK does, and a value that is not an http(s) URL is IGNORED rather than honored — a
// malformed override would otherwise turn every call into an opaque transport failure,
// and falling back to production is both the safe direction and the visible one.
func APIRoot() string {
	apiRootOnce.Do(func() {
		apiRootValue = resolveAPIRoot(os.Getenv(apiRootEnv))
	})
	return apiRootValue
}

// resolveAPIRoot is APIRoot's pure half, so the precedence and the rejection rule are
// testable without mutating process state.
func resolveAPIRoot(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return defaultAPIRoot
	}
	lower := strings.ToLower(v)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return defaultAPIRoot
	}
	return strings.TrimRight(v, "/")
}

// IsAPIRootOverridden reports whether this process talks to something other than the
// production gateway. Tools that describe where their answer came from use it, because
// "no findings" from a staging gateway and "no findings" from production are different
// statements and a reader cannot tell them apart otherwise.
func IsAPIRootOverridden() bool {
	return APIRoot() != defaultAPIRoot
}
