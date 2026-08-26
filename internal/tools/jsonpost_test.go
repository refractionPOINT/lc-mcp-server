package tools

import (
	"strings"
	"testing"
)

// The gateway override has to move THIS helper too. It used to hardcode the
// production root, so pointing the server at a staging gateway moved every other
// call and left the routes that go through PostJSON talking to production with the
// same credential — one route silently answering from a different estate.
func TestJSONPostRootFollowsTheConfiguredGateway(t *testing.T) {
	root := lcAPIRoot()
	if !strings.HasSuffix(root, "/v1/") {
		t.Fatalf("lcAPIRoot() = %q, want a /v1/ suffix", root)
	}
	if strings.Contains(strings.TrimSuffix(root, "/v1/"), "/v1") {
		t.Fatalf("lcAPIRoot() = %q, version segment duplicated", root)
	}
	// No LC_API_URL in the test process, so this must be the production default —
	// asserted so the fallback cannot quietly become something else.
	if root != "https://api.limacharlie.io/v1/" {
		t.Fatalf("lcAPIRoot() = %q, want the production default with no override set", root)
	}
}
