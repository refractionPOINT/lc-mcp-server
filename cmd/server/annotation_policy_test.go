package main

import (
	"strings"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// OAuth scopes are enforced from each tool's readOnlyHint annotation: a tool
// annotated read-only is reachable with limacharlie:read alone. That makes a
// mislabel a privilege escalation, so this guards the registered tool set
// (every package main imports) against a mutating tool being annotated
// read-only.

// mutatingWords are name parts that mean a tool changes state.
var mutatingWords = map[string]bool{
	"delete": true, "set": true, "create": true, "add": true, "remove": true, "update": true,
	"push": true, "upload": true, "isolate": true, "rejoin": true, "untag": true, "revoke": true,
	"rotate": true, "subscribe": true, "unsubscribe": true, "merge": true, "dismiss": true,
	"restore": true, "execute": true, "purge": true, "apply": true, "kill": true, "reopen": true,
	"revise": true,
}

// readOnlyDespiteTheName lists read-only tools whose names contain a mutating
// word. Each only previews or mints a single-use confirmation token; the
// mutation itself is a separate tool that needs limacharlie:write.
var readOnlyDespiteTheName = map[string]string{
	"get_org_delete_confirmation":  "mints a 60 second confirmation token; delete_org performs the deletion",
	"mailsec_prepare_tenant_purge": "returns a warning and a single-use token; mailsec_purge_tenant performs the purge",
}

func TestReadOnlyAnnotationsAreNotOnMutatingTools(t *testing.T) {
	var checked, readOnly int
	for _, name := range tools.GetToolsForProfile("all") {
		reg, ok := tools.GetTool(name)
		if !ok {
			continue
		}
		checked++
		if reg.RequiredScope() != auth.ScopeRead {
			continue
		}
		readOnly++
		for _, word := range strings.Split(name, "_") {
			if !mutatingWords[word] {
				continue
			}
			if _, accepted := readOnlyDespiteTheName[name]; accepted {
				continue
			}
			t.Errorf("tool %q is annotated readOnlyHint=true but its name says it mutates (%q): "+
				"a limacharlie:read token could call it. Fix the annotation, or list it in "+
				"readOnlyDespiteTheName with the reason it is read-only", name, word)
		}
	}
	if checked < 100 || readOnly == 0 {
		t.Fatalf("expected the full tool registry, checked %d tools (%d read-only)", checked, readOnly)
	}
	for name := range readOnlyDespiteTheName {
		reg, ok := tools.GetTool(name)
		if !ok {
			t.Errorf("readOnlyDespiteTheName lists %q, which is not registered: remove the stale entry", name)
		} else if reg.RequiredScope() != auth.ScopeRead {
			t.Errorf("readOnlyDespiteTheName lists %q, which is no longer read-only: remove the entry", name)
		}
	}
}

func TestKnownDestructiveToolsNeedWrite(t *testing.T) {
	for _, name := range []string{
		"delete_secret", "delete_org", "set_secret", "delete_sensor", "lc_call_tool",
	} {
		reg, ok := tools.GetTool(name)
		if !ok {
			continue // not part of this build's registry
		}
		if got := reg.RequiredScope(); got != auth.ScopeWrite {
			t.Errorf("%s requires %q, want %q", name, got, auth.ScopeWrite)
		}
	}
	if reg, ok := tools.GetTool("delete_secret"); !ok || reg.RequiredScope() != auth.ScopeWrite {
		t.Errorf("delete_secret must be registered and need write")
	}
}
