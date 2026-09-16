package cloudsec

import (
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cloudsec_test_provider takes an arbitrary cloudsec_provider record shape and forwards
// it verbatim — there is nothing GitLab/Bitbucket-specific in the handler itself, since
// the gateway validates the record. But an agent calling this tool has no other in-band
// way to learn which fields a GitLab or Bitbucket record needs, or that GitLab
// additionally requires group-level (not per-project) membership: the CLI's `cloudsec
// provider test --help` documents this in prose, and this tool's description is the only
// place an MCP caller could learn it. Pin the fields and the current validation rule
// (Maxime's decision on #100: a broad token is accepted, only a missing required scope is
// refused) so this cannot silently rot back to undiscoverable, or drift back to
// documenting the reverted ceiling-refusal rule.
func TestTestProviderDescriptionDocumentsGitLabAndBitbucketShapes(t *testing.T) {
	reg, exists := tools.GetTool("cloudsec_test_provider")
	require.True(t, exists)

	desc := reg.Description
	assert.Contains(t, desc, "gitlab_namespace")
	assert.Contains(t, desc, "bitbucket_workspace")
	assert.Contains(t, desc, "namespace_membership")
	assert.Contains(t, desc, "Reporter", "the group-level membership requirement must be named")
	assert.Contains(t, desc, "BROADER")
	assert.Contains(t, desc, "MISSING")
}
