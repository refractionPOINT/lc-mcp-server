package admin

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/refractionpoint/lc-mcp-go/internal/tools/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var fakeAPI *testutil.FakeAPI

func TestMain(m *testing.M) {
	api, stop := testutil.InstallFakeAPI()
	fakeAPI = api
	code := m.Run()
	stop()
	os.Exit(code)
}

const (
	testGroup     = "g1"
	testTargetOID = "11111111-2222-3333-4444-555555555555"
)

// gateway answers the permission lookup (who) with the given permissions by org,
// as the API does, and acknowledges everything else.
func gateway(userPerms string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/who") {
			_, _ = w.Write([]byte(`{"orgs":[],"perms":[],"user_perms":` + userPerms + `}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}
}

// userContext is a signed-in user (UID OAuth) with ai_agent.operate enforcement
// armed, which is the case the target-org check exists for.
func userContext(t *testing.T, enforce bool) context.Context {
	t.Helper()
	ctx := fakeAPI.Context(t, auth.AuthModeUIDOAuth, "")
	if enforce {
		cache := auth.NewPermissionCache(time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
		t.Cleanup(cache.Close)
		ctx = auth.WithPermissionCache(ctx, cache)
	}
	return auth.WithPermissionEnforcement(ctx, enforce)
}

func toolText(res *mcp.CallToolResult) string { return res.Content[0].(mcp.TextContent).Text }

// requestsTo lists the requests the fake gateway got for a path suffix.
func requestsTo(suffix string) []testutil.RecordedRequest {
	var out []testutil.RecordedRequest
	for _, r := range fakeAPI.Requests() {
		if strings.HasSuffix(r.Path, suffix) {
			out = append(out, r)
		}
	}
	return out
}

func bodyOID(t *testing.T, r testutil.RecordedRequest) string {
	t.Helper()
	form, err := url.ParseQuery(string(r.Body))
	require.NoError(t, err)
	return form.Get("oid")
}

// Adding an org gives the group (and so the AI agent acting for its owner) access
// to it, so the org's own ai_agent.operate setting must allow it first.
func TestAddOrgToGroupNeedsAIAgentOperateOnTheOrgBeingAdded(t *testing.T) {
	reg, ok := tools.GetTool("add_org_to_group")
	require.True(t, ok)
	args := map[string]any{"gid": testGroup, "oid": testTargetOID}

	t.Run("an org that does not allow AI agents is refused before the API is called", func(t *testing.T) {
		fakeAPI.Handle(t, gateway(`{"`+testTargetOID+`":["org.get"]}`))
		res, err := reg.Invoke(userContext(t, true), args)
		require.NoError(t, err)
		require.True(t, res.IsError, toolText(res))
		assert.Contains(t, toolText(res), "ai_agent.operate")
		assert.Empty(t, requestsTo("/groups/"+testGroup+"/orgs"), "nothing reaches the group API")
	})

	t.Run("an org that allows AI agents is added", func(t *testing.T) {
		fakeAPI.Handle(t, gateway(`{"`+testTargetOID+`":["ai_agent.operate"]}`))
		res, err := reg.Invoke(userContext(t, true), args)
		require.NoError(t, err)
		require.False(t, res.IsError, toolText(res))
		adds := requestsTo("/groups/" + testGroup + "/orgs")
		require.Len(t, adds, 1)
		assert.Equal(t, http.MethodPost, adds[0].Method)
		assert.Equal(t, testTargetOID, bodyOID(t, adds[0]))
	})

	t.Run("without enforcement the API alone decides", func(t *testing.T) {
		fakeAPI.Handle(t, gateway(`{}`))
		res, err := reg.Invoke(userContext(t, false), args)
		require.NoError(t, err)
		require.False(t, res.IsError, toolText(res))
		assert.Len(t, requestsTo("/groups/"+testGroup+"/orgs"), 1)
		assert.Empty(t, requestsTo("/who"), "no permission lookup when nothing is enforced")
	})
}

// Removing an org only takes access away, and the API asks no more of the caller
// than owning the group: it checks no permission on the removed org. So an owner
// who has lost access to an org, or whose org refuses AI agents, can still remove
// it through the tool.
func TestRemoveOrgFromGroupDoesNotNeedAIAgentOperateOnTheRemovedOrg(t *testing.T) {
	reg, ok := tools.GetTool("remove_org_from_group")
	require.True(t, ok)
	args := map[string]any{"gid": testGroup, "oid": testTargetOID}

	for name, userPerms := range map[string]string{
		"the org does not allow AI agents":    `{"` + testTargetOID + `":["org.get"]}`,
		"the caller has no access to the org": `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			fakeAPI.Handle(t, gateway(userPerms))
			res, err := reg.Invoke(userContext(t, true), args)
			require.NoError(t, err)
			require.False(t, res.IsError, toolText(res))

			removes := requestsTo("/groups/" + testGroup + "/orgs")
			require.Len(t, removes, 1)
			assert.Equal(t, http.MethodDelete, removes[0].Method)
			assert.Equal(t, testTargetOID, bodyOID(t, removes[0]))
			assert.Empty(t, requestsTo("/who"), "no permission lookup for the removed org")
		})
	}

	t.Run("a malformed oid is still refused before the API is called", func(t *testing.T) {
		for _, oid := range []string{"..", ".", "../" + testTargetOID, "my-org"} {
			fakeAPI.Handle(t, nil)
			res, err := reg.Invoke(userContext(t, true), map[string]any{"gid": testGroup, "oid": oid})
			require.NoError(t, err)
			require.True(t, res.IsError, oid)
			assert.Contains(t, toolText(res), "invalid organization ID")
			assert.Empty(t, fakeAPI.Requests(), oid)
		}
	})
}
