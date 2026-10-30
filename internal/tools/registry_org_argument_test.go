package tools

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exchangeSpy stands in for the network: it counts the Firebase-to-JWT exchanges
// (jwt.limacharlie.io) and fails every request.
type exchangeSpy struct{ exchanges atomic.Int32 }

func (s *exchangeSpy) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host == "jwt.limacharlie.io" {
		s.exchanges.Add(1)
	}
	return nil, errors.New("no network in tests")
}

// Switching the credential to the named org is a network round trip in UID OAuth
// mode (the Firebase token is exchanged for a JWT carrying the org). It is only
// worth making for a check that then runs, and a failure of it must not fail a call
// that needs no check.
func TestRequireAIAgentAccessToOrg_OnlySwitchesOrgsWhenItChecks(t *testing.T) {
	spy := &exchangeSpy{}
	prev := http.DefaultTransport
	http.DefaultTransport = spy
	t.Cleanup(func() { http.DefaultTransport = prev })

	cache := auth.NewPermissionCache(time.Minute, slog.Default())
	t.Cleanup(cache.Close)
	oauthUser := func() context.Context {
		return auth.WithAuthContext(context.Background(), &auth.AuthContext{
			Mode: auth.AuthModeUIDOAuth, UID: "user-uid", FirebaseIDToken: "firebase-id-token",
		})
	}

	t.Run("enforcement off: nothing to check, nothing exchanged", func(t *testing.T) {
		spy.exchanges.Store(0)
		ctx := auth.WithPermissionEnforcement(auth.WithPermissionCache(oauthUser(), cache), false)
		assert.NoError(t, RequireAIAgentAccessToOrg(ctx, testPermissionOID))
		assert.Zero(t, spy.exchanges.Load())
	})

	t.Run("no permission cache: nothing to check, nothing exchanged", func(t *testing.T) {
		spy.exchanges.Store(0)
		ctx := auth.WithPermissionEnforcement(oauthUser(), true)
		assert.NoError(t, RequireAIAgentAccessToOrg(ctx, testPermissionOID))
		assert.Zero(t, spy.exchanges.Load())
	})

	t.Run("enforced: the credential is switched to the org first, and a failed switch denies", func(t *testing.T) {
		spy.exchanges.Store(0)
		ctx := auth.WithPermissionEnforcement(auth.WithPermissionCache(oauthUser(), cache), true)
		err := RequireAIAgentAccessToOrg(ctx, testPermissionOID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot act on organization")
		assert.EqualValues(t, 1, spy.exchanges.Load())
	})

	t.Run("a malformed oid is refused before anything else", func(t *testing.T) {
		spy.exchanges.Store(0)
		for _, oid := range []string{"..", "my-org", ""} {
			for _, enforce := range []bool{false, true} {
				ctx := auth.WithPermissionEnforcement(auth.WithPermissionCache(oauthUser(), cache), enforce)
				err := RequireAIAgentAccessToOrg(ctx, oid)
				require.Error(t, err, "%q enforce=%v", oid, enforce)
				assert.Contains(t, err.Error(), "invalid organization ID")
			}
		}
		assert.Zero(t, spy.exchanges.Load())
	})
}
