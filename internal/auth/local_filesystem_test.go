package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Local filesystem access is opt-in: an unmarked context (every HTTP request, a test
// harness, a background job) must not have it.
func TestLocalFilesystemAccessIsOptIn(t *testing.T) {
	assert.False(t, HasLocalFilesystemAccess(context.Background()))

	ctx := WithLocalFilesystemAccess(context.Background())
	assert.True(t, HasLocalFilesystemAccess(ctx))

	// It survives the derivations a request goes through...
	derived := WithAuthContext(ctx, &AuthContext{Mode: AuthModeNormal, OID: "o", APIKey: "k"})
	assert.True(t, HasLocalFilesystemAccess(derived))
	// ...and marking a child does not leak to the parent.
	assert.False(t, HasLocalFilesystemAccess(context.Background()))
}
