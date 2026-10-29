package state

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tokens written before resource binding existed carry no "resource" key and
// must keep decoding; new records without one must not grow the key.
func TestResourceFieldIsBackwardCompatible(t *testing.T) {
	var at AccessTokenData
	require.NoError(t, json.Unmarshal([]byte(`{"access_token":"a","uid":"u","scope":"openid","expires_at":1}`), &at))
	assert.Empty(t, at.Resource)

	var rt RefreshTokenData
	require.NoError(t, json.Unmarshal([]byte(`{"refresh_token":"r","uid":"u"}`), &rt))
	assert.Empty(t, rt.Resource)

	var code AuthorizationCode
	require.NoError(t, json.Unmarshal([]byte(`{"code":"c","uid":"u"}`), &code))
	assert.Empty(t, code.Resource)

	for _, v := range []any{&AccessTokenData{}, &RefreshTokenData{}, &AuthorizationCode{}} {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), "resource")
	}

	raw, err := json.Marshal(&AccessTokenData{Resource: "https://mcp.example.com/mcp"})
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"resource":"https://mcp.example.com/mcp"`)
}
