package cloudsec

import (
	"encoding/base64"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestIaCReceiptRejectsUnfilteredOrPartlyAppliedSuccess(t *testing.T) {
	args := lc.Dict{"has_iac_origin": false, "iac_attribution": []string{"unknown"}}
	require.NoError(t, requireIaCReceipt(args, map[string]interface{}{"has_iac_origin": false, "iac_attribution": []interface{}{"unknown"}}))
	for _, receipt := range []interface{}{nil, true, lc.Dict{}, lc.Dict{"has_iac_origin": false}, lc.Dict{"has_iac_origin": 0, "iac_attribution": []string{"unknown"}}} {
		require.Error(t, requireIaCReceipt(args, receipt))
	}
	require.NoError(t, requireIaCReceipt(nil, nil))
}

func TestIaCCSVReceiptBoundAndLegacyCompatibility(t *testing.T) {
	args := lc.Dict{"has_iac_origin": false}
	prefix := "# lc_iac_filters_v1="
	valid := prefix + base64.RawURLEncoding.EncodeToString([]byte(`{"has_iac_origin":false}`)) + "\r\nname\nfixture\n"
	got, err := checkIaCCSVReceipt(args, valid)
	require.NoError(t, err)
	require.Equal(t, "name\nfixture\n", got)
	for _, raw := range []string{"name\nfixture\n", prefix + "%%%\n", prefix + strings.Repeat("a", 1025) + "\n", prefix + base64.RawURLEncoding.EncodeToString([]byte(`{"has_iac_origin":true}`)) + "\n"} {
		_, err := checkIaCCSVReceipt(args, raw)
		require.Error(t, err)
	}
	got, err = checkIaCCSVReceipt(nil, "name\nfixture\n")
	require.NoError(t, err)
	require.Equal(t, "name\nfixture\n", got)
}
