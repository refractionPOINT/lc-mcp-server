package http

import "testing"

// TestOIDCoveredByClaims pins the cross-tenant boundary for the org-JWT
// passthrough path: the OID arrives in a header while the credential is the JWT,
// so a token scoped to org A must not be able to name org B. The thin-token
// cases must fail open — webapp user tokens legitimately carry oid="-" and no
// per-org claims, and rejecting those would break every such caller.
func TestOIDCoveredByClaims(t *testing.T) {
	const orgA = "11111111-1111-1111-1111-111111111111"
	const orgB = "22222222-2222-2222-2222-222222222222"

	cases := []struct {
		name      string
		claimOIDs []string
		requested string
		want      bool
	}{
		{"token scoped to the requested org", []string{orgA}, orgA, true},
		{"multi-org token containing the requested org", []string{orgB, orgA}, orgA, true},
		{"token for another org is rejected", []string{orgA}, orgB, false},
		{"multi-org token excluding the requested org is rejected", []string{orgA, "33333333-3333-3333-3333-333333333333"}, orgB, false},
		{"thin token (placeholder only) fails open", []string{"-"}, orgA, true},
		{"thin token (no claims) fails open", nil, orgA, true},
		{"thin token (empty claim) fails open", []string{""}, orgA, true},
		{"placeholder alongside a concrete org still enforces", []string{"-", orgA}, orgB, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := oidCoveredByClaims(tc.claimOIDs, tc.requested); got != tc.want {
				t.Errorf("oidCoveredByClaims(%q, %q) = %v, want %v", tc.claimOIDs, tc.requested, got, tc.want)
			}
		})
	}
}
