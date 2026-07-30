package auth

import "testing"

// ValidateUIDFormat guards the request path, so it must accept every UID an
// identity provider can legitimately mint. ValidateUID's "looks like a token"
// heuristics are deliberately absent here: they exist to catch an operator
// pasting a secret into LC_UID, and applying them to a caller-supplied header
// would reject real users whose UID happens to be 32+ alphanumeric characters.
func TestValidateUIDFormatAcceptsRealIdentities(t *testing.T) {
	valid := []string{
		"HM5oDavp4zSdQBRKxj4Q3TBmiHG2",     // Firebase UID, 28 chars
		"aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1eF", // 32 chars, base64 alphabet
		"0123456789abcdef0123456789abcdef", // 32 chars, all hex
		"maxime@refractionpoint.com",       // email identity
		"user.name_1-2",                    // punctuation in the allowed set
	}
	for _, uid := range valid {
		if err := ValidateUIDFormat(uid); err != nil {
			t.Errorf("ValidateUIDFormat(%q) rejected a legitimate UID: %v", uid, err)
		}
	}

	invalid := map[string]string{
		"":    "empty",
		"ab":  "too short",
		"a b": "space is outside the allowed set",
		"eyJhbGciOiJSUzI1NiJ9.eyJ1aWQiOiJ4In0.c2ln": "a JWT is not an identity",
	}
	for uid, why := range invalid {
		if err := ValidateUIDFormat(uid); err == nil {
			t.Errorf("ValidateUIDFormat(%q) accepted an invalid UID (%s)", uid, why)
		}
	}
}
