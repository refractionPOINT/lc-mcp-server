package cloudsec

import (
	"context"
	"strings"
	"testing"
)

func TestProvenancePushBoundsBeforeAuthentication(t *testing.T) {
	for _, document := range []any{nil, 123, "", strings.Repeat("x", (1<<20)+1), "not JSON"} {
		result, err := pushProvenance(context.Background(), map[string]interface{}{"document": document})
		if err != nil || result == nil || !result.IsError {
			t.Fatal("invalid document accepted")
		}
	}
}
