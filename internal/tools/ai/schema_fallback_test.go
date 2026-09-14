package ai

import (
	"errors"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"testing"
)

type schemaSourceStub struct {
	filtered, all *lc.Schemas
	err           error
	allCalls      int
}

func (s *schemaSourceStub) GetSchemasForPlatform(string) (*lc.Schemas, error) {
	return s.filtered, s.err
}
func (s *schemaSourceStub) GetSchemas() (*lc.Schemas, error) { s.allCalls++; return s.all, nil }

func TestEventSelectionFallsBackFromEmptyPlatform(t *testing.T) {
	for _, tc := range []struct {
		name     string
		filtered *lc.Schemas
		err      error
		fallback bool
	}{
		{"nil", nil, nil, true},
		{"empty", &lc.Schemas{}, nil, true},
		{"detections only", &lc.Schemas{EventTypes: []string{"det:alert"}}, nil, true},
		{"unsupported", nil, errors.New("unsupported filter"), true},
		{"events", &lc.Schemas{EventTypes: []string{"evt:NEW_PROCESS"}}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &schemaSourceStub{filtered: tc.filtered, all: &lc.Schemas{EventTypes: []string{"evt:DNS_REQUEST"}}, err: tc.err}
			got, err := eventSelectionSchemas(source, "zeek")
			if err != nil {
				t.Fatal(err)
			}
			want := tc.filtered
			if tc.fallback {
				want = source.all
			}
			if got != want || (source.allCalls > 0) != tc.fallback {
				t.Fatalf("got %#v, fallback calls %d", got, source.allCalls)
			}
		})
	}
}
