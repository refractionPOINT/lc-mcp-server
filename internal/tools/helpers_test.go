package tools

import (
	"errors"
	"testing"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

// mockLCQLValidator is a mock implementation of LCQLValidator for testing.
type mockLCQLValidator struct {
	validateFunc func(query string) (*lc.ValidationResponse, error)
}

func (m *mockLCQLValidator) ValidateLCQLQuery(query string) (*lc.ValidationResponse, error) {
	if m.validateFunc != nil {
		return m.validateFunc(query)
	}
	return &lc.ValidationResponse{}, nil
}

func TestValidateLCQLQuery(t *testing.T) {
	t.Run("empty query returns error", func(t *testing.T) {
		mock := &mockLCQLValidator{}

		valid, errMsg := ValidateLCQLQuery(mock, "")

		if valid {
			t.Error("expected valid to be false for empty query")
		}
		if errMsg != "query is empty" {
			t.Errorf("expected error message 'query is empty', got '%s'", errMsg)
		}
	})

	t.Run("valid query returns success", func(t *testing.T) {
		mock := &mockLCQLValidator{
			validateFunc: func(query string) (*lc.ValidationResponse, error) {
				return &lc.ValidationResponse{Error: ""}, nil
			},
		}

		valid, errMsg := ValidateLCQLQuery(mock, "-1h | * | * | / exists")

		if !valid {
			t.Error("expected valid to be true for valid query")
		}
		if errMsg != "" {
			t.Errorf("expected empty error message, got '%s'", errMsg)
		}
	})

	t.Run("invalid query returns validation error", func(t *testing.T) {
		mock := &mockLCQLValidator{
			validateFunc: func(query string) (*lc.ValidationResponse, error) {
				return &lc.ValidationResponse{Error: "invalid filter syntax"}, nil
			},
		}

		valid, errMsg := ValidateLCQLQuery(mock, "-1h | * | limit:10")

		if valid {
			t.Error("expected valid to be false for invalid query")
		}
		if errMsg != "invalid filter syntax" {
			t.Errorf("expected error message 'invalid filter syntax', got '%s'", errMsg)
		}
	})

	t.Run("API error returns formatted error", func(t *testing.T) {
		mock := &mockLCQLValidator{
			validateFunc: func(query string) (*lc.ValidationResponse, error) {
				return nil, errors.New("connection refused")
			},
		}

		valid, errMsg := ValidateLCQLQuery(mock, "-1h | * | * | / exists")

		if valid {
			t.Error("expected valid to be false when API returns error")
		}
		if errMsg != "validation error: connection refused" {
			t.Errorf("expected error message 'validation error: connection refused', got '%s'", errMsg)
		}
	})

	t.Run("query is passed to validator", func(t *testing.T) {
		var receivedQuery string
		mock := &mockLCQLValidator{
			validateFunc: func(query string) (*lc.ValidationResponse, error) {
				receivedQuery = query
				return &lc.ValidationResponse{}, nil
			},
		}

		testQuery := "-24h | plat == windows | NEW_PROCESS | event/FILE_PATH contains 'cmd.exe'"
		ValidateLCQLQuery(mock, testQuery)

		if receivedQuery != testQuery {
			t.Errorf("expected query '%s' to be passed to validator, got '%s'", testQuery, receivedQuery)
		}
	})
}

func TestValidateLCQLQueryFull(t *testing.T) {
	t.Run("empty query returns error result", func(t *testing.T) {
		mock := &mockLCQLValidator{}

		result := ValidateLCQLQueryFull(mock, "")

		if result.Valid {
			t.Error("expected Valid to be false for empty query")
		}
		if result.Error != "query is empty" {
			t.Errorf("expected error 'query is empty', got '%s'", result.Error)
		}
	})

	t.Run("valid query returns full result with estimates", func(t *testing.T) {
		mock := &mockLCQLValidator{
			validateFunc: func(query string) (*lc.ValidationResponse, error) {
				return &lc.ValidationResponse{
					Error:     "",
					NumEvals:  1000,
					NumEvents: 500,
					EvalTime:  2.5,
				}, nil
			},
		}

		result := ValidateLCQLQueryFull(mock, "-1h | * | * | / exists")

		if !result.Valid {
			t.Error("expected Valid to be true")
		}
		if result.Error != "" {
			t.Errorf("expected empty error, got '%s'", result.Error)
		}
		if result.NumEvals != 1000 {
			t.Errorf("expected NumEvals=1000, got %d", result.NumEvals)
		}
		if result.NumEvents != 500 {
			t.Errorf("expected NumEvents=500, got %d", result.NumEvents)
		}
		if result.EvalTime != 2.5 {
			t.Errorf("expected EvalTime=2.5, got %f", result.EvalTime)
		}
	})

	t.Run("invalid query returns error with estimates", func(t *testing.T) {
		mock := &mockLCQLValidator{
			validateFunc: func(query string) (*lc.ValidationResponse, error) {
				return &lc.ValidationResponse{
					Error:     "invalid syntax",
					NumEvals:  100,
					NumEvents: 50,
					EvalTime:  0.1,
				}, nil
			},
		}

		result := ValidateLCQLQueryFull(mock, "-1h | * | invalid")

		if result.Valid {
			t.Error("expected Valid to be false")
		}
		if result.Error != "invalid syntax" {
			t.Errorf("expected error 'invalid syntax', got '%s'", result.Error)
		}
		// Estimates should still be returned even for invalid queries
		if result.NumEvals != 100 {
			t.Errorf("expected NumEvals=100, got %d", result.NumEvals)
		}
	})

	t.Run("API error returns error result", func(t *testing.T) {
		mock := &mockLCQLValidator{
			validateFunc: func(query string) (*lc.ValidationResponse, error) {
				return nil, errors.New("network error")
			},
		}

		result := ValidateLCQLQueryFull(mock, "-1h | * | * | / exists")

		if result.Valid {
			t.Error("expected Valid to be false when API returns error")
		}
		if result.Error != "validation error: network error" {
			t.Errorf("expected 'validation error: network error', got '%s'", result.Error)
		}
	})
}
