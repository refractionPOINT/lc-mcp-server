package tools

import (
	"errors"
	"math"
	"testing"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

// floatEquals compares two float64 values with a small tolerance for floating point precision.
func floatEquals(a, b, tolerance float64) bool {
	return math.Abs(a-b) <= tolerance
}

// mockLCQLValidator is a mock implementation of LCQLValidator for testing.
type mockLCQLValidator struct {
	validateFunc            func(query string) (*lc.ValidationResponse, error)
	estimateBillingFunc     func(query string) (*lc.BillingEstimate, error)
	validateAndEstimateFunc func(query string) (*lc.QueryValidationResult, error)
}

func (m *mockLCQLValidator) ValidateLCQLQuery(query string) (*lc.ValidationResponse, error) {
	if m.validateFunc != nil {
		return m.validateFunc(query)
	}
	return &lc.ValidationResponse{}, nil
}

func (m *mockLCQLValidator) EstimateLCQLQueryBilling(query string) (*lc.BillingEstimate, error) {
	if m.estimateBillingFunc != nil {
		return m.estimateBillingFunc(query)
	}
	return &lc.BillingEstimate{}, nil
}

func (m *mockLCQLValidator) ValidateAndEstimateLCQLQuery(query string) (*lc.QueryValidationResult, error) {
	if m.validateAndEstimateFunc != nil {
		return m.validateAndEstimateFunc(query)
	}
	return &lc.QueryValidationResult{
		Validation:      &lc.ValidationResponse{},
		BillingEstimate: &lc.BillingEstimate{},
	}, nil
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
			validateAndEstimateFunc: func(query string) (*lc.QueryValidationResult, error) {
				return &lc.QueryValidationResult{
					Validation:      &lc.ValidationResponse{Error: ""},
					BillingEstimate: &lc.BillingEstimate{},
				}, nil
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
			validateAndEstimateFunc: func(query string) (*lc.QueryValidationResult, error) {
				return &lc.QueryValidationResult{
					Validation:      &lc.ValidationResponse{Error: "invalid filter syntax"},
					BillingEstimate: nil,
				}, nil
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
			validateAndEstimateFunc: func(query string) (*lc.QueryValidationResult, error) {
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
			validateAndEstimateFunc: func(query string) (*lc.QueryValidationResult, error) {
				receivedQuery = query
				return &lc.QueryValidationResult{
					Validation:      &lc.ValidationResponse{},
					BillingEstimate: &lc.BillingEstimate{},
				}, nil
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

	t.Run("valid query returns full result with billing estimates", func(t *testing.T) {
		mock := &mockLCQLValidator{
			validateAndEstimateFunc: func(query string) (*lc.QueryValidationResult, error) {
				return &lc.QueryValidationResult{
					Validation: &lc.ValidationResponse{Error: ""},
					BillingEstimate: &lc.BillingEstimate{
						BilledEvents: 93698021,
						FreeEvents:   4319347,
						EstimatedPrice: lc.EstimatedPrice{
							Price:    46849.01,
							Currency: "USD cents",
						},
					},
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
		if result.BilledEvents != 93698021 {
			t.Errorf("expected BilledEvents=93698021, got %d", result.BilledEvents)
		}
		if result.FreeEvents != 4319347 {
			t.Errorf("expected FreeEvents=4319347, got %d", result.FreeEvents)
		}
		// Price should be converted from cents to USD (46849.01 cents = $468.4901 USD)
		expectedPrice := 468.4901
		if !floatEquals(result.EstimatedPriceUSD, expectedPrice, 0.0001) {
			t.Errorf("expected EstimatedPriceUSD=%f, got %f", expectedPrice, result.EstimatedPriceUSD)
		}
	})

	t.Run("valid query with non-cents currency", func(t *testing.T) {
		mock := &mockLCQLValidator{
			validateAndEstimateFunc: func(query string) (*lc.QueryValidationResult, error) {
				return &lc.QueryValidationResult{
					Validation: &lc.ValidationResponse{Error: ""},
					BillingEstimate: &lc.BillingEstimate{
						BilledEvents: 1000,
						FreeEvents:   500,
						EstimatedPrice: lc.EstimatedPrice{
							Price:    10.50,
							Currency: "USD",
						},
					},
				}, nil
			},
		}

		result := ValidateLCQLQueryFull(mock, "-1h | * | * | / exists")

		if !result.Valid {
			t.Error("expected Valid to be true")
		}
		// Price should be used as-is when not in cents
		if !floatEquals(result.EstimatedPriceUSD, 10.50, 0.0001) {
			t.Errorf("expected EstimatedPriceUSD=10.50, got %f", result.EstimatedPriceUSD)
		}
	})

	t.Run("valid query with nil billing estimate", func(t *testing.T) {
		mock := &mockLCQLValidator{
			validateAndEstimateFunc: func(query string) (*lc.QueryValidationResult, error) {
				return &lc.QueryValidationResult{
					Validation:      &lc.ValidationResponse{Error: ""},
					BillingEstimate: nil,
				}, nil
			},
		}

		result := ValidateLCQLQueryFull(mock, "-1h | * | * | / exists")

		if !result.Valid {
			t.Error("expected Valid to be true")
		}
		// Billing fields should be zero when estimate is nil
		if result.BilledEvents != 0 {
			t.Errorf("expected BilledEvents=0, got %d", result.BilledEvents)
		}
		if result.FreeEvents != 0 {
			t.Errorf("expected FreeEvents=0, got %d", result.FreeEvents)
		}
		if !floatEquals(result.EstimatedPriceUSD, 0, 0.0001) {
			t.Errorf("expected EstimatedPriceUSD=0, got %f", result.EstimatedPriceUSD)
		}
	})

	t.Run("invalid query returns error without billing estimates", func(t *testing.T) {
		mock := &mockLCQLValidator{
			validateAndEstimateFunc: func(query string) (*lc.QueryValidationResult, error) {
				return &lc.QueryValidationResult{
					Validation:      &lc.ValidationResponse{Error: "invalid syntax"},
					BillingEstimate: nil,
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
	})

	t.Run("API error returns error result", func(t *testing.T) {
		mock := &mockLCQLValidator{
			validateAndEstimateFunc: func(query string) (*lc.QueryValidationResult, error) {
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

func TestEstimateLCQLQueryBilling(t *testing.T) {
	t.Run("empty query returns error", func(t *testing.T) {
		mock := &mockLCQLValidator{}

		_, err := EstimateLCQLQueryBilling(mock, "")

		if err == nil {
			t.Error("expected error for empty query")
		}
		if err.Error() != "query is empty" {
			t.Errorf("expected error 'query is empty', got '%s'", err.Error())
		}
	})

	t.Run("valid query returns billing estimate", func(t *testing.T) {
		mock := &mockLCQLValidator{
			estimateBillingFunc: func(query string) (*lc.BillingEstimate, error) {
				return &lc.BillingEstimate{
					BilledEvents: 50000,
					FreeEvents:   10000,
					EstimatedPrice: lc.EstimatedPrice{
						Price:    25.0,
						Currency: "USD cents",
					},
				}, nil
			},
		}

		estimate, err := EstimateLCQLQueryBilling(mock, "-1h | * | * | / exists")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if estimate.BilledEvents != 50000 {
			t.Errorf("expected BilledEvents=50000, got %d", estimate.BilledEvents)
		}
		if estimate.FreeEvents != 10000 {
			t.Errorf("expected FreeEvents=10000, got %d", estimate.FreeEvents)
		}
	})

	t.Run("API error is propagated", func(t *testing.T) {
		mock := &mockLCQLValidator{
			estimateBillingFunc: func(query string) (*lc.BillingEstimate, error) {
				return nil, errors.New("API unavailable")
			},
		}

		_, err := EstimateLCQLQueryBilling(mock, "-1h | * | * | / exists")

		if err == nil {
			t.Error("expected error when API returns error")
		}
		if err.Error() != "API unavailable" {
			t.Errorf("expected error 'API unavailable', got '%s'", err.Error())
		}
	})

	t.Run("query is passed to estimator", func(t *testing.T) {
		var receivedQuery string
		mock := &mockLCQLValidator{
			estimateBillingFunc: func(query string) (*lc.BillingEstimate, error) {
				receivedQuery = query
				return &lc.BillingEstimate{}, nil
			},
		}

		testQuery := "-7d | plat == linux | DNS_REQUEST | event/DOMAIN_NAME ends_with '.evil.com'"
		EstimateLCQLQueryBilling(mock, testQuery)

		if receivedQuery != testQuery {
			t.Errorf("expected query '%s' to be passed to estimator, got '%s'", testQuery, receivedQuery)
		}
	})
}
