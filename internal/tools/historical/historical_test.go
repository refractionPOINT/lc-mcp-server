package historical

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/refractionpoint/lc-mcp-go/internal/tools/testutil"
)

func TestParseTimeframe(t *testing.T) {
	// LCQL only supports hours (h) and minutes (m), not days (d)
	t.Run("no timeframe", func(t *testing.T) {
		gotHas, gotDays, err := parseTimeframe("plat == windows | * | event/* contains 'psexec'")
		if err != nil {
			t.Errorf("parseTimeframe() unexpected error: %v", err)
		}
		if gotHas != false {
			t.Errorf("parseTimeframe() gotHas = %v, want false", gotHas)
		}
		if gotDays != 0 {
			t.Errorf("parseTimeframe() gotDays = %v, want 0", gotDays)
		}
	})

	t.Run("720 hours (30 days)", func(t *testing.T) {
		gotHas, gotDays, err := parseTimeframe("-720h | plat == windows | * | event/* contains 'psexec'")
		if err != nil {
			t.Errorf("parseTimeframe() unexpected error: %v", err)
		}
		if gotHas != true {
			t.Errorf("parseTimeframe() gotHas = %v, want true", gotHas)
		}
		if !floatEquals(gotDays, 30, 0.0001) {
			t.Errorf("parseTimeframe() gotDays = %v, want 30", gotDays)
		}
	})

	t.Run("168 hours (7 days)", func(t *testing.T) {
		gotHas, gotDays, err := parseTimeframe("-168h | plat == windows | * | event/* contains 'psexec'")
		if err != nil {
			t.Errorf("parseTimeframe() unexpected error: %v", err)
		}
		if gotHas != true {
			t.Errorf("parseTimeframe() gotHas = %v, want true", gotHas)
		}
		if !floatEquals(gotDays, 7, 0.0001) {
			t.Errorf("parseTimeframe() gotDays = %v, want 7", gotDays)
		}
	})

	t.Run("24 hours (1 day)", func(t *testing.T) {
		gotHas, gotDays, err := parseTimeframe("-24h | plat == windows | * | event/* contains 'psexec'")
		if err != nil {
			t.Errorf("parseTimeframe() unexpected error: %v", err)
		}
		if gotHas != true {
			t.Errorf("parseTimeframe() gotHas = %v, want true", gotHas)
		}
		if !floatEquals(gotDays, 1, 0.0001) {
			t.Errorf("parseTimeframe() gotDays = %v, want 1", gotDays)
		}
	})

	t.Run("48 hours (2 days)", func(t *testing.T) {
		gotHas, gotDays, err := parseTimeframe("-48h | plat == windows | * | event/* contains 'psexec'")
		if err != nil {
			t.Errorf("parseTimeframe() unexpected error: %v", err)
		}
		if gotHas != true {
			t.Errorf("parseTimeframe() gotHas = %v, want true", gotHas)
		}
		if !floatEquals(gotDays, 2, 0.0001) {
			t.Errorf("parseTimeframe() gotDays = %v, want 2", gotDays)
		}
	})

	t.Run("30 minutes", func(t *testing.T) {
		gotHas, gotDays, err := parseTimeframe("-30m | plat == windows | * | event/* contains 'psexec'")
		if err != nil {
			t.Errorf("parseTimeframe() unexpected error: %v", err)
		}
		if gotHas != true {
			t.Errorf("parseTimeframe() gotHas = %v, want true", gotHas)
		}
		expectedDays := 30.0 / (60 * 24) // 0.0208333...
		if !floatEquals(gotDays, expectedDays, 0.0001) {
			t.Errorf("parseTimeframe() gotDays = %v, want %v", gotDays, expectedDays)
		}
	})

	t.Run("1440 hours (60 days)", func(t *testing.T) {
		gotHas, gotDays, err := parseTimeframe("-1440h | plat == windows | * | event/* contains 'psexec'")
		if err != nil {
			t.Errorf("parseTimeframe() unexpected error: %v", err)
		}
		if gotHas != true {
			t.Errorf("parseTimeframe() gotHas = %v, want true", gotHas)
		}
		if !floatEquals(gotDays, 60, 0.0001) {
			t.Errorf("parseTimeframe() gotDays = %v, want 60", gotDays)
		}
	})

	t.Run("timeframe without pipe separator", func(t *testing.T) {
		gotHas, gotDays, err := parseTimeframe("-168h plat == windows | * | event/* contains 'psexec'")
		if err != nil {
			t.Errorf("parseTimeframe() unexpected error: %v", err)
		}
		if gotHas != true {
			t.Errorf("parseTimeframe() gotHas = %v, want true", gotHas)
		}
		if !floatEquals(gotDays, 7, 0.0001) {
			t.Errorf("parseTimeframe() gotDays = %v, want 7", gotDays)
		}
	})

	t.Run("days suffix not supported - treated as no timeframe", func(t *testing.T) {
		// LCQL doesn't support 'd' suffix, so it should not match
		gotHas, _, err := parseTimeframe("-30d | plat == windows | * | event/* contains 'psexec'")
		if err != nil {
			t.Errorf("parseTimeframe() unexpected error: %v", err)
		}
		if gotHas != false {
			t.Errorf("parseTimeframe() gotHas = %v, want false (d suffix not supported)", gotHas)
		}
	})
}

func TestValidateAndPrepareQuery(t *testing.T) {
	// LCQL only supports hours (h) and minutes (m), not days (d)
	t.Run("no timeframe - adds -720h (30 days)", func(t *testing.T) {
		got, err := validateAndPrepareQuery("plat == windows | * | event/* contains 'psexec'")
		if err != nil {
			t.Errorf("validateAndPrepareQuery() unexpected error: %v", err)
		}
		want := "-720h | plat == windows | * | event/* contains 'psexec'"
		if got != want {
			t.Errorf("validateAndPrepareQuery() = %v, want %v", got, want)
		}
	})

	t.Run("168 hours (7 days) - allowed", func(t *testing.T) {
		query := "-168h | plat == windows | * | event/* contains 'psexec'"
		got, err := validateAndPrepareQuery(query)
		if err != nil {
			t.Errorf("validateAndPrepareQuery() unexpected error: %v", err)
		}
		if got != query {
			t.Errorf("validateAndPrepareQuery() = %v, want %v", got, query)
		}
	})

	t.Run("720 hours (30 days) - allowed", func(t *testing.T) {
		query := "-720h | plat == windows | * | event/* contains 'psexec'"
		got, err := validateAndPrepareQuery(query)
		if err != nil {
			t.Errorf("validateAndPrepareQuery() unexpected error: %v", err)
		}
		if got != query {
			t.Errorf("validateAndPrepareQuery() = %v, want %v", got, query)
		}
	})

	t.Run("24 hours - allowed", func(t *testing.T) {
		query := "-24h | plat == windows | * | event/* contains 'psexec'"
		got, err := validateAndPrepareQuery(query)
		if err != nil {
			t.Errorf("validateAndPrepareQuery() unexpected error: %v", err)
		}
		if got != query {
			t.Errorf("validateAndPrepareQuery() = %v, want %v", got, query)
		}
	})

	t.Run("1440 hours (60 days) - rejected", func(t *testing.T) {
		_, err := validateAndPrepareQuery("-1440h | plat == windows | * | event/* contains 'psexec'")
		if err == nil {
			t.Error("validateAndPrepareQuery() expected error for >30 days timeframe")
		}
	})

	t.Run("744 hours (31 days) - rejected", func(t *testing.T) {
		_, err := validateAndPrepareQuery("-744h | plat == windows | * | event/* contains 'psexec'")
		if err == nil {
			t.Error("validateAndPrepareQuery() expected error for >30 days timeframe")
		}
	})

	t.Run("721 hours (>30 days) - rejected", func(t *testing.T) {
		_, err := validateAndPrepareQuery("-721h | plat == windows | * | event/* contains 'psexec'")
		if err == nil {
			t.Error("validateAndPrepareQuery() expected error for >30 days timeframe")
		}
	})

	t.Run("days suffix treated as no timeframe - adds -720h", func(t *testing.T) {
		// Since LCQL doesn't support 'd' suffix, it's treated as no timeframe
		got, err := validateAndPrepareQuery("-30d | plat == windows | * | event/* contains 'psexec'")
		if err != nil {
			t.Errorf("validateAndPrepareQuery() unexpected error: %v", err)
		}
		// The -30d is not recognized as timeframe, so -720h is prepended
		want := "-720h | -30d | plat == windows | * | event/* contains 'psexec'"
		if got != want {
			t.Errorf("validateAndPrepareQuery() = %v, want %v", got, want)
		}
	})
}

// Helper function for floating point comparison
func floatEquals(a, b, epsilon float64) bool {
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return diff < epsilon
}

// setupTestContext creates a context with auth for testing.
func setupTestContext() context.Context {
	authCtx := &auth.AuthContext{
		Mode:   auth.AuthModeNormal,
		OID:    "test-org",
		APIKey: "test-key",
	}
	return auth.WithAuthContext(context.Background(), authCtx)
}

// extractResultText extracts the text content from an MCP CallToolResult.
//
// Parameters:
//   - result: The MCP CallToolResult to extract text from
//
// Returns:
//   - string: The extracted text content
//   - bool: Whether extraction was successful
func extractResultText(result *mcp.CallToolResult) (string, bool) {
	if len(result.Content) == 0 {
		return "", false
	}
	if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
		return textContent.Text, true
	}
	return "", false
}

func TestValidateLCQLQueryTool(t *testing.T) {
	t.Run("missing query parameter returns error", func(t *testing.T) {
		ctx := setupTestContext()
		mock := &testutil.MockOrganization{}
		ctx = tools.WithOrganizationClient(ctx, mock)

		reg, ok := tools.GetTool("validate_lcql_query")
		if !ok {
			t.Fatal("validate_lcql_query tool not registered")
		}

		// Call with missing query
		result, err := reg.Handler(ctx, map[string]any{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		text, ok := extractResultText(result)
		if !ok {
			t.Fatal("failed to extract result text")
		}

		// Should be an error result
		if result.IsError != true {
			t.Error("expected IsError to be true for missing query")
		}
		if text != "query parameter is required" {
			t.Errorf("expected 'query parameter is required', got '%s'", text)
		}
	})

	t.Run("empty query parameter returns error", func(t *testing.T) {
		ctx := setupTestContext()
		mock := &testutil.MockOrganization{}
		ctx = tools.WithOrganizationClient(ctx, mock)

		reg, ok := tools.GetTool("validate_lcql_query")
		if !ok {
			t.Fatal("validate_lcql_query tool not registered")
		}

		// Call with empty query
		result, err := reg.Handler(ctx, map[string]any{
			"query": "",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		text, ok := extractResultText(result)
		if !ok {
			t.Fatal("failed to extract result text")
		}

		if result.IsError != true {
			t.Error("expected IsError to be true for empty query")
		}
		if text != "query parameter is required" {
			t.Errorf("expected 'query parameter is required', got '%s'", text)
		}
	})

	t.Run("valid query returns success with valid=true", func(t *testing.T) {
		ctx := setupTestContext()
		mock := &testutil.MockOrganization{
			ValidateAndEstimateLCQLQueryFunc: func(query string) (*lc.QueryValidationResult, error) {
				return &lc.QueryValidationResult{
					Validation:      &lc.ValidationResponse{Error: ""},
					BillingEstimate: &lc.BillingEstimate{},
				}, nil
			},
		}
		ctx = tools.WithOrganizationClient(ctx, mock)

		reg, ok := tools.GetTool("validate_lcql_query")
		if !ok {
			t.Fatal("validate_lcql_query tool not registered")
		}

		testQuery := "-1h | * | * | / exists"
		result, err := reg.Handler(ctx, map[string]any{
			"query": testQuery,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		text, ok := extractResultText(result)
		if !ok {
			t.Fatal("failed to extract result text")
		}

		var resultData map[string]any
		if err := json.Unmarshal([]byte(text), &resultData); err != nil {
			t.Fatalf("failed to parse result JSON: %v", err)
		}

		if resultData["valid"] != true {
			t.Error("expected valid=true")
		}
		if resultData["query"] != testQuery {
			t.Errorf("expected query='%s', got '%v'", testQuery, resultData["query"])
		}
		// Should not have error field for valid queries
		if _, hasError := resultData["error"]; hasError {
			t.Error("expected no error field for valid query")
		}
	})

	t.Run("invalid query returns success with valid=false and error message", func(t *testing.T) {
		ctx := setupTestContext()
		mock := &testutil.MockOrganization{
			ValidateAndEstimateLCQLQueryFunc: func(query string) (*lc.QueryValidationResult, error) {
				return &lc.QueryValidationResult{
					Validation: &lc.ValidationResponse{Error: "invalid filter syntax at position 10"},
				}, nil
			},
		}
		ctx = tools.WithOrganizationClient(ctx, mock)

		reg, ok := tools.GetTool("validate_lcql_query")
		if !ok {
			t.Fatal("validate_lcql_query tool not registered")
		}

		testQuery := "-1h | * | limit:10"
		result, err := reg.Handler(ctx, map[string]any{
			"query": testQuery,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		text, ok := extractResultText(result)
		if !ok {
			t.Fatal("failed to extract result text")
		}

		var resultData map[string]any
		if err := json.Unmarshal([]byte(text), &resultData); err != nil {
			t.Fatalf("failed to parse result JSON: %v", err)
		}

		if resultData["valid"] != false {
			t.Error("expected valid=false for invalid query")
		}
		if resultData["query"] != testQuery {
			t.Errorf("expected query='%s', got '%v'", testQuery, resultData["query"])
		}
		if resultData["error"] != "invalid filter syntax at position 10" {
			t.Errorf("expected error message, got '%v'", resultData["error"])
		}
	})

	t.Run("API error returns success with valid=false and validation error", func(t *testing.T) {
		ctx := setupTestContext()
		mock := &testutil.MockOrganization{
			ValidateAndEstimateLCQLQueryFunc: func(query string) (*lc.QueryValidationResult, error) {
				return nil, errors.New("connection timeout")
			},
		}
		ctx = tools.WithOrganizationClient(ctx, mock)

		reg, ok := tools.GetTool("validate_lcql_query")
		if !ok {
			t.Fatal("validate_lcql_query tool not registered")
		}

		testQuery := "-1h | * | * | / exists"
		result, err := reg.Handler(ctx, map[string]any{
			"query": testQuery,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		text, ok := extractResultText(result)
		if !ok {
			t.Fatal("failed to extract result text")
		}

		var resultData map[string]any
		if err := json.Unmarshal([]byte(text), &resultData); err != nil {
			t.Fatalf("failed to parse result JSON: %v", err)
		}

		if resultData["valid"] != false {
			t.Error("expected valid=false when API returns error")
		}
		errorMsg, ok := resultData["error"].(string)
		if !ok {
			t.Fatal("expected error field to be string")
		}
		if errorMsg != "validation error: connection timeout" {
			t.Errorf("expected 'validation error: connection timeout', got '%s'", errorMsg)
		}
	})

	t.Run("query is passed correctly to validator", func(t *testing.T) {
		ctx := setupTestContext()
		var receivedQuery string
		mock := &testutil.MockOrganization{
			ValidateAndEstimateLCQLQueryFunc: func(query string) (*lc.QueryValidationResult, error) {
				receivedQuery = query
				return &lc.QueryValidationResult{
					Validation:      &lc.ValidationResponse{Error: ""},
					BillingEstimate: &lc.BillingEstimate{},
				}, nil
			},
		}
		ctx = tools.WithOrganizationClient(ctx, mock)

		reg, ok := tools.GetTool("validate_lcql_query")
		if !ok {
			t.Fatal("validate_lcql_query tool not registered")
		}

		testQuery := "-24h | plat == windows | NEW_PROCESS | event/FILE_PATH contains 'cmd.exe'"
		_, err := reg.Handler(ctx, map[string]any{
			"query": testQuery,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if receivedQuery != testQuery {
			t.Errorf("expected query '%s' to be passed to validator, got '%s'", testQuery, receivedQuery)
		}
	})
}

func TestEstimateLCQLQueryTool(t *testing.T) {
	t.Run("missing query parameter returns error", func(t *testing.T) {
		ctx := setupTestContext()
		mock := &testutil.MockOrganization{}
		ctx = tools.WithOrganizationClient(ctx, mock)

		reg, ok := tools.GetTool("estimate_lcql_query")
		if !ok {
			t.Fatal("estimate_lcql_query tool not registered")
		}

		result, err := reg.Handler(ctx, map[string]any{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.IsError != true {
			t.Error("expected IsError to be true for missing query")
		}
	})

	t.Run("valid query returns estimates", func(t *testing.T) {
		ctx := setupTestContext()
		mock := &testutil.MockOrganization{
			ValidateAndEstimateLCQLQueryFunc: func(query string) (*lc.QueryValidationResult, error) {
				return &lc.QueryValidationResult{
					Validation: &lc.ValidationResponse{
						Error:     "",
						NumEvals:  1500,
						NumEvents: 750,
						EvalTime:  3.2,
					},
					BillingEstimate: &lc.BillingEstimate{
						BilledEvents: 50000,
						FreeEvents:   10000,
						EstimatedPrice: lc.EstimatedPrice{
							Price:    25.0,
							Currency: "USD cents",
						},
					},
				}, nil
			},
		}
		ctx = tools.WithOrganizationClient(ctx, mock)

		reg, ok := tools.GetTool("estimate_lcql_query")
		if !ok {
			t.Fatal("estimate_lcql_query tool not registered")
		}

		testQuery := "-1h | * | * | / exists"
		result, err := reg.Handler(ctx, map[string]any{
			"query": testQuery,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.IsError {
			t.Error("expected IsError to be false for valid query")
		}

		text, ok := extractResultText(result)
		if !ok {
			t.Fatal("failed to extract result text")
		}

		var resultData map[string]any
		if err := json.Unmarshal([]byte(text), &resultData); err != nil {
			t.Fatalf("failed to parse result JSON: %v", err)
		}

		if resultData["query"] != testQuery {
			t.Errorf("expected query='%s', got '%v'", testQuery, resultData["query"])
		}
		// Check D&R validation fields
		if resultData["num_evals"].(float64) != 1500 {
			t.Errorf("expected num_evals=1500, got %v", resultData["num_evals"])
		}
		if resultData["num_events"].(float64) != 750 {
			t.Errorf("expected num_events=750, got %v", resultData["num_events"])
		}
		if resultData["eval_time"].(float64) != 3.2 {
			t.Errorf("expected eval_time=3.2, got %v", resultData["eval_time"])
		}
		// Check billing estimate fields
		if resultData["billed_events"].(float64) != 50000 {
			t.Errorf("expected billed_events=50000, got %v", resultData["billed_events"])
		}
		if resultData["free_events"].(float64) != 10000 {
			t.Errorf("expected free_events=10000, got %v", resultData["free_events"])
		}
	})

	t.Run("invalid query returns error", func(t *testing.T) {
		ctx := setupTestContext()
		mock := &testutil.MockOrganization{
			ValidateAndEstimateLCQLQueryFunc: func(query string) (*lc.QueryValidationResult, error) {
				return &lc.QueryValidationResult{
					Validation: &lc.ValidationResponse{Error: "syntax error"},
				}, nil
			},
		}
		ctx = tools.WithOrganizationClient(ctx, mock)

		reg, ok := tools.GetTool("estimate_lcql_query")
		if !ok {
			t.Fatal("estimate_lcql_query tool not registered")
		}

		result, err := reg.Handler(ctx, map[string]any{
			"query": "-1h | invalid",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Estimate tool returns error for invalid queries
		if result.IsError != true {
			t.Error("expected IsError to be true for invalid query")
		}

		text, ok := extractResultText(result)
		if !ok {
			t.Fatal("failed to extract result text")
		}
		if text != "invalid query: syntax error" {
			t.Errorf("expected 'invalid query: syntax error', got '%s'", text)
		}
	})
}

func TestAnalyzeLCQLQueryTool(t *testing.T) {
	t.Run("missing query parameter returns error", func(t *testing.T) {
		ctx := setupTestContext()
		mock := &testutil.MockOrganization{}
		ctx = tools.WithOrganizationClient(ctx, mock)

		reg, ok := tools.GetTool("analyze_lcql_query")
		if !ok {
			t.Fatal("analyze_lcql_query tool not registered")
		}

		result, err := reg.Handler(ctx, map[string]any{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.IsError != true {
			t.Error("expected IsError to be true for missing query")
		}
	})

	t.Run("valid query returns validation and estimates", func(t *testing.T) {
		ctx := setupTestContext()
		mock := &testutil.MockOrganization{
			ValidateAndEstimateLCQLQueryFunc: func(query string) (*lc.QueryValidationResult, error) {
				return &lc.QueryValidationResult{
					Validation: &lc.ValidationResponse{
						Error:     "",
						NumEvals:  2000,
						NumEvents: 1000,
						EvalTime:  5.5,
					},
					BillingEstimate: &lc.BillingEstimate{
						BilledEvents: 100000,
						FreeEvents:   20000,
						EstimatedPrice: lc.EstimatedPrice{
							Price:    50.0,
							Currency: "USD cents",
						},
					},
				}, nil
			},
		}
		ctx = tools.WithOrganizationClient(ctx, mock)

		reg, ok := tools.GetTool("analyze_lcql_query")
		if !ok {
			t.Fatal("analyze_lcql_query tool not registered")
		}

		testQuery := "-1h | * | * | / exists"
		result, err := reg.Handler(ctx, map[string]any{
			"query": testQuery,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.IsError {
			t.Error("expected IsError to be false for valid query")
		}

		text, ok := extractResultText(result)
		if !ok {
			t.Fatal("failed to extract result text")
		}

		var resultData map[string]any
		if err := json.Unmarshal([]byte(text), &resultData); err != nil {
			t.Fatalf("failed to parse result JSON: %v", err)
		}

		// Check validation fields
		if resultData["valid"] != true {
			t.Error("expected valid=true")
		}
		if resultData["query"] != testQuery {
			t.Errorf("expected query='%s', got '%v'", testQuery, resultData["query"])
		}
		// Should not have error field for valid queries
		if _, hasError := resultData["error"]; hasError {
			t.Error("expected no error field for valid query")
		}

		// Check D&R validation estimates
		if resultData["num_evals"].(float64) != 2000 {
			t.Errorf("expected num_evals=2000, got %v", resultData["num_evals"])
		}
		if resultData["num_events"].(float64) != 1000 {
			t.Errorf("expected num_events=1000, got %v", resultData["num_events"])
		}
		if resultData["eval_time"].(float64) != 5.5 {
			t.Errorf("expected eval_time=5.5, got %v", resultData["eval_time"])
		}

		// Check billing estimates
		if resultData["billed_events"].(float64) != 100000 {
			t.Errorf("expected billed_events=100000, got %v", resultData["billed_events"])
		}
		if resultData["free_events"].(float64) != 20000 {
			t.Errorf("expected free_events=20000, got %v", resultData["free_events"])
		}
	})

	t.Run("invalid query returns validation error and estimates", func(t *testing.T) {
		ctx := setupTestContext()
		mock := &testutil.MockOrganization{
			ValidateAndEstimateLCQLQueryFunc: func(query string) (*lc.QueryValidationResult, error) {
				return &lc.QueryValidationResult{
					Validation: &lc.ValidationResponse{
						Error:     "invalid filter at position 5",
						NumEvals:  100,
						NumEvents: 50,
						EvalTime:  0.5,
					},
				}, nil
			},
		}
		ctx = tools.WithOrganizationClient(ctx, mock)

		reg, ok := tools.GetTool("analyze_lcql_query")
		if !ok {
			t.Fatal("analyze_lcql_query tool not registered")
		}

		testQuery := "-1h | invalid"
		result, err := reg.Handler(ctx, map[string]any{
			"query": testQuery,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Analyze tool returns success even for invalid queries (with valid=false)
		if result.IsError {
			t.Error("expected IsError to be false - analyze returns structured result")
		}

		text, ok := extractResultText(result)
		if !ok {
			t.Fatal("failed to extract result text")
		}

		var resultData map[string]any
		if err := json.Unmarshal([]byte(text), &resultData); err != nil {
			t.Fatalf("failed to parse result JSON: %v", err)
		}

		// Check validation fields
		if resultData["valid"] != false {
			t.Error("expected valid=false for invalid query")
		}
		if resultData["error"] != "invalid filter at position 5" {
			t.Errorf("expected error message, got '%v'", resultData["error"])
		}
	})

	t.Run("API error returns validation error", func(t *testing.T) {
		ctx := setupTestContext()
		mock := &testutil.MockOrganization{
			ValidateAndEstimateLCQLQueryFunc: func(query string) (*lc.QueryValidationResult, error) {
				return nil, errors.New("API unavailable")
			},
		}
		ctx = tools.WithOrganizationClient(ctx, mock)

		reg, ok := tools.GetTool("analyze_lcql_query")
		if !ok {
			t.Fatal("analyze_lcql_query tool not registered")
		}

		result, err := reg.Handler(ctx, map[string]any{
			"query": "-1h | * | * | / exists",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		text, ok := extractResultText(result)
		if !ok {
			t.Fatal("failed to extract result text")
		}

		var resultData map[string]any
		if err := json.Unmarshal([]byte(text), &resultData); err != nil {
			t.Fatalf("failed to parse result JSON: %v", err)
		}

		if resultData["valid"] != false {
			t.Error("expected valid=false when API returns error")
		}
		if resultData["error"] != "validation error: API unavailable" {
			t.Errorf("expected 'validation error: API unavailable', got '%v'", resultData["error"])
		}
	})
}
