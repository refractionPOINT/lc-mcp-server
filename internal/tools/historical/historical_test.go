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
	tests := []struct {
		name     string
		query    string
		wantHas  bool
		wantDays float64
		wantErr  bool
	}{
		{
			name:     "No timeframe",
			query:    "plat == windows | * | event/* contains 'psexec'",
			wantHas:  false,
			wantDays: 0,
			wantErr:  false,
		},
		{
			name:     "30 days",
			query:    "-30d | plat == windows | * | event/* contains 'psexec'",
			wantHas:  true,
			wantDays: 30,
			wantErr:  false,
		},
		{
			name:     "7 days",
			query:    "-7d | plat == windows | * | event/* contains 'psexec'",
			wantHas:  true,
			wantDays: 7,
			wantErr:  false,
		},
		{
			name:     "24 hours",
			query:    "-24h | plat == windows | * | event/* contains 'psexec'",
			wantHas:  true,
			wantDays: 1,
			wantErr:  false,
		},
		{
			name:     "48 hours",
			query:    "-48h | plat == windows | * | event/* contains 'psexec'",
			wantHas:  true,
			wantDays: 2,
			wantErr:  false,
		},
		{
			name:     "30 minutes",
			query:    "-30m | plat == windows | * | event/* contains 'psexec'",
			wantHas:  true,
			wantDays: 30.0 / (60 * 24), // 0.0208333...
			wantErr:  false,
		},
		{
			name:     "60 days",
			query:    "-60d | plat == windows | * | event/* contains 'psexec'",
			wantHas:  true,
			wantDays: 60,
			wantErr:  false,
		},
		{
			name:     "Timeframe without pipe",
			query:    "-7d plat == windows | * | event/* contains 'psexec'",
			wantHas:  true,
			wantDays: 7,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHas, gotDays, err := parseTimeframe(tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseTimeframe() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotHas != tt.wantHas {
				t.Errorf("parseTimeframe() gotHas = %v, want %v", gotHas, tt.wantHas)
			}
			// For days comparison, use a small epsilon for floating point comparison
			epsilon := 0.0001
			if gotHas && !floatEquals(gotDays, tt.wantDays, epsilon) {
				t.Errorf("parseTimeframe() gotDays = %v, want %v", gotDays, tt.wantDays)
			}
		})
	}
}

func TestValidateAndPrepareQuery(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		want    string
		wantErr bool
	}{
		{
			name:    "No timeframe - adds -30d",
			query:   "plat == windows | * | event/* contains 'psexec'",
			want:    "-30d | plat == windows | * | event/* contains 'psexec'",
			wantErr: false,
		},
		{
			name:    "7 days - allowed",
			query:   "-7d | plat == windows | * | event/* contains 'psexec'",
			want:    "-7d | plat == windows | * | event/* contains 'psexec'",
			wantErr: false,
		},
		{
			name:    "30 days - allowed",
			query:   "-30d | plat == windows | * | event/* contains 'psexec'",
			want:    "-30d | plat == windows | * | event/* contains 'psexec'",
			wantErr: false,
		},
		{
			name:    "24 hours - allowed",
			query:   "-24h | plat == windows | * | event/* contains 'psexec'",
			want:    "-24h | plat == windows | * | event/* contains 'psexec'",
			wantErr: false,
		},
		{
			name:    "60 days - rejected",
			query:   "-60d | plat == windows | * | event/* contains 'psexec'",
			want:    "",
			wantErr: true,
		},
		{
			name:    "31 days - rejected",
			query:   "-31d | plat == windows | * | event/* contains 'psexec'",
			want:    "",
			wantErr: true,
		},
		{
			name:    "720 hours (30 days) - allowed",
			query:   "-720h | plat == windows | * | event/* contains 'psexec'",
			want:    "-720h | plat == windows | * | event/* contains 'psexec'",
			wantErr: false,
		},
		{
			name:    "721 hours (>30 days) - rejected",
			query:   "-721h | plat == windows | * | event/* contains 'psexec'",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateAndPrepareQuery(tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateAndPrepareQuery() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("validateAndPrepareQuery() = %v, want %v", got, tt.want)
			}
		})
	}
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
			ValidateLCQLQueryFunc: func(query string) (*lc.ValidationResponse, error) {
				return &lc.ValidationResponse{Error: ""}, nil
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
			ValidateLCQLQueryFunc: func(query string) (*lc.ValidationResponse, error) {
				return &lc.ValidationResponse{Error: "invalid filter syntax at position 10"}, nil
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
			ValidateLCQLQueryFunc: func(query string) (*lc.ValidationResponse, error) {
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
			ValidateLCQLQueryFunc: func(query string) (*lc.ValidationResponse, error) {
				receivedQuery = query
				return &lc.ValidationResponse{Error: ""}, nil
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
			ValidateLCQLQueryFunc: func(query string) (*lc.ValidationResponse, error) {
				return &lc.ValidationResponse{
					Error:     "",
					NumEvals:  1500,
					NumEvents: 750,
					EvalTime:  3.2,
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
		// Check estimates are returned (JSON numbers are float64)
		if resultData["num_evals"].(float64) != 1500 {
			t.Errorf("expected num_evals=1500, got %v", resultData["num_evals"])
		}
		if resultData["num_events"].(float64) != 750 {
			t.Errorf("expected num_events=750, got %v", resultData["num_events"])
		}
		if resultData["eval_time"].(float64) != 3.2 {
			t.Errorf("expected eval_time=3.2, got %v", resultData["eval_time"])
		}
	})

	t.Run("invalid query returns error", func(t *testing.T) {
		ctx := setupTestContext()
		mock := &testutil.MockOrganization{
			ValidateLCQLQueryFunc: func(query string) (*lc.ValidationResponse, error) {
				return &lc.ValidationResponse{Error: "syntax error"}, nil
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
			ValidateLCQLQueryFunc: func(query string) (*lc.ValidationResponse, error) {
				return &lc.ValidationResponse{
					Error:     "",
					NumEvals:  2000,
					NumEvents: 1000,
					EvalTime:  5.5,
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

		// Check estimates
		if resultData["num_evals"].(float64) != 2000 {
			t.Errorf("expected num_evals=2000, got %v", resultData["num_evals"])
		}
		if resultData["num_events"].(float64) != 1000 {
			t.Errorf("expected num_events=1000, got %v", resultData["num_events"])
		}
		if resultData["eval_time"].(float64) != 5.5 {
			t.Errorf("expected eval_time=5.5, got %v", resultData["eval_time"])
		}
	})

	t.Run("invalid query returns validation error and estimates", func(t *testing.T) {
		ctx := setupTestContext()
		mock := &testutil.MockOrganization{
			ValidateLCQLQueryFunc: func(query string) (*lc.ValidationResponse, error) {
				return &lc.ValidationResponse{
					Error:     "invalid filter at position 5",
					NumEvals:  100,
					NumEvents: 50,
					EvalTime:  0.5,
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

		// Estimates should still be returned
		if resultData["num_evals"].(float64) != 100 {
			t.Errorf("expected num_evals=100, got %v", resultData["num_evals"])
		}
	})

	t.Run("API error returns validation error", func(t *testing.T) {
		ctx := setupTestContext()
		mock := &testutil.MockOrganization{
			ValidateLCQLQueryFunc: func(query string) (*lc.ValidationResponse, error) {
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
