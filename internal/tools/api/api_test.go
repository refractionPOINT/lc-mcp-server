package api

import (
	"context"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func TestToolRegistration(t *testing.T) {
	// Test that the tool is registered
	tool, ok := tools.GetTool("lc_api_call")
	if !ok {
		t.Fatal("lc_api_call tool not registered")
	}

	if tool.Name != "lc_api_call" {
		t.Errorf("Expected tool name 'lc_api_call', got '%s'", tool.Name)
	}

	if tool.Profile != "api_access" {
		t.Errorf("Expected profile 'api_access', got '%s'", tool.Profile)
	}

	if !tool.RequiresOID {
		t.Error("Expected RequiresOID to be true")
	}
}

func TestProfileDefinition(t *testing.T) {
	// Test that the api_access profile exists and contains lc_api_call
	profile := tools.GetToolsForProfile("api_access")
	if len(profile) == 0 {
		t.Fatal("api_access profile not found or empty")
	}

	found := false
	for _, toolName := range profile {
		if toolName == "lc_api_call" {
			found = true
			break
		}
	}

	if !found {
		t.Error("lc_api_call not found in api_access profile")
	}
}

func TestEndpointValidation(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    interface{}
		expectError string
	}{
		{"valid api endpoint", "api", ""},
		{"valid billing endpoint", "billing", ""},
		{"valid replay endpoint", "replay", ""}, // Valid endpoint (auth context error is expected, not validation error)
		{"uppercase API normalized", "API", ""},
		{"uppercase BILLING normalized", "BILLING", ""},
		{"uppercase REPLAY normalized", "REPLAY", ""}, // Valid endpoint after normalization
		{"invalid endpoint", "invalid", "endpoint must be one of: 'api', 'billing', or 'replay'"},
		{"empty endpoint", "", "endpoint parameter is required and must be a string"},
		{"missing endpoint", nil, "endpoint parameter is required and must be a string"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := map[string]interface{}{
				"method": "GET",
				"path":   "/test",
			}
			if tt.endpoint != nil {
				args["endpoint"] = tt.endpoint
			}

			// Call the actual handler
			result, err := handleLCAPICall(context.Background(), args)
			if err != nil {
				t.Fatalf("handler returned unexpected error: %v", err)
			}

			// Check if we got the expected error in the result
			if tt.expectError != "" {
				if !result.IsError {
					t.Errorf("Expected error for endpoint %v, but got success", tt.endpoint)
					return
				}
				// Verify error message contains expected text
				errorText := ""
				if len(result.Content) > 0 {
					if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
						errorText = textContent.Text
					}
				}
				if !strings.Contains(errorText, tt.expectError) {
					t.Errorf("Expected error containing %q, got %q", tt.expectError, errorText)
				}
			} else {
				// For valid endpoints without other issues, we expect auth context error
				// (since we don't have auth set up), which means endpoint validation passed
				if result.IsError {
					errorText := ""
					if len(result.Content) > 0 {
						if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
							errorText = textContent.Text
						}
					}
					// If we get an endpoint validation error, the test fails
					if strings.Contains(errorText, "endpoint must be") || strings.Contains(errorText, "endpoint parameter is required") {
						t.Errorf("Endpoint validation failed unexpectedly: %s", errorText)
					}
					// Other errors (like auth context) are expected and mean validation passed
				}
			}
		})
	}
}

func TestMethodValidation(t *testing.T) {
	tests := []struct {
		name        string
		method      interface{}
		expectError string
	}{
		// Valid methods
		{"valid GET method", "GET", ""},
		{"valid POST method", "POST", ""},
		{"valid PUT method", "PUT", ""},
		{"valid DELETE method", "DELETE", ""},
		{"valid PATCH method", "PATCH", ""},
		// Lowercase should be normalized to uppercase
		{"lowercase get normalized", "get", ""},
		{"lowercase post normalized", "post", ""},
		// Invalid methods
		{"invalid HEAD method", "HEAD", "method must be one of: GET, POST, PUT, DELETE, PATCH"},
		{"invalid OPTIONS method", "OPTIONS", "method must be one of: GET, POST, PUT, DELETE, PATCH"},
		{"invalid TRACE method", "TRACE", "method must be one of: GET, POST, PUT, DELETE, PATCH"},
		{"invalid CONNECT method", "CONNECT", "method must be one of: GET, POST, PUT, DELETE, PATCH"},
		{"empty method", "", "method parameter is required and must be a string"},
		{"missing method", nil, "method parameter is required and must be a string"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := map[string]interface{}{
				"endpoint": "api",
				"path":     "/test",
			}
			if tt.method != nil {
				args["method"] = tt.method
			}

			// Call the actual handler
			result, err := handleLCAPICall(context.Background(), args)
			if err != nil {
				t.Fatalf("handler returned unexpected error: %v", err)
			}

			// Check if we got the expected error in the result
			if tt.expectError != "" {
				if !result.IsError {
					t.Errorf("Expected error for method %v, but got success", tt.method)
					return
				}
				// Verify error message contains expected text
				errorText := ""
				if len(result.Content) > 0 {
					if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
						errorText = textContent.Text
					}
				}
				if !strings.Contains(errorText, tt.expectError) {
					t.Errorf("Expected error containing %q, got %q", tt.expectError, errorText)
				}
			} else {
				// For valid methods, we expect auth context error
				// (since we don't have auth set up), which means method validation passed
				if result.IsError {
					errorText := ""
					if len(result.Content) > 0 {
						if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
							errorText = textContent.Text
						}
					}
					// If we get a method validation error, the test fails
					if strings.Contains(errorText, "method must be") || strings.Contains(errorText, "method parameter is required") {
						t.Errorf("Method validation failed unexpectedly: %s", errorText)
					}
					// Other errors (like auth context) are expected and mean validation passed
				}
			}
		})
	}
}
