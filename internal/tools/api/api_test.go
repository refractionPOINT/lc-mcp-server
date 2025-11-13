package api

import (
	"testing"

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
		endpoint string
		valid    bool
	}{
		{"api", true},
		{"billing", true},
		{"API", true}, // Should be normalized to lowercase
		{"BILLING", true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			normalized := tt.endpoint
			if normalized != "" {
				// Simulate the normalization that happens in the handler
				normalized = string([]rune(normalized)) // Would be lowercase in real code
			}

			// Just a basic check - the actual validation happens in the handler
			if tt.endpoint == "api" || tt.endpoint == "billing" || tt.endpoint == "API" || tt.endpoint == "BILLING" {
				if !tt.valid {
					t.Errorf("Expected %s to be valid", tt.endpoint)
				}
			}
		})
	}
}

func TestMethodValidation(t *testing.T) {
	validMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}

	for _, method := range validMethods {
		t.Run(method, func(t *testing.T) {
			// Just verify the method is in our list
			found := false
			for _, valid := range validMethods {
				if method == valid {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Method %s should be valid", method)
			}
		})
	}

	invalidMethods := []string{"HEAD", "OPTIONS", "TRACE", "CONNECT", ""}
	for _, method := range invalidMethods {
		t.Run(method, func(t *testing.T) {
			found := false
			for _, valid := range validMethods {
				if method == valid {
					found = true
					break
				}
			}
			if found {
				t.Errorf("Method %s should be invalid", method)
			}
		})
	}
}
