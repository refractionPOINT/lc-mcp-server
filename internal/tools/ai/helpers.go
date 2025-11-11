package ai

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/generative-ai-go/genai"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"google.golang.org/api/option"
	"gopkg.in/yaml.v3"
)

const (
	// DefaultModel is the default Gemini model to use
	DefaultModel = "gemini-2.5-flash"
	// LiteModel is the lite version of Gemini
	LiteModel = "gemini-2.5-flash-lite"
	// DefaultRetryCount is the default number of retries for YAML parsing/validation
	DefaultRetryCount = 10
)

// GetRetryCount returns the configured retry count from environment or default
func GetRetryCount() int {
	if count := os.Getenv("LLM_YAML_RETRY_COUNT"); count != "" {
		var retryCount int
		fmt.Sscanf(count, "%d", &retryCount)
		if retryCount > 0 && retryCount <= 50 {
			return retryCount
		}
	}
	return DefaultRetryCount
}

// getPromptTemplate reads a prompt template from the prompts directory
func getPromptTemplate(promptName string) (string, error) {
	// Get the path to the prompts directory (relative to project root)
	promptPath := filepath.Join("prompts", promptName+".txt")

	// Try to read from current directory first
	content, err := os.ReadFile(promptPath)
	if err != nil {
		// Try from executable directory
		ex, exErr := os.Executable()
		if exErr == nil {
			exDir := filepath.Dir(ex)
			promptPath = filepath.Join(exDir, "prompts", promptName+".txt")
			content, err = os.ReadFile(promptPath)
		}
	}

	if err != nil {
		return "", fmt.Errorf("failed to read prompt template %s: %w", promptName, err)
	}

	return strings.TrimSpace(string(content)), nil
}

// geminiResponse gets a response from Gemini API
func geminiResponse(ctx context.Context, messages []map[string]interface{}, systemPrompt string, modelName string, temperature float32) (string, error) {
	startTime := time.Now()
	defer func() {
		elapsed := time.Since(startTime)
		fmt.Printf("Gemini response time: %v\n", elapsed)
	}()

	// Get API key from environment
	apiKey := os.Getenv("GOOGLE_API_KEY")
	if apiKey == "" {
		return "", fmt.Errorf("GOOGLE_API_KEY environment variable not set")
	}

	// Create client
	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		return "", fmt.Errorf("failed to create Gemini client: %w", err)
	}
	defer client.Close()

	// Get the model
	model := client.GenerativeModel(modelName)

	// Set temperature
	model.Temperature = &temperature

	// Set system instruction if provided
	if systemPrompt != "" {
		model.SystemInstruction = &genai.Content{
			Parts: []genai.Part{genai.Text(systemPrompt)},
		}
	}

	// Start chat session
	cs := model.StartChat()

	// Add message history (excluding the last user message which we'll send separately)
	for i := 0; i < len(messages)-1; i++ {
		msg := messages[i]
		role, ok := msg["role"].(string)
		if !ok {
			continue
		}

		parts, ok := msg["parts"].([]interface{})
		if !ok {
			continue
		}

		var genaiParts []genai.Part
		for _, part := range parts {
			if partMap, ok := part.(map[string]interface{}); ok {
				if text, ok := partMap["text"].(string); ok {
					genaiParts = append(genaiParts, genai.Text(text))
				}
			}
		}

		if len(genaiParts) == 0 {
			continue
		}

		// Map role to Gemini role
		genaiRole := "user"
		if role == "model" {
			genaiRole = "model"
		}

		cs.History = append(cs.History, &genai.Content{
			Parts: genaiParts,
			Role:  genaiRole,
		})
	}

	// Get the last message (the current prompt)
	lastMsg := messages[len(messages)-1]
	parts, ok := lastMsg["parts"].([]interface{})
	if !ok || len(parts) == 0 {
		return "", fmt.Errorf("invalid message format")
	}

	var genaiParts []genai.Part
	for _, part := range parts {
		if partMap, ok := part.(map[string]interface{}); ok {
			if text, ok := partMap["text"].(string); ok {
				genaiParts = append(genaiParts, genai.Text(text))
			}
		}
	}

	// Send message and get response
	resp, err := cs.SendMessage(ctx, genaiParts...)
	if err != nil {
		return "", fmt.Errorf("failed to get Gemini response: %w", err)
	}

	// Extract text from response
	if len(resp.Candidates) == 0 || len(resp.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("empty response from Gemini")
	}

	var responseText strings.Builder
	for _, part := range resp.Candidates[0].Content.Parts {
		if text, ok := part.(genai.Text); ok {
			responseText.WriteString(string(text))
		}
	}

	return strings.TrimSpace(responseText.String()), nil
}

// validateLCQLQuery validates an LCQL query using the SDK
func validateLCQLQuery(org *lc.Organization, query string) (bool, string) {
	if query == "" {
		return false, "query is empty"
	}

	// Use SDK's LCQL validation via replay service
	resp, err := org.ValidateLCQLQuery(query)
	if err != nil {
		return false, fmt.Sprintf("validation error: %v", err)
	}

	// Check if validation found an error
	if resp.Error != "" {
		return false, resp.Error
	}

	return true, ""
}

// validateDRRule validates a D&R rule using the SDK
func validateDRRule(org *lc.Organization, ruleYAML string) (bool, string) {
	// Parse the YAML to a Dict
	var rule lc.Dict
	if err := yaml.Unmarshal([]byte(ruleYAML), &rule); err != nil {
		return false, fmt.Sprintf("invalid YAML: %v", err)
	}

	// Use the dict-based validation
	return validateDRRuleDict(org, rule)
}

// validateDRRuleDict validates a D&R rule dict using the SDK
func validateDRRuleDict(org *lc.Organization, rule lc.Dict) (bool, string) {
	// Basic validation: should have either "detect" or "respond" or both
	hasDetect := rule["detect"] != nil
	hasRespond := rule["respond"] != nil

	if !hasDetect && !hasRespond {
		return false, "rule must have at least a 'detect' or 'respond' component"
	}

	// Use SDK's D&R validation via replay service
	resp, err := org.ValidateDRRule(rule)
	if err != nil {
		return false, fmt.Sprintf("validation error: %v", err)
	}

	// Check if validation found an error
	if resp.Error != "" {
		return false, resp.Error
	}

	return true, ""
}

// schemaTypeCodeToString converts a schema type code to a string
func schemaTypeCodeToString(code string) string {
	switch code {
	case "s":
		return "string"
	case "i":
		return "integer"
	case "f":
		return "float"
	case "b":
		return "boolean"
	default:
		return ""
	}
}

// interpretSchema interprets the schema returned from the API and returns a simplified version
func interpretSchema(schema map[string]interface{}) string {
	schemaMap, ok := schema["schema"].(map[string]interface{})
	if !ok {
		return ""
	}

	eventType, ok := schemaMap["event_type"].(string)
	if !ok {
		return ""
	}

	// Remove the "evt:" prefix if present
	parts := strings.SplitN(eventType, ":", 2)
	if len(parts) == 2 {
		eventType = parts[1]
	}

	output := fmt.Sprintf("Schema for %s:\nFieldsName\tFieldType\n", eventType)

	elements, ok := schemaMap["elements"].([]interface{})
	if !ok {
		return output
	}

	for _, elem := range elements {
		elemStr, ok := elem.(string)
		if !ok {
			continue
		}

		// Parse "type:fieldname" format
		parts := strings.SplitN(elemStr, ":", 2)
		if len(parts) != 2 {
			continue
		}

		typeCode := parts[0]
		fieldName := parts[1]
		typeName := schemaTypeCodeToString(typeCode)

		output += fmt.Sprintf("%s\t%s\n", fieldName, typeName)
	}

	return output
}

// getSchemaInfo fetches schema information from the SDK
func getSchemaInfo(ctx context.Context, org *lc.Organization) string {
	// Get all available schemas
	schemas, err := org.GetSchemas()
	if err != nil {
		fmt.Printf("Warning: failed to fetch schemas: %v\n", err)
		return "No schema available - extrapolate with best effort."
	}

	if schemas == nil || len(schemas.EventTypes) == 0 {
		return "No schema available - extrapolate with best effort."
	}

	// Build schema information
	// Provide a list of available event types rather than full schemas
	// to avoid overwhelming the prompt with too much data
	var schemaInfo strings.Builder
	schemaInfo.WriteString(fmt.Sprintf("Available event types (%d total):\n", len(schemas.EventTypes)))

	// Group into columns for readability
	for i, eventType := range schemas.EventTypes {
		// Remove "evt:" prefix if present for cleaner output
		cleanType := eventType
		if parts := strings.SplitN(eventType, ":", 2); len(parts) == 2 {
			cleanType = parts[1]
		}

		schemaInfo.WriteString(cleanType)

		// Add separator or newline
		if (i+1)%3 == 0 {
			schemaInfo.WriteString("\n")
		} else if i < len(schemas.EventTypes)-1 {
			schemaInfo.WriteString(", ")
		}
	}

	schemaInfo.WriteString("\n\nUse these event type names in your LCQL queries. ")
	schemaInfo.WriteString("Common fields across most events include: routing (with sid, oid, tags, etc.), ")
	schemaInfo.WriteString("event_type, ts (timestamp), and type-specific fields.")

	return schemaInfo.String()
}
