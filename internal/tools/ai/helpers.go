package ai

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"google.golang.org/genai"
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

// isDebugAIEnabled checks if DEBUG_AI environment variable is set
func isDebugAIEnabled() bool {
	value := strings.ToLower(os.Getenv("DEBUG_AI"))
	return value == "true" || value == "1" || value == "yes"
}

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

// ptr is a helper function to create a pointer to a value
func ptr[T any](v T) *T {
	return &v
}

// geminiResponse gets a response from Gemini API using the new official SDK
func geminiResponse(ctx context.Context, messages []map[string]interface{}, systemPrompt string, modelName string, temperature float32) (string, error) {
	startTime := time.Now()
	defer func() {
		elapsed := time.Since(startTime)
		slog.Debug("Gemini response time", "duration_ms", elapsed.Milliseconds())
	}()

	// Get API key from environment
	apiKey := os.Getenv("GOOGLE_API_KEY")
	if apiKey == "" {
		return "", fmt.Errorf("GOOGLE_API_KEY environment variable not set")
	}

	// Create client with new SDK
	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey:  apiKey,
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create Gemini client: %w", err)
	}

	// Build chat history for the new SDK
	var history []*genai.Content
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

		var genaiParts []*genai.Part
		for _, part := range parts {
			if partMap, ok := part.(map[string]interface{}); ok {
				if text, ok := partMap["text"].(string); ok {
					genaiParts = append(genaiParts, &genai.Part{Text: text})
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

		history = append(history, &genai.Content{
			Parts: genaiParts,
			Role:  genaiRole,
		})
	}

	// Prepare generation config
	config := &genai.GenerateContentConfig{
		Temperature: ptr(temperature),
	}

	// Set system instruction if provided
	if systemPrompt != "" {
		config.SystemInstruction = &genai.Content{
			Parts: []*genai.Part{{Text: systemPrompt}},
		}
	}

	// Create chat with history and config
	chat, err := client.Chats.Create(ctx, modelName, config, history)
	if err != nil {
		return "", fmt.Errorf("failed to create chat: %w", err)
	}

	// Get the last message (the current prompt)
	lastMsg := messages[len(messages)-1]
	parts, ok := lastMsg["parts"].([]interface{})
	if !ok || len(parts) == 0 {
		return "", fmt.Errorf("invalid message format")
	}

	var genaiParts []*genai.Part
	for _, part := range parts {
		if partMap, ok := part.(map[string]interface{}); ok {
			if text, ok := partMap["text"].(string); ok {
				genaiParts = append(genaiParts, &genai.Part{Text: text})
			}
		}
	}

	// Debug logging for AI prompts
	if isDebugAIEnabled() {
		slog.Info("DEBUG_AI: System Prompt", "prompt", systemPrompt)
		for i, part := range genaiParts {
			slog.Info("DEBUG_AI: User Message", "part_index", i, "text", part.Text)
		}
	}

	// Send message and get response
	resp, err := chat.Send(ctx, genaiParts...)
	if err != nil {
		return "", fmt.Errorf("failed to get Gemini response: %w", err)
	}

	// Extract text from response using the Text() method
	responseText := resp.Text()
	if responseText == "" {
		return "", fmt.Errorf("empty response from Gemini")
	}

	// Debug logging for AI response
	if isDebugAIEnabled() {
		slog.Info("DEBUG_AI: AI Response", "response", responseText)
	}

	return strings.TrimSpace(responseText), nil
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

// cleanYAMLResponse removes markdown formatting from AI-generated YAML
func cleanYAMLResponse(response string) string {
	// Remove markdown code fences and trim whitespace
	response = strings.TrimSpace(response)
	response = strings.ReplaceAll(response, "```yaml", "")
	response = strings.ReplaceAll(response, "```yml", "")
	response = strings.ReplaceAll(response, "```", "")
	return strings.TrimSpace(response)
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

// interpretSchema interprets the schema returned from the API and returns an LLM-optimized format
// The output format is designed to be easily parsed by LLMs and shows full event paths
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

	elements, ok := schemaMap["elements"].([]interface{})
	if !ok || len(elements) == 0 {
		return fmt.Sprintf("### %s\nNo fields available.\n", eventType)
	}

	// Build LLM-optimized output with markdown formatting
	var output strings.Builder
	output.WriteString(fmt.Sprintf("### Event: %s\n", eventType))
	output.WriteString(fmt.Sprintf("Use `event: %s` in D&R rules to match this event type.\n\n", eventType))
	output.WriteString("**Available fields:**\n")
	output.WriteString("| Path | Type |\n")
	output.WriteString("|------|------|\n")

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

		// Format path with event/ prefix for LLM clarity
		// This matches the path format used in D&R rules and LCQL queries
		fullPath := fmt.Sprintf("event/%s", fieldName)
		output.WriteString(fmt.Sprintf("| `%s` | %s |\n", fullPath, typeName))
	}

	output.WriteString("\n---\n")
	return output.String()
}

// getSchemaInfo fetches schema information from the SDK
// This is a fallback when smart schema extraction doesn't return specific schemas
func getSchemaInfo(ctx context.Context, org *lc.Organization, schemaType string) string {
	// Get all available schemas
	schemas, err := org.GetSchemas()
	if err != nil {
		slog.Warn("Failed to fetch schemas", "error", err)
		return "No schema available - use common event field patterns like `event/FILE_PATH`, `event/COMMAND_LINE`, etc."
	}

	if schemas == nil || len(schemas.EventTypes) == 0 {
		return "No schema available - use common event field patterns like `event/FILE_PATH`, `event/COMMAND_LINE`, etc."
	}

	// Build schema information with LLM-optimized formatting
	var schemaInfo strings.Builder

	eventTypes := []string{}
	for _, eventType := range schemas.EventTypes {
		if parts := strings.SplitN(eventType, ":", 2); len(parts) == 2 && (parts[0] == schemaType || schemaType == "") {
			eventTypes = append(eventTypes, parts[1])
		}
	}

	schemaInfo.WriteString("## Available Event Types\n\n")
	schemaInfo.WriteString(fmt.Sprintf("The following %d event types are available:\n\n", len(eventTypes)))

	// List event types in a cleaner format
	for i, et := range eventTypes {
		if i > 0 && i%10 == 0 {
			schemaInfo.WriteString("\n")
		}
		schemaInfo.WriteString(fmt.Sprintf("`%s` ", et))
	}

	schemaInfo.WriteString("\n\n## Path Usage Guidelines\n\n")
	schemaInfo.WriteString("Use paths with the `event/` prefix for event-specific fields:\n")
	schemaInfo.WriteString("- `event/FILE_PATH` - File path\n")
	schemaInfo.WriteString("- `event/COMMAND_LINE` - Command line arguments\n")
	schemaInfo.WriteString("- `event/PARENT/FILE_PATH` - Parent process path\n")
	schemaInfo.WriteString("- `event/DOMAIN_NAME` - DNS domain name\n")
	schemaInfo.WriteString("- `event/NETWORK_ACTIVITY/?/DESTINATION/IP_ADDRESS` - Network destination IP\n\n")
	schemaInfo.WriteString("Use `routing/` prefix for sensor metadata:\n")
	schemaInfo.WriteString("- `routing/hostname`, `routing/sid`, `routing/tags`\n")

	return schemaInfo.String()
}

// detectPlatform uses AI to identify the platform from a user query
// Returns the detected platform name or empty string if not detected
func detectPlatform(ctx context.Context, org *lc.Organization, userQuery string) string {
	// Add timeout for this operation
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Get available platform names
	platforms, err := org.GetPlatformNames()
	if err != nil {
		slog.Warn("Failed to fetch platform names", "error", err)
		return ""
	}

	if len(platforms) == 0 {
		return ""
	}

	// Load the platform detection prompt template
	promptTemplate, err := getPromptTemplate("gen_platform")
	if err != nil {
		slog.Warn("Failed to load platform detection prompt", "error", err)
		return ""
	}

	// Replace the platforms placeholder
	prompt := strings.Replace(promptTemplate, "{platforms}", strings.Join(platforms, ", "), -1)

	// Call Gemini with LiteModel for fast, cheap inference
	messages := []map[string]interface{}{
		{
			"role": "user",
			"parts": []interface{}{
				map[string]interface{}{"text": userQuery},
			},
		},
	}

	response, err := geminiResponse(ctx, messages, prompt, LiteModel, 0.0)
	if err != nil {
		slog.Warn("Failed to detect platform", "error", err)
		return ""
	}

	// Clean and validate the response
	detectedPlatform := strings.TrimSpace(response)

	// Verify the detected platform is in our list
	for _, p := range platforms {
		if strings.EqualFold(p, detectedPlatform) {
			slog.Debug("Platform detected", "platform", p, "query", userQuery)
			return p
		}
	}

	// Empty or invalid response means no platform detected
	slog.Debug("No platform detected", "query", userQuery)
	return ""
}

// selectRelevantEvents uses AI to select relevant event types for a query
// Returns a list of event type names that are relevant to the query
func selectRelevantEvents(ctx context.Context, org *lc.Organization, userQuery string, platform string) []string {
	// Add timeout for this operation
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Get schemas based on platform
	var schemas *lc.Schemas
	var err error

	if platform != "" {
		schemas, err = org.GetSchemasForPlatform(platform)
		if err != nil {
			slog.Warn("Failed to fetch platform schemas, falling back to all schemas", "platform", platform, "error", err)
			schemas, err = org.GetSchemas()
		}
	} else {
		schemas, err = org.GetSchemas()
	}

	if err != nil || schemas == nil || len(schemas.EventTypes) == 0 {
		slog.Warn("Failed to fetch schemas for event selection", "error", err)
		return nil
	}

	// Extract just the event names - ONLY actual event types (evt: prefix), not detections or other schemas
	eventNames := make([]string, 0, len(schemas.EventTypes))
	for _, eventType := range schemas.EventTypes {
		parts := strings.SplitN(eventType, ":", 2)
		if len(parts) == 2 && parts[0] == "evt" {
			eventNames = append(eventNames, parts[1])
		}
	}

	if len(eventNames) == 0 {
		slog.Warn("No event types found after filtering", "total_schemas", len(schemas.EventTypes))
		return nil
	}

	slog.Debug("Filtered event types for AI selection", "event_count", len(eventNames), "total_schemas", len(schemas.EventTypes))

	// Load the event selection prompt template
	promptTemplate, err := getPromptTemplate("gen_event_list")
	if err != nil {
		slog.Warn("Failed to load event selection prompt", "error", err)
		return nil
	}

	// Replace the events placeholder
	prompt := strings.Replace(promptTemplate, "{events}", strings.Join(eventNames, "\n"), -1)

	// Call Gemini with LiteModel for fast, cheap inference
	messages := []map[string]interface{}{
		{
			"role": "user",
			"parts": []interface{}{
				map[string]interface{}{"text": userQuery},
			},
		},
	}

	response, err := geminiResponse(ctx, messages, prompt, LiteModel, 0.0)
	if err != nil {
		slog.Warn("Failed to select relevant events", "error", err)
		return nil
	}

	// Parse the response - one event per line
	lines := strings.Split(response, "\n")
	selectedEvents := make([]string, 0, len(lines))

	// Create a map for quick lookup of valid event names
	validEvents := make(map[string]bool)
	for _, name := range eventNames {
		validEvents[name] = true
	}

	for _, line := range lines {
		eventName := strings.TrimSpace(line)
		if eventName == "" {
			continue
		}
		// Validate the event name exists
		if validEvents[eventName] {
			selectedEvents = append(selectedEvents, eventName)
		}
	}

	slog.Debug("Selected relevant events", "count", len(selectedEvents), "events", selectedEvents, "query", userQuery)
	return selectedEvents
}

// getEnhancedSchemaContext gets detailed schema information for selected events
// Returns a formatted string with event types and their field definitions
// Fetches all schemas in parallel for performance
func getEnhancedSchemaContext(ctx context.Context, org *lc.Organization, events []string) string {
	if len(events) == 0 {
		return ""
	}

	// Fetch all schemas in parallel
	type schemaResult struct {
		eventName string
		schema    *lc.SchemaResponse
		err       error
	}

	results := make(chan schemaResult, len(events))
	var wg sync.WaitGroup

	for _, eventName := range events {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			schema, err := org.GetSchema(name)
			results <- schemaResult{name, schema, err}
		}(eventName)
	}

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results into a map
	schemas := make(map[string]*lc.SchemaResponse)
	for result := range results {
		if result.err != nil {
			slog.Debug("Failed to fetch schema for event", "event", result.eventName, "error", result.err)
			continue
		}
		if result.schema != nil {
			schemas[result.eventName] = result.schema
		}
	}

	if len(schemas) == 0 {
		return ""
	}

	// Build output in original order for consistency
	var schemaInfo strings.Builder
	schemaInfo.WriteString("## Available Event Schemas\n\n")
	schemaInfo.WriteString(fmt.Sprintf("The following %d event types are relevant to your query. ", len(schemas)))
	schemaInfo.WriteString("Use the exact paths shown below in your rules and queries.\n\n")

	fetchedCount := 0
	for _, eventName := range events {
		schema, ok := schemas[eventName]
		if !ok {
			continue
		}

		// Convert to map for interpretSchema
		schemaMap := map[string]interface{}{
			"schema": map[string]interface{}{
				"event_type": schema.Schema.EventType,
				"elements":   convertElementsToInterface(schema.Schema.Elements),
			},
		}

		interpreted := interpretSchema(schemaMap)
		if interpreted != "" {
			schemaInfo.WriteString(interpreted)
			schemaInfo.WriteString("\n")
			fetchedCount++
		}
	}

	if fetchedCount == 0 {
		return ""
	}

	// Add clear guidance for LLM on how to use these paths
	schemaInfo.WriteString("## Path Usage Guidelines\n\n")
	schemaInfo.WriteString("**For D&R detection rules:** Use paths exactly as shown above (e.g., `path: event/FILE_PATH`)\n\n")
	schemaInfo.WriteString("**For LCQL queries:** Use paths in filter expressions (e.g., `event/FILE_PATH contains 'value'`)\n\n")
	schemaInfo.WriteString("**Common routing fields** available on all events:\n")
	schemaInfo.WriteString("- `routing/sid` - Sensor ID\n")
	schemaInfo.WriteString("- `routing/hostname` - Sensor hostname\n")
	schemaInfo.WriteString("- `routing/tags` - Sensor tags array\n")
	schemaInfo.WriteString("- `routing/event_type` - The event type name\n")

	return schemaInfo.String()
}

// convertElementsToInterface converts []SchemaElement to []interface{} for interpretSchema
func convertElementsToInterface(elements []lc.SchemaElement) []interface{} {
	result := make([]interface{}, len(elements))
	for i, elem := range elements {
		result[i] = string(elem)
	}
	return result
}

// getSmartSchemaContext performs multi-stage context extraction for AI generation
// This is the main function that orchestrates platform detection, event selection, and schema fetching
func getSmartSchemaContext(ctx context.Context, org *lc.Organization, userQuery string, schemaType string) string {
	// Stage 1: Detect platform from query
	platform := detectPlatform(ctx, org, userQuery)

	// Stage 2: Select relevant events for the query
	relevantEvents := selectRelevantEvents(ctx, org, userQuery, platform)

	// Stage 3: Get enhanced schema context if we have relevant events
	if len(relevantEvents) > 0 {
		enhancedContext := getEnhancedSchemaContext(ctx, org, relevantEvents)
		if enhancedContext != "" {
			return enhancedContext
		}
	}

	// Fall back to basic schema info if smart extraction failed
	slog.Debug("Falling back to basic schema info", "platform", platform, "relevant_events", len(relevantEvents))
	return getSchemaInfo(ctx, org, schemaType)
}
