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

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

const (
	// DefaultModel is the Claude model used for complex generation tasks
	DefaultModel = anthropic.ModelClaudeSonnet4_6
	// LiteModel is a smaller, faster Claude model for simple classification tasks
	LiteModel = anthropic.ModelClaudeHaiku4_5
	// DefaultRetryCount is the default number of retries for YAML parsing/validation
	DefaultRetryCount = 10
	// defaultMaxTokens is the maximum number of tokens for Claude responses
	defaultMaxTokens int64 = 8192
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

// claudeResponse gets a response from the Anthropic Claude API.
// Results are memoized: identical inputs return a cached response for up to 24 hours.
func claudeResponse(ctx context.Context, messages []map[string]interface{}, systemPrompt string, modelName string, temperature float32) (string, error) {
	startTime := time.Now()
	defer func() {
		elapsed := time.Since(startTime)
		slog.Debug("Claude response time", "duration_ms", elapsed.Milliseconds())
	}()

	// Check the cache first.
	cache := getCache()
	cacheKey := buildCacheKey(messages, systemPrompt, modelName, temperature)
	if cached, ok := cache.get(cacheKey); ok {
		slog.Debug("AI cache hit", "key", cacheKey, "model", modelName)
		return cached, nil
	}

	// Get API key from environment
	apiKey := os.Getenv("ANTHROPIC_KEY")
	if apiKey == "" {
		return "", fmt.Errorf("ANTHROPIC_KEY environment variable not set")
	}

	// Create Anthropic client
	client := anthropic.NewClient(option.WithAPIKey(apiKey))

	// Convert generic message format to Anthropic MessageParam slice
	anthropicMessages := convertToAnthropicMessages(messages)

	// Build request parameters
	params := anthropic.MessageNewParams{
		Model:       modelName,
		MaxTokens:   defaultMaxTokens,
		Temperature: anthropic.Float(float64(temperature)),
		Messages:    anthropicMessages,
	}

	// Set system prompt if provided, with prompt caching to reduce cost
	// on retry iterations that resend the same large system prompt.
	if systemPrompt != "" {
		params.System = []anthropic.TextBlockParam{
			{
				Text:         systemPrompt,
				CacheControl: anthropic.NewCacheControlEphemeralParam(),
			},
		}
	}

	// Debug logging for AI prompts
	if isDebugAIEnabled() {
		slog.Info("DEBUG_AI: System Prompt", "prompt", systemPrompt)
		for i, msg := range messages {
			slog.Info("DEBUG_AI: Message", "index", i, "role", msg["role"], "parts", msg["parts"])
		}
	}

	// Send message and get response
	resp, err := client.Messages.New(ctx, params)
	if err != nil {
		return "", fmt.Errorf("failed to get Claude response: %w", err)
	}

	// Extract text from response content blocks
	var textParts []string
	for _, block := range resp.Content {
		if block.Type == "text" {
			textParts = append(textParts, block.Text)
		}
	}

	responseText := strings.Join(textParts, "")
	if responseText == "" {
		return "", fmt.Errorf("empty response from Claude")
	}

	// Debug logging for AI response
	if isDebugAIEnabled() {
		slog.Info("DEBUG_AI: AI Response", "response", responseText)
	}

	result := strings.TrimSpace(responseText)

	// Store in cache for future identical requests.
	cache.set(cacheKey, result)

	return result, nil
}

// convertToAnthropicMessages converts the generic message format used throughout
// the codebase into Anthropic SDK MessageParam types.
func convertToAnthropicMessages(messages []map[string]interface{}) []anthropic.MessageParam {
	var result []anthropic.MessageParam

	for _, msg := range messages {
		role, ok := msg["role"].(string)
		if !ok {
			continue
		}

		parts, ok := msg["parts"].([]interface{})
		if !ok {
			continue
		}

		// Extract text from parts
		var textBlocks []anthropic.ContentBlockParamUnion
		for _, part := range parts {
			if partMap, ok := part.(map[string]interface{}); ok {
				if text, ok := partMap["text"].(string); ok {
					textBlocks = append(textBlocks, anthropic.NewTextBlock(text))
				}
			}
		}

		if len(textBlocks) == 0 {
			continue
		}

		// Map role: Gemini used "model" for assistant, Anthropic uses "assistant"
		switch role {
		case "user":
			result = append(result, anthropic.NewUserMessage(textBlocks...))
		case "model", "assistant":
			result = append(result, anthropic.NewAssistantMessage(textBlocks...))
		}
	}

	return result
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

// isLanguageHint reports whether a token is a bare markdown fence language hint
// (e.g. "lcql", "yaml"). Anything carrying punctuation is content, not a hint —
// an LCQL query starts with a timeframe like "-1h", which must never be mistaken
// for one and dropped.
func isLanguageHint(token string) bool {
	if token == "" {
		return false
	}
	for _, r := range token {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// dropFenceLines removes markdown code-fence marker lines ("```", "```lcql")
// from a response, keeping every other line — including whatever follows the
// closing fence.
//
// Deleting the whole span from the opening fence to the last "```" would be
// simpler, but it silently swallows the explanation models place after the
// closing fence, and that explanation is returned to the caller.
func dropFenceLines(response string) string {
	lines := strings.Split(strings.TrimSpace(response), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "```") {
			kept = append(kept, line)
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "```"))
		// A bare marker, or a marker plus a lone language hint, is pure
		// decoration and disappears. A marker with real content glued to it
		// keeps that content.
		if rest == "" || isLanguageHint(rest) {
			continue
		}
		kept = append(kept, rest)
	}
	return strings.TrimSpace(strings.Join(kept, "\n"))
}

// hasWrappingBackticks reports whether a line both begins and ends with a backtick.
func hasWrappingBackticks(line string) bool {
	return len(line) >= 2 && strings.HasPrefix(line, "`") && strings.HasSuffix(line, "`")
}

// unwrapInlineCode removes a single pair of wrapping backticks from a line whose
// content cannot itself start with one.
//
// Safe for LCQL only: a query always begins with a timeframe ("-24h", a date),
// so a leading backtick is unambiguously a markdown wrapper. One backtick is
// removed per side, leaving an inner backtick-quoted regex in a `matches` clause
// intact.
func unwrapInlineCode(line string) string {
	line = strings.TrimSpace(line)
	if hasWrappingBackticks(line) {
		line = strings.TrimSpace(line[1 : len(line)-1])
	}
	return line
}

// unwrapSelectorInlineCode removes wrapping backticks from a sensor selector,
// distinguishing a markdown wrapper from the selector's own value quoting.
//
// Selectors backtick-quote values, so both of these begin and end with a
// backtick but mean different things:
//
//	`vip` in tags and plat == `windows`     <- not wrapped; quotes two values
//	`plat == `linux` and isolated == true`  <- wrapped; quotes one value
//
// Stripping a pair from the first corrupts it into
// "vip` in tags and plat == `windows"; failing to strip the second leaves an
// unusable expression. They are told apart by what the leading backtick would
// quote: a selector value is a single bare token, so if that segment contains
// whitespace the backtick cannot be a value quote and must be a wrapper.
func unwrapSelectorInlineCode(line string) string {
	line = strings.TrimSpace(line)
	if !hasWrappingBackticks(line) {
		return line
	}
	inner := line[1 : len(line)-1]

	// No interior backticks: the outer pair can only be a wrapper.
	i := strings.Index(inner, "`")
	if i < 0 {
		return strings.TrimSpace(inner)
	}

	// Whitespace in the segment the leading backtick would quote means it is
	// not quoting a value, so the outer pair is a wrapper.
	if strings.ContainsAny(inner[:i], " \t") {
		return strings.TrimSpace(inner)
	}

	// The leading backtick opens a real quoted value; leave the line alone.
	return line
}

// extractFirstLine pulls the first meaningful line out of an AI response and
// strips the markdown decoration models habitually add around it, returning the
// value and whatever remains as the explanation.
//
// Models routinely wrap the value in a code fence or inline backticks despite
// being told not to. Passing those characters through to a validator produces a
// parse failure at position 0 that looks nothing like the real problem, which
// then poisons every retry with a misleading error.
func extractFirstLine(response string) (string, string) {
	return splitValueAndExplanation(response, unwrapSelectorInlineCode)
}

// splitValueAndExplanation drops fence lines, then splits the body into its
// first line (passed through unwrap) and the remaining explanation.
func splitValueAndExplanation(response string, unwrap func(string) string) (string, string) {
	body := dropFenceLines(response)
	lines := strings.SplitN(body, "\n", 2)
	value := unwrap(lines[0])
	explanation := ""
	if len(lines) > 1 {
		explanation = strings.TrimSpace(lines[1])
	}
	return value, explanation
}

// lcqlComponentSeparators is the number of pipes separating an LCQL query's 4
// required components, and so the minimum a line must have to be query-shaped.
const lcqlComponentSeparators = 3

// extractGeneratedLCQL extracts the LCQL query and explanation from an AI response.
//
// On top of the markdown stripping done by extractFirstLine, this scans for the
// first line that actually looks like LCQL (an LCQL query has at least the 3
// pipes separating its 4 required components). That keeps a preamble sentence
// the model was told not to emit — or a refusal paragraph — from being submitted
// to the validator in place of the query sitting a few lines below it.
func extractGeneratedLCQL(response string) (string, string) {
	value, explanation := splitValueAndExplanation(response, unwrapInlineCode)
	if strings.Count(value, "|") >= lcqlComponentSeparators {
		return value, explanation
	}

	// First line was not a query; look for one further down.
	lines := strings.Split(dropFenceLines(response), "\n")
	for i, line := range lines {
		candidate := unwrapInlineCode(line)
		if strings.Count(candidate, "|") < lcqlComponentSeparators {
			continue
		}
		return candidate, strings.TrimSpace(strings.Join(lines[i+1:], "\n"))
	}

	// Nothing query-shaped found: fall back to the first line so the validator
	// error reported to the user reflects what the model actually produced.
	return value, explanation
}

// cleanYAMLResponse removes markdown formatting from AI-generated YAML
func cleanYAMLResponse(response string) string {
	if block, ok := firstFencedBlock(response); ok {
		return block
	}
	return trimLeadingProse(strings.TrimSpace(response))
}

// cleanCodeResponse extracts generated source code from an AI response, using
// the same fenced-block rule as cleanYAMLResponse. Unfenced responses are
// returned as-is: code has no equivalent of a YAML key to anchor prose
// detection on, and guessing would risk deleting a leading comment or import.
func cleanCodeResponse(response string) string {
	if block, ok := firstFencedBlock(response); ok {
		return block
	}
	return strings.TrimSpace(response)
}

// firstFencedBlock returns the contents of the first ```-delimited block, and
// whether one was found. An unterminated opening fence yields everything after
// it, which is what a truncated response should degrade to.
//
// Only lines that *begin* with a fence marker are treated as markers, so a
// fence sequence appearing inside a string value is left alone. Deleting every
// "```" substring instead — as this used to — silently rewrote such values.
func firstFencedBlock(response string) (string, bool) {
	lines := strings.Split(strings.TrimSpace(response), "\n")
	start := -1
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			start = i
			break
		}
	}
	if start == -1 {
		return "", false
	}
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "```") {
			return strings.TrimSpace(strings.Join(lines[start+1:i], "\n")), true
		}
	}
	return strings.TrimSpace(strings.Join(lines[start+1:], "\n")), true
}

// trimLeadingProse drops conversational lines that precede the YAML in an
// unfenced response ("Here is the detection rule:", "My apologies...").
//
// Such a line is often valid YAML on its own — "Here is the detection rule:"
// parses as a mapping key — so it cannot be rejected by well-formedness alone.
// It is recognised instead by the key containing whitespace: rule fields are
// single tokens (op, path, event, rules), prose keys are sentences. Once a line
// that looks like real YAML is seen, everything from there on is kept verbatim.
func trimLeadingProse(response string) string {
	lines := strings.Split(response, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Comments and list items are unambiguous YAML starts.
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "-") {
			return strings.TrimSpace(strings.Join(lines[i:], "\n"))
		}
		key, _, isMapping := strings.Cut(trimmed, ":")
		if isMapping && !strings.ContainsAny(key, " \t") {
			return strings.TrimSpace(strings.Join(lines[i:], "\n"))
		}
		// Prose: keep scanning.
	}
	// Nothing recognisable — return the response untouched so the parse error
	// reported to the caller reflects what the model actually produced.
	return response
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
func getSchemaInfo(ctx context.Context, org *lc.Organization, schemaType string) string {
	// Get all available schemas
	schemas, err := org.GetSchemas()
	if err != nil {
		slog.Warn("Failed to fetch schemas", "error", err)
		return "No schema available - extrapolate with best effort."
	}

	if schemas == nil || len(schemas.EventTypes) == 0 {
		return "No schema available - extrapolate with best effort."
	}

	// Build schema information
	// Provide a list of available event types rather than full schemas
	// to avoid overwhelming the prompt with too much data
	var schemaInfo strings.Builder

	eventTypes := []string{}
	for _, eventType := range schemas.EventTypes {
		if parts := strings.SplitN(eventType, ":", 2); len(parts) == 2 && (schemaType == "" || parts[0] == schemaType) {
			eventTypes = append(eventTypes, fmt.Sprintf("%q", parts[1]))
		}
	}

	schemaInfo.WriteString(fmt.Sprintf("Available event types (%d total):\n", len(eventTypes)))

	schemaInfo.WriteString(strings.Join(eventTypes, ", "))

	schemaInfo.WriteString("\n\nUse these event type names in your LCQL queries. ")
	schemaInfo.WriteString("Common fields across most events include: routing (with sid, oid, tags, etc.), ")
	schemaInfo.WriteString("event_type, ts (timestamp), and type-specific fields.")

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

	// Replace the platforms placeholder with a markdown list
	var markdownPlatforms strings.Builder
	for _, platform := range platforms {
		markdownPlatforms.WriteString(fmt.Sprintf("- %s\n", platform))
	}
	prompt := strings.Replace(promptTemplate, "{platforms}", markdownPlatforms.String(), -1)

	// Call Claude with LiteModel for fast, cheap inference
	messages := []map[string]interface{}{
		{
			"role": "user",
			"parts": []interface{}{
				map[string]interface{}{"text": userQuery},
			},
		},
	}

	response, err := claudeResponse(ctx, messages, prompt, LiteModel, 0.0)
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

	// Call Claude with LiteModel for fast, cheap inference
	messages := []map[string]interface{}{
		{
			"role": "user",
			"parts": []interface{}{
				map[string]interface{}{"text": userQuery},
			},
		},
	}

	response, err := claudeResponse(ctx, messages, prompt, LiteModel, 0.0)
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
	schemaInfo.WriteString(fmt.Sprintf("Detailed schemas for %d relevant event types:\n\n", len(schemas)))

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

	schemaInfo.WriteString("\nUse these event type names and field paths in your queries. ")
	schemaInfo.WriteString("Common fields across most events include: routing (with sid, oid, tags, etc.), ")
	schemaInfo.WriteString("event_type, ts (timestamp).")

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

// getCurrentTimestampContext returns formatted timestamp context to inject into AI prompts.
// The timestamp is rounded to the current UTC date so that identical queries on the
// same day produce the same cache key while still giving the AI useful time context.
func getCurrentTimestampContext() string {
	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	return fmt.Sprintf("Current date: %s (unix %d)",
		dayStart.Format("2006-01-02"),
		dayStart.Unix())
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
