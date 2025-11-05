package ai

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"gopkg.in/yaml.v3"
)

func init() {
	// Register AI-powered tools
	RegisterGenerateLCQLQuery()
	RegisterGenerateDRRuleDetection()
	RegisterGenerateDRRuleRespond()
	RegisterGenerateSensorSelector()
	RegisterGeneratePythonPlaybook()
	RegisterGenerateDetectionSummary()
}

// getOrganization retrieves the organization from the context
func getOrganization(ctx context.Context) (*lc.Organization, error) {
	cache, err := auth.GetSDKCache(ctx)
	if err != nil {
		return nil, err
	}
	return cache.GetFromContext(ctx)
}

// RegisterGenerateLCQLQuery registers the generate_lcql_query tool
func RegisterGenerateLCQLQuery() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "generate_lcql_query",
		Description: "Generate an LCQL query from natural language description using AI",
		Profile:     "ai_powered",
		RequiresOID: true,
		Schema: mcp.NewTool("generate_lcql_query",
			mcp.WithDescription("Generate a LimaCharlie Query Language (LCQL) query from a natural language description using Google Gemini AI"),
			mcp.WithString("query",
				mcp.Required(),
				mcp.Description("Natural language description of what to query")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			query, ok := args["query"].(string)
			if !ok || query == "" {
				return tools.ErrorResult("query parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			startTime := time.Now()
			fmt.Printf("Tool called: generate_lcql_query(query=%s)\n", query)

			// Get the prompt template
			promptTemplate, err := getPromptTemplate("gen_lcql")
			if err != nil {
				return tools.ErrorResultf("failed to load prompt template: %v", err), nil
			}

			// TODO: Get schema from prompt (requires implementing schema detection)
			// For now, use empty schema
			schema := "No schema available - extrapolate with best effort."
			prompt := strings.Replace(promptTemplate, "{lcql_schema}", schema, -1)

			// Loop up to retry count times to generate and validate
			maxIterations := GetRetryCount()
			messages := []map[string]interface{}{
				{
					"role": "user",
					"parts": []interface{}{
						map[string]interface{}{"text": query},
					},
				},
			}

			var lastError string

			for iteration := 0; iteration < maxIterations; iteration++ {
				fmt.Printf("LCQL generation attempt %d/%d\n", iteration+1, maxIterations)

				// Get the generated query
				response, err := geminiResponse(ctx, messages, prompt, DefaultModel, 0.0)
				if err != nil {
					return tools.ErrorResultf("failed to get Gemini response: %v", err), nil
				}

				// Parse response (format: query on first line, then explanation)
				lines := strings.SplitN(response, "\n", 2)
				generatedQuery := strings.TrimSpace(lines[0])
				explanation := ""
				if len(lines) > 1 {
					explanation = strings.TrimSpace(lines[1])
				}

				// Validate the query
				valid, validationError := validateLCQLQuery(org, generatedQuery)

				if valid {
					fmt.Printf("LCQL query validated successfully on attempt %d\n", iteration+1)
					elapsed := time.Since(startTime)
					fmt.Printf("generate_lcql_query time: %v\n", elapsed)

					return tools.SuccessResult(map[string]interface{}{
						"query":       generatedQuery,
						"explanation": explanation,
					}), nil
				}

				// Query is invalid, prepare for next iteration
				lastError = validationError
				fmt.Printf("LCQL validation failed on attempt %d: %s\n", iteration+1, validationError)

				// Add the assistant's response and the validation error
				messages = append(messages, map[string]interface{}{
					"role": "model",
					"parts": []interface{}{
						map[string]interface{}{"text": response},
					},
				})
				messages = append(messages, map[string]interface{}{
					"role": "user",
					"parts": []interface{}{
						map[string]interface{}{
							"text": fmt.Sprintf("The previous query generated was invalid with this error: %s\nPlease fix the query and try again.", validationError),
						},
					},
				})
			}

			// All iterations failed
			elapsed := time.Since(startTime)
			fmt.Printf("generate_lcql_query time: %v\n", elapsed)

			return tools.ErrorResultf("Failed to generate valid LCQL query after %d attempts. Last error: %s", maxIterations, lastError), nil
		},
	})
}

// RegisterGenerateDRRuleDetection registers the generate_dr_rule_detection tool
func RegisterGenerateDRRuleDetection() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "generate_dr_rule_detection",
		Description: "Generate a D&R rule detection component from natural language using AI",
		Profile:     "ai_powered",
		RequiresOID: true,
		Schema: mcp.NewTool("generate_dr_rule_detection",
			mcp.WithDescription("Generate a Detection & Response rule's detection component based on natural language description using Google Gemini AI"),
			mcp.WithString("query",
				mcp.Required(),
				mcp.Description("Natural language description of what to detect")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			query, ok := args["query"].(string)
			if !ok || query == "" {
				return tools.ErrorResult("query parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			startTime := time.Now()
			fmt.Printf("Tool called: generate_dr_rule_detection(query=%s)\n", query)

			// Get the prompt template
			promptTemplate, err := getPromptTemplate("gen_dr_detect")
			if err != nil {
				return tools.ErrorResultf("failed to load prompt template: %v", err), nil
			}

			// TODO: Get schema from prompt
			schema := "No schema available - extrapolate with best effort."
			prompt := strings.Replace(promptTemplate, "{lcql_schema}", schema, -1)

			// Loop up to retry count times
			maxIterations := GetRetryCount()
			messages := []map[string]interface{}{
				{
					"role": "user",
					"parts": []interface{}{
						map[string]interface{}{"text": query},
					},
				},
			}

			var lastError string

			for iteration := 0; iteration < maxIterations; iteration++ {
				fmt.Printf("D&R detection generation attempt %d/%d\n", iteration+1, maxIterations)

				// Get the generated detection
				response, err := geminiResponse(ctx, messages, prompt, DefaultModel, 0.0)
				if err != nil {
					return tools.ErrorResultf("failed to get Gemini response: %v", err), nil
				}

				// Remove markdown formatting if present
				generatedDetection := strings.TrimSpace(response)
				generatedDetection = strings.ReplaceAll(generatedDetection, "```yaml", "")
				generatedDetection = strings.ReplaceAll(generatedDetection, "```", "")
				generatedDetection = strings.TrimSpace(generatedDetection)

				// Try to parse the YAML first
				var parsedDetection map[string]interface{}
				if err := yaml.Unmarshal([]byte(generatedDetection), &parsedDetection); err != nil {
					lastError = fmt.Sprintf("Invalid YAML syntax: %v", err)
					fmt.Printf("D&R detection YAML parsing failed on attempt %d: %s\n", iteration+1, lastError)

					messages = append(messages, map[string]interface{}{
						"role": "model",
						"parts": []interface{}{
							map[string]interface{}{"text": response},
						},
					})
					messages = append(messages, map[string]interface{}{
						"role": "user",
						"parts": []interface{}{
							map[string]interface{}{
								"text": fmt.Sprintf("The previous detection rule generated had invalid YAML syntax with this error: %s\nPlease fix the YAML syntax and try again.", lastError),
							},
						},
					})
					continue
				}

				// Create a minimal D&R rule structure for validation
				testRuleYAML := fmt.Sprintf("detect:\n%s\nrespond: []", generatedDetection)

				// Validate the rule
				valid, validationError := validateDRRule(org, testRuleYAML)

				if valid {
					fmt.Printf("D&R detection validated successfully on attempt %d\n", iteration+1)
					elapsed := time.Since(startTime)
					fmt.Printf("generate_dr_rule_detection time: %v\n", elapsed)

					return tools.SuccessResult(map[string]interface{}{
						"detection": generatedDetection,
					}), nil
				}

				// Rule is invalid
				lastError = validationError
				fmt.Printf("D&R detection validation failed on attempt %d: %s\n", iteration+1, validationError)

				messages = append(messages, map[string]interface{}{
					"role": "model",
					"parts": []interface{}{
						map[string]interface{}{"text": response},
					},
				})
				messages = append(messages, map[string]interface{}{
					"role": "user",
					"parts": []interface{}{
						map[string]interface{}{
							"text": fmt.Sprintf("The previous detection rule generated was invalid with this error: %s\nPlease fix the detection rule and try again.", validationError),
						},
					},
				})
			}

			// All iterations failed
			elapsed := time.Since(startTime)
			fmt.Printf("generate_dr_rule_detection time: %v\n", elapsed)

			return tools.ErrorResultf("Failed to generate valid D&R detection after %d attempts. Last error: %s", maxIterations, lastError), nil
		},
	})
}

// RegisterGenerateDRRuleRespond registers the generate_dr_rule_respond tool
func RegisterGenerateDRRuleRespond() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "generate_dr_rule_respond",
		Description: "Generate a D&R rule respond component from natural language using AI",
		Profile:     "ai_powered",
		RequiresOID: true,
		Schema: mcp.NewTool("generate_dr_rule_respond",
			mcp.WithDescription("Generate a Detection & Response rule's respond component based on natural language description using Google Gemini AI"),
			mcp.WithString("query",
				mcp.Required(),
				mcp.Description("Natural language description of how to respond")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			query, ok := args["query"].(string)
			if !ok || query == "" {
				return tools.ErrorResult("query parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			startTime := time.Now()
			fmt.Printf("Tool called: generate_dr_rule_respond(query=%s)\n", query)

			// Get the prompt template
			prompt, err := getPromptTemplate("gen_dr_respond")
			if err != nil {
				return tools.ErrorResultf("failed to load prompt template: %v", err), nil
			}

			// Loop up to retry count times
			maxIterations := GetRetryCount()
			messages := []map[string]interface{}{
				{
					"role": "user",
					"parts": []interface{}{
						map[string]interface{}{"text": query},
					},
				},
			}

			var lastError string

			for iteration := 0; iteration < maxIterations; iteration++ {
				fmt.Printf("D&R respond generation attempt %d/%d\n", iteration+1, maxIterations)

				// Get the generated respond
				response, err := geminiResponse(ctx, messages, prompt, DefaultModel, 0.0)
				if err != nil {
					return tools.ErrorResultf("failed to get Gemini response: %v", err), nil
				}

				// Remove markdown formatting
				generatedRespond := strings.TrimSpace(response)
				generatedRespond = strings.ReplaceAll(generatedRespond, "```yaml", "")
				generatedRespond = strings.ReplaceAll(generatedRespond, "```", "")
				generatedRespond = strings.TrimSpace(generatedRespond)

				// Try to parse the YAML
				var parsedRespond interface{}
				if err := yaml.Unmarshal([]byte(generatedRespond), &parsedRespond); err != nil {
					lastError = fmt.Sprintf("Invalid YAML syntax: %v", err)
					fmt.Printf("D&R respond YAML parsing failed on attempt %d: %s\n", iteration+1, lastError)

					messages = append(messages, map[string]interface{}{
						"role": "model",
						"parts": []interface{}{
							map[string]interface{}{"text": response},
						},
					})
					messages = append(messages, map[string]interface{}{
						"role": "user",
						"parts": []interface{}{
							map[string]interface{}{
								"text": fmt.Sprintf("The previous respond rule generated had invalid YAML syntax with this error: %s\nPlease fix the YAML syntax and try again.", lastError),
							},
						},
					})
					continue
				}

				// Create a minimal D&R rule for validation
				testRuleYAML := fmt.Sprintf("detect: {}\nrespond:\n%s", generatedRespond)

				// Validate the rule
				valid, validationError := validateDRRule(org, testRuleYAML)

				if valid {
					fmt.Printf("D&R respond validated successfully on attempt %d\n", iteration+1)
					elapsed := time.Since(startTime)
					fmt.Printf("generate_dr_rule_respond time: %v\n", elapsed)

					return tools.SuccessResult(map[string]interface{}{
						"respond": generatedRespond,
					}), nil
				}

				// Rule is invalid
				lastError = validationError
				fmt.Printf("D&R respond validation failed on attempt %d: %s\n", iteration+1, validationError)

				messages = append(messages, map[string]interface{}{
					"role": "model",
					"parts": []interface{}{
						map[string]interface{}{"text": response},
					},
				})
				messages = append(messages, map[string]interface{}{
					"role": "user",
					"parts": []interface{}{
						map[string]interface{}{
							"text": fmt.Sprintf("The previous respond rule generated was invalid with this error: %s\nPlease fix the respond rule and try again.", validationError),
						},
					},
				})
			}

			// All iterations failed
			elapsed := time.Since(startTime)
			fmt.Printf("generate_dr_rule_respond time: %v\n", elapsed)

			return tools.ErrorResultf("Failed to generate valid D&R respond after %d attempts. Last error: %s", maxIterations, lastError), nil
		},
	})
}

// RegisterGenerateSensorSelector registers the generate_sensor_selector tool
func RegisterGenerateSensorSelector() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "generate_sensor_selector",
		Description: "Generate a sensor selector expression from natural language using AI",
		Profile:     "ai_powered",
		RequiresOID: false,
		Schema: mcp.NewTool("generate_sensor_selector",
			mcp.WithDescription("Generate a sensor selector expression based on natural language description using Google Gemini AI"),
			mcp.WithString("query",
				mcp.Required(),
				mcp.Description("Natural language description of which sensors to select")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			query, ok := args["query"].(string)
			if !ok || query == "" {
				return tools.ErrorResult("query parameter is required"), nil
			}

			startTime := time.Now()
			fmt.Printf("Tool called: generate_sensor_selector(query=%s)\n", query)

			// Get the prompt template
			prompt, err := getPromptTemplate("gen_sensor_selector")
			if err != nil {
				return tools.ErrorResultf("failed to load prompt template: %v", err), nil
			}

			// Single call to Gemini for sensor selector
			messages := []map[string]interface{}{
				{
					"role": "user",
					"parts": []interface{}{
						map[string]interface{}{"text": query},
					},
				},
			}

			response, err := geminiResponse(ctx, messages, prompt, DefaultModel, 0.0)
			if err != nil {
				return tools.ErrorResultf("failed to get Gemini response: %v", err), nil
			}

			// Parse response (format: selector on first line, then explanation)
			lines := strings.SplitN(response, "\n", 2)
			selector := strings.TrimSpace(lines[0])
			explanation := ""
			if len(lines) > 1 {
				explanation = strings.TrimSpace(lines[1])
			}

			elapsed := time.Since(startTime)
			fmt.Printf("generate_sensor_selector time: %v\n", elapsed)

			return tools.SuccessResult(map[string]interface{}{
				"selector":    selector,
				"explanation": explanation,
			}), nil
		},
	})
}

// RegisterGeneratePythonPlaybook registers the generate_python_playbook tool
func RegisterGeneratePythonPlaybook() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "generate_python_playbook",
		Description: "Generate a Python playbook script from natural language using AI",
		Profile:     "ai_powered",
		RequiresOID: false,
		Schema: mcp.NewTool("generate_python_playbook",
			mcp.WithDescription("Generate a Python playbook script based on natural language description using Google Gemini AI"),
			mcp.WithString("query",
				mcp.Required(),
				mcp.Description("Natural language description of the playbook automation")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			query, ok := args["query"].(string)
			if !ok || query == "" {
				return tools.ErrorResult("query parameter is required"), nil
			}

			startTime := time.Now()
			fmt.Printf("Tool called: generate_python_playbook(query=%s)\n", query)

			// Get the prompt template
			prompt, err := getPromptTemplate("gen_playbook")
			if err != nil {
				return tools.ErrorResultf("failed to load prompt template: %v", err), nil
			}

			// Single call to Gemini for playbook
			messages := []map[string]interface{}{
				{
					"role": "user",
					"parts": []interface{}{
						map[string]interface{}{"text": query},
					},
				},
			}

			response, err := geminiResponse(ctx, messages, prompt, DefaultModel, 0.0)
			if err != nil {
				return tools.ErrorResultf("failed to get Gemini response: %v", err), nil
			}

			// Remove markdown code fences if present
			playbook := strings.TrimSpace(response)
			playbook = strings.ReplaceAll(playbook, "```python", "")
			playbook = strings.ReplaceAll(playbook, "```", "")
			playbook = strings.TrimSpace(playbook)

			elapsed := time.Since(startTime)
			fmt.Printf("generate_python_playbook time: %v\n", elapsed)

			return tools.SuccessResult(map[string]interface{}{
				"playbook": playbook,
			}), nil
		},
	})
}

// RegisterGenerateDetectionSummary registers the generate_detection_summary tool
func RegisterGenerateDetectionSummary() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "generate_detection_summary",
		Description: "Generate a summary of detections using AI",
		Profile:     "ai_powered",
		RequiresOID: false,
		Schema: mcp.NewTool("generate_detection_summary",
			mcp.WithDescription("Generate a human-readable summary of detection data using Google Gemini AI"),
			mcp.WithString("detections",
				mcp.Required(),
				mcp.Description("JSON string of detection data to summarize")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			detections, ok := args["detections"].(string)
			if !ok || detections == "" {
				return tools.ErrorResult("detections parameter is required"), nil
			}

			startTime := time.Now()
			fmt.Printf("Tool called: generate_detection_summary\n")

			// Get the prompt template
			prompt, err := getPromptTemplate("gen_det_summary")
			if err != nil {
				return tools.ErrorResultf("failed to load prompt template: %v", err), nil
			}

			// Single call to Gemini for summary
			messages := []map[string]interface{}{
				{
					"role": "user",
					"parts": []interface{}{
						map[string]interface{}{"text": detections},
					},
				},
			}

			response, err := geminiResponse(ctx, messages, prompt, DefaultModel, 0.0)
			if err != nil {
				return tools.ErrorResultf("failed to get Gemini response: %v", err), nil
			}

			elapsed := time.Since(startTime)
			fmt.Printf("generate_detection_summary time: %v\n", elapsed)

			return tools.SuccessResult(map[string]interface{}{
				"summary": response,
			}), nil
		},
	})
}
