package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

const (
	apiRootURL     = "https://api.limacharlie.io"
	billingRootURL = "https://billing.limacharlie.io"
	defaultTimeout = 30 * time.Second
)

func init() {
	RegisterLCAPICall()
}

// RegisterLCAPICall registers the lc_api_call tool
func RegisterLCAPICall() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "lc_api_call",
		Description: "Make a generic HTTP request to LimaCharlie API or billing endpoints",
		Profile:     "api_access",
		RequiresOID: true,
		Schema: mcp.NewTool("lc_api_call",
			mcp.WithDescription("Make a generic HTTP request to LimaCharlie API or billing endpoints. "+
				"This tool provides direct access to LimaCharlie APIs for advanced use cases not covered by other tools. "+
				"The LLM should have its own API documentation to use this tool effectively."),
			mcp.WithString("endpoint",
				mcp.Required(),
				mcp.Description("Target endpoint: 'api' for api.limacharlie.io or 'billing' for billing.limacharlie.io")),
			mcp.WithString("method",
				mcp.Required(),
				mcp.Description("HTTP method: GET, POST, PUT, DELETE, or PATCH")),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("API path (e.g., '/v1/orgs/{oid}/sensors'). Should start with '/'")),
			mcp.WithObject("query_params",
				mcp.Description("Optional URL query parameters as key-value pairs")),
			mcp.WithObject("headers",
				mcp.Description("Optional custom HTTP headers as key-value pairs")),
			mcp.WithObject("body",
				mcp.Description("Optional request body (will be sent as JSON)")),
			mcp.WithNumber("timeout",
				mcp.Description("Optional request timeout in seconds (default: 30)")),
		),
		Handler: handleLCAPICall,
	})
}

func handleLCAPICall(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	// Extract and validate endpoint parameter
	endpoint, ok := args["endpoint"].(string)
	if !ok || endpoint == "" {
		return tools.ErrorResult("endpoint parameter is required and must be a string"), nil
	}
	endpoint = strings.ToLower(strings.TrimSpace(endpoint))
	if endpoint != "api" && endpoint != "billing" {
		return tools.ErrorResult("endpoint must be either 'api' or 'billing'"), nil
	}

	// Extract and validate HTTP method
	method, ok := args["method"].(string)
	if !ok || method == "" {
		return tools.ErrorResult("method parameter is required and must be a string"), nil
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	validMethods := map[string]bool{"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true}
	if !validMethods[method] {
		return tools.ErrorResult("method must be one of: GET, POST, PUT, DELETE, PATCH"), nil
	}

	// Extract and validate path
	path, ok := args["path"].(string)
	if !ok || path == "" {
		return tools.ErrorResult("path parameter is required and must be a string"), nil
	}
	path = strings.TrimSpace(path)
	if !strings.HasPrefix(path, "/") {
		return tools.ErrorResult("path must start with '/'"), nil
	}

	// Extract optional query parameters
	var queryParams map[string]interface{}
	if qp, ok := args["query_params"].(map[string]interface{}); ok {
		queryParams = qp
	}

	// Extract optional custom headers
	var customHeaders map[string]interface{}
	if h, ok := args["headers"].(map[string]interface{}); ok {
		customHeaders = h
	}

	// Extract optional body
	var requestBody map[string]interface{}
	if b, ok := args["body"].(map[string]interface{}); ok {
		requestBody = b
	}

	// Extract optional timeout
	timeout := defaultTimeout
	if t, ok := args["timeout"].(float64); ok && t > 0 {
		timeout = time.Duration(t) * time.Second
	}

	// Get auth context
	authCtx, err := auth.FromContext(ctx)
	if err != nil {
		return tools.ErrorResultf("failed to get auth context: %v", err), nil
	}

	// Build full URL
	var baseURL string
	if endpoint == "api" {
		baseURL = apiRootURL
	} else {
		baseURL = billingRootURL
	}
	fullURL := baseURL + path

	// Add query parameters
	if len(queryParams) > 0 {
		urlObj, err := url.Parse(fullURL)
		if err != nil {
			return tools.ErrorResultf("failed to parse URL: %v", err), nil
		}
		q := urlObj.Query()
		for key, value := range queryParams {
			q.Add(key, fmt.Sprintf("%v", value))
		}
		urlObj.RawQuery = q.Encode()
		fullURL = urlObj.String()
	}

	// Prepare request body
	var bodyReader io.Reader
	if len(requestBody) > 0 {
		bodyBytes, err := json.Marshal(requestBody)
		if err != nil {
			return tools.ErrorResultf("failed to marshal request body: %v", err), nil
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// Create HTTP request
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, method, fullURL, bodyReader)
	if err != nil {
		return tools.ErrorResultf("failed to create HTTP request: %v", err), nil
	}

	// Set standard headers
	req.Header.Set("User-Agent", "limacharlie-mcp-server")

	// Set authorization header
	if authCtx.JWTToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authCtx.JWTToken))
	} else if authCtx.APIKey != "" {
		// Fallback to API key if JWT not available
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authCtx.APIKey))
	}

	// Set content type for requests with body
	if len(requestBody) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add custom headers
	for key, value := range customHeaders {
		req.Header.Set(key, fmt.Sprintf("%v", value))
	}

	// Make HTTP request
	client := &http.Client{
		Timeout: timeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		return tools.ErrorResultf("HTTP request failed: %v", err), nil
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return tools.ErrorResultf("failed to read response body: %v", err), nil
	}

	// Try to parse response as JSON
	var responseData interface{}
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &responseData); err != nil {
			// If not valid JSON, return as string
			responseData = string(respBody)
		}
	}

	// Build result
	result := map[string]interface{}{
		"status_code": resp.StatusCode,
		"status":      resp.Status,
		"headers":     resp.Header,
		"body":        responseData,
	}

	// Add error information if status code indicates failure
	if resp.StatusCode >= 400 {
		result["error"] = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return tools.SuccessResult(result), nil
}
