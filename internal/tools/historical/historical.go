package historical

import (
	"context"
	"fmt"
	"math"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register historical data tools
	RegisterRunLCQLQuery()
	RegisterGetHistoricDetections()
	RegisterSearchIOCs()
	RegisterBatchSearchIOCs()
	RegisterGetTimeWhenSensorHasData()
}


// RegisterRunLCQLQuery registers the run_lcql_query tool
func RegisterRunLCQLQuery() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "run_lcql_query",
		Description: "Run a LimaCharlie Query Language (LCQL) query on the organization",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("run_lcql_query",
			mcp.WithDescription("Run a LimaCharlie Query Language (LCQL) query on the organization"),
			mcp.WithString("query",
				mcp.Required(),
				mcp.Description("The LCQL query to run")),
			mcp.WithNumber("limit",
				mcp.Description("Maximum number of results to return (unlimited if not specified)")),
			mcp.WithString("stream",
				mcp.Description("Stream to query: 'event', 'detect', or 'audit' (default: 'event')")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract query
			query, ok := args["query"].(string)
			if !ok || query == "" {
				return tools.ErrorResult("query parameter is required"), nil
			}

			// Extract limit (unlimited if not specified)
			limit := math.MaxInt
			if limitFloat, ok := args["limit"].(float64); ok {
				limit = int(limitFloat)
			}

			// Extract stream (default "event")
			stream := "event"
			if streamStr, ok := args["stream"].(string); ok && streamStr != "" {
				stream = streamStr
			}

			// Validate stream parameter
			if stream != "event" && stream != "detect" && stream != "audit" {
				return tools.ErrorResultf("invalid stream '%s' specified. Must be one of: 'event', 'detect', 'audit'", stream), nil
			}

			// Get organization
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create query request with cursor-based pagination
			queryReq := lc.QueryRequest{
				Query:  query,
				Stream: stream,
				Cursor: "-", // Enable cursor-based pagination
			}

			// Get query iterator
			iter, err := org.QueryAll(queryReq)
			if err != nil {
				return tools.ErrorResultf("failed to create query iterator: %v", err), nil
			}

			// Collect results up to the limit
			// Use reasonable initial capacity to avoid "makeslice: cap out of range" panic
			// when limit is math.MaxInt (unlimited)
			initialCap := 100
			if limit != math.MaxInt && limit < 1000 {
				initialCap = limit
			}
			results := make([]lc.Dict, 0, initialCap)
			hasMore := false

			for iter.HasMore() {
				resp, err := iter.Next()
				if err != nil {
					return tools.ErrorResultf("failed to fetch query results: %v", err), nil
				}

				if resp == nil {
					break
				}

				// Add results from this page
				for _, result := range resp.Results {
					if len(results) >= limit {
						hasMore = true
						break
					}
					results = append(results, result)
				}

				// Stop if we've reached the limit
				if len(results) >= limit {
					hasMore = true
					break
				}
			}

			// Check if there are more results available
			if !hasMore && iter.HasMore() {
				hasMore = true
			}

			response := map[string]interface{}{
				"results":  results,
				"has_more": hasMore,
			}

			return tools.SuccessResult(response), nil
		},
	})
}

// RegisterGetHistoricDetections registers the get_historic_detections tool
func RegisterGetHistoricDetections() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_historic_detections",
		Description: "Get historic detections for the organization between two timestamps",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("get_historic_detections",
			mcp.WithDescription("Get historic detections for the organization between two epoch timestamps"),
			mcp.WithNumber("start",
				mcp.Required(),
				mcp.Description("Start timestamp in Unix epoch seconds")),
			mcp.WithNumber("end",
				mcp.Required(),
				mcp.Description("End timestamp in Unix epoch seconds")),
			mcp.WithString("cat",
				mcp.Description("Detection category to filter by")),
			mcp.WithNumber("limit",
				mcp.Description("Maximum number of results to return")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract start and end timestamps
			startFloat, ok := args["start"].(float64)
			if !ok {
				return tools.ErrorResult("start parameter is required"), nil
			}
			start := int64(startFloat)

			endFloat, ok := args["end"].(float64)
			if !ok {
				return tools.ErrorResult("end parameter is required"), nil
			}
			end := int64(endFloat)

			// Get organization
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// TODO: Go SDK needs GetDetections() method
			// Need to add: func (org *Organization) GetDetections(start, end int64) ([]Detection, error)
			// For now, return error indicating SDK limitation
			_ = org
			_ = start
			_ = end

			result := map[string]interface{}{
				"error":   "not_implemented",
				"message": "Go SDK does not yet have GetDetections() method. Need to add to go-limacharlie SDK.",
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterSearchIOCs registers the search_iocs tool
func RegisterSearchIOCs() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "search_iocs",
		Description: "Search for Indicators of Compromise (IOCs) across the organization",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("search_iocs",
			mcp.WithDescription("Search for Indicators of Compromise (IOCs) across the organization"),
			mcp.WithString("ioc_type",
				mcp.Required(),
				mcp.Description("Type of IOC: 'hash', 'domain', 'ip', 'file_path', etc.")),
			mcp.WithString("ioc_value",
				mcp.Required(),
				mcp.Description("The IOC value to search for (supports wildcards with *)")),
			mcp.WithString("info_type",
				mcp.Required(),
				mcp.Description("Type of information to retrieve: 'summary', 'locations', etc.")),
			mcp.WithNumber("limit",
				mcp.Description("Maximum number of results to return")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract parameters
			iocType, ok := args["ioc_type"].(string)
			if !ok || iocType == "" {
				return tools.ErrorResult("ioc_type parameter is required"), nil
			}

			iocValue, ok := args["ioc_value"].(string)
			if !ok || iocValue == "" {
				return tools.ErrorResult("ioc_value parameter is required"), nil
			}

			infoType, ok := args["info_type"].(string)
			if !ok || infoType == "" {
				return tools.ErrorResult("info_type parameter is required"), nil
			}

			// Get organization
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// TODO: Go SDK needs SearchIOC() method
			// Need to add: func (org *Organization) SearchIOC(iocType, iocValue, infoType string) (interface{}, error)
			// For now, return error indicating SDK limitation
			_ = org
			_ = iocType
			_ = iocValue
			_ = infoType

			result := map[string]interface{}{
				"error":   "not_implemented",
				"message": "Go SDK does not yet have SearchIOC() method. Need to add to go-limacharlie SDK.",
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterBatchSearchIOCs registers the batch_search_iocs tool
func RegisterBatchSearchIOCs() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "batch_search_iocs",
		Description: "Batch search for multiple IOCs at once",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("batch_search_iocs",
			mcp.WithDescription("Batch search for multiple IOCs at once"),
			mcp.WithString("iocs",
				mcp.Required(),
				mcp.Description("JSON array of IOC objects with type and value fields")),
			mcp.WithString("info_type",
				mcp.Required(),
				mcp.Description("Type of information to retrieve: 'summary', 'locations', etc.")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {

			// Get organization
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Note: Using InsightObjectsBatch from SDK
			_ = org

			result := map[string]interface{}{
				"error":   "not_implemented",
				"message": "Go SDK needs InsightObjectsBatch() method. Need to add to go-limacharlie SDK.",
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterGetTimeWhenSensorHasData registers the get_time_when_sensor_has_data tool
func RegisterGetTimeWhenSensorHasData() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_time_when_sensor_has_data",
		Description: "Get the time range when a sensor has telemetry data",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("get_time_when_sensor_has_data",
			mcp.WithDescription("Get the time range when a sensor has telemetry data"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, ok := args["sid"].(string)
			if !ok {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			// Get organization
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Use GenericGETRequest to get sensor data time range
			resp := lc.Dict{}
			path := fmt.Sprintf("insight/%s/timeline/%s", org.GetOID(), sid)
			if err := org.GenericGETRequest(path, nil, &resp); err != nil {
				return tools.ErrorResultf("failed to get sensor timeline: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}
