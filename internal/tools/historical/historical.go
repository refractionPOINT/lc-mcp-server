package historical

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register historical data tools
	RegisterRunLCQLQuery()
	RegisterRunLCQLQueryFree()
	RegisterValidateLCQLQuery()
	RegisterEstimateLCQLQuery()
	RegisterAnalyzeLCQLQuery()
	RegisterGetHistoricDetections()
	RegisterGetDetection()
	RegisterSearchIOCs()
	RegisterBatchSearchIOCs()
	RegisterGetTimeWhenSensorHasData()
	RegisterGetEventByAtom()
	RegisterGetAtomChildren()
}

// timeframePattern matches LCQL timeframe patterns like -30d, -24h, -30m
var timeframePattern = regexp.MustCompile(`^-(\d+)([mhd])\s*\|?`)

// parseTimeframe extracts and validates a timeframe from an LCQL query
// Returns: hasTimeframe, daysEquivalent, error
func parseTimeframe(query string) (bool, float64, error) {
	query = strings.TrimSpace(query)
	matches := timeframePattern.FindStringSubmatch(query)
	if len(matches) == 0 {
		return false, 0, nil
	}

	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return false, 0, fmt.Errorf("invalid timeframe value: %v", err)
	}

	unit := matches[2]
	var days float64

	switch unit {
	case "m": // minutes
		days = value / (60 * 24)
	case "h": // hours
		days = value / 24
	case "d": // days
		days = value
	default:
		return false, 0, fmt.Errorf("unsupported timeframe unit: %s", unit)
	}

	return true, days, nil
}

// validateAndPrepareQuery validates the timeframe is within 30 days and prepares the query
func validateAndPrepareQuery(query string) (string, error) {
	hasTimeframe, days, err := parseTimeframe(query)
	if err != nil {
		return "", err
	}

	if hasTimeframe {
		if days > 30 {
			return "", fmt.Errorf("timeframe exceeds free tier limit of 30 days (%.1f days specified). Use 'run_lcql_query' for longer timeframes", days)
		}
		// Query already has a valid timeframe, use as-is
		return query, nil
	}

	// No timeframe, prepend -30d
	return "-30d | " + query, nil
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

			// Validate the LCQL query before executing
			if valid, errMsg := tools.ValidateLCQLQuery(org, query); !valid {
				return tools.ErrorResultf("invalid LCQL query: %s", errMsg), nil
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

// RegisterRunLCQLQueryFree registers the run_lcql_query_free tool (limited to 30 days)
func RegisterRunLCQLQueryFree() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "run_lcql_query_free",
		Description: "Run a LimaCharlie Query Language (LCQL) query limited to the last 30 days (free tier)",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("run_lcql_query_free",
			mcp.WithDescription("Run a LimaCharlie Query Language (LCQL) query limited to the last 30 days (free tier). Automatically adds '-30d' timeframe if not specified. If a timeframe is provided, it must be <= 30 days."),
			mcp.WithString("query",
				mcp.Required(),
				mcp.Description("The LCQL query to run (without timeframe, or with timeframe <= 30 days)")),
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

			// Validate and prepare query with timeframe
			preparedQuery, err := validateAndPrepareQuery(query)
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
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

			// Validate the LCQL query before executing
			if valid, errMsg := tools.ValidateLCQLQuery(org, preparedQuery); !valid {
				return tools.ErrorResultf("invalid LCQL query: %s", errMsg), nil
			}

			// Create query request with cursor-based pagination
			queryReq := lc.QueryRequest{
				Query:  preparedQuery,
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

// RegisterValidateLCQLQuery registers the validate_lcql_query tool.
// This tool validates LCQL query syntax without executing the query.
func RegisterValidateLCQLQuery() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "validate_lcql_query",
		Description: "Validate an LCQL query syntax without executing it",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("validate_lcql_query",
			mcp.WithDescription("Validate an LCQL (LimaCharlie Query Language) query syntax without executing it. Returns whether the query is valid and any syntax errors. Use analyze_lcql_query if you also need resource estimates."),
			mcp.WithString("query",
				mcp.Required(),
				mcp.Description("The LCQL query to validate")),
		),
		Handler: func(ctx context.Context, args map[string]any) (*mcp.CallToolResult, error) {
			// Extract query
			query, ok := args["query"].(string)
			if !ok || query == "" {
				return tools.ErrorResult("query parameter is required"), nil
			}

			// Get organization client (supports both real and mock implementations)
			org, err := tools.GetOrganizationClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Validate the LCQL query
			valid, errMsg := tools.ValidateLCQLQuery(org, query)

			response := map[string]any{
				"valid": valid,
				"query": query,
			}

			if !valid {
				response["error"] = errMsg
			}

			return tools.SuccessResult(response), nil
		},
	})
}

// RegisterEstimateLCQLQuery registers the estimate_lcql_query tool.
// This tool returns resource estimates for an LCQL query without executing it.
func RegisterEstimateLCQLQuery() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "estimate_lcql_query",
		Description: "Get resource estimates for an LCQL query without executing it",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("estimate_lcql_query",
			mcp.WithDescription("Get resource estimates for an LCQL (LimaCharlie Query Language) query without executing it. Returns estimated number of events, evaluations, and processing time. Use this to understand query cost before running."),
			mcp.WithString("query",
				mcp.Required(),
				mcp.Description("The LCQL query to estimate")),
		),
		Handler: func(ctx context.Context, args map[string]any) (*mcp.CallToolResult, error) {
			// Extract query
			query, ok := args["query"].(string)
			if !ok || query == "" {
				return tools.ErrorResult("query parameter is required"), nil
			}

			// Get organization client (supports both real and mock implementations)
			org, err := tools.GetOrganizationClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get full validation result including estimates
			result := tools.ValidateLCQLQueryFull(org, query)

			// Return error if query is invalid
			if !result.Valid {
				return tools.ErrorResultf("invalid query: %s", result.Error), nil
			}

			response := map[string]any{
				"query":      query,
				"num_evals":  result.NumEvals,
				"num_events": result.NumEvents,
				"eval_time":  result.EvalTime,
			}

			return tools.SuccessResult(response), nil
		},
	})
}

// RegisterAnalyzeLCQLQuery registers the analyze_lcql_query tool.
// This tool validates and estimates an LCQL query without executing it.
func RegisterAnalyzeLCQLQuery() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "analyze_lcql_query",
		Description: "Validate and estimate an LCQL query without executing it",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("analyze_lcql_query",
			mcp.WithDescription("Analyze an LCQL (LimaCharlie Query Language) query without executing it. Returns both validation status and resource estimates (number of events, evaluations, processing time). Use this for complete query analysis before running."),
			mcp.WithString("query",
				mcp.Required(),
				mcp.Description("The LCQL query to analyze")),
		),
		Handler: func(ctx context.Context, args map[string]any) (*mcp.CallToolResult, error) {
			// Extract query
			query, ok := args["query"].(string)
			if !ok || query == "" {
				return tools.ErrorResult("query parameter is required"), nil
			}

			// Get organization client (supports both real and mock implementations)
			org, err := tools.GetOrganizationClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get full validation result including estimates
			result := tools.ValidateLCQLQueryFull(org, query)

			response := map[string]any{
				"query":      query,
				"valid":      result.Valid,
				"num_evals":  result.NumEvals,
				"num_events": result.NumEvents,
				"eval_time":  result.EvalTime,
			}

			if !result.Valid {
				response["error"] = result.Error
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
			mcp.WithString("sid",
				mcp.Description("Optional sensor ID to filter detections by")),
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
			start := int(startFloat)

			endFloat, ok := args["end"].(float64)
			if !ok {
				return tools.ErrorResult("end parameter is required"), nil
			}
			end := int(endFloat)

			// Get organization
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Extract optional parameters
			sid := ""
			if sidStr, ok := args["sid"].(string); ok {
				sid = sidStr
			}

			cat := ""
			if catStr, ok := args["cat"].(string); ok {
				cat = catStr
			}

			limit := 0 // 0 means no limit
			if limitFloat, ok := args["limit"].(float64); ok {
				limit = int(limitFloat)
			}

			// Create the request
			req := lc.HistoricalDetectionsRequest{
				SID:    sid,
				Cat:    cat,
				Cursor: "-", // Start from the beginning
				Start:  start,
				End:    end,
				Limit:  limit,
			}

			// Fetch all detections with pagination
			allDetects := make([]lc.Detect, 0)
			for {
				resp, err := org.HistoricalDetections(req)
				if err != nil {
					return tools.ErrorResultf("failed to get historical detections: %v", err), nil
				}

				allDetects = append(allDetects, resp.Detects...)

				// Check if there's a next cursor
				if resp.NextCursor == "" {
					break
				}

				// Check if we've reached the limit
				if limit > 0 && len(allDetects) >= limit {
					allDetects = allDetects[:limit]
					break
				}

				// Update cursor for next iteration
				req.Cursor = resp.NextCursor
			}

			result := map[string]interface{}{
				"detections": allDetects,
				"count":      len(allDetects),
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterGetDetection registers the get_detection tool
func RegisterGetDetection() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_detection",
		Description: "Get a specific detection by its detection ID",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("get_detection",
			mcp.WithDescription("Get a specific detection by its detection ID (detect_id/atom)"),
			mcp.WithString("detection_id",
				mcp.Required(),
				mcp.Description("The detection ID (detect_id/atom) to retrieve")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract detection_id parameter
			detectionID, ok := args["detection_id"].(string)
			if !ok || detectionID == "" {
				return tools.ErrorResult("detection_id parameter is required"), nil
			}

			// Get organization
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Make GET request to /insight/{oid}/detections/{detection_id}
			path := fmt.Sprintf("insight/%s/detections/%s", org.GetOID(), detectionID)
			var response lc.Dict
			if err := org.GenericGETRequest(path, nil, &response); err != nil {
				return tools.ErrorResultf("failed to get detection: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"detection": response,
			}), nil
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
			mcp.WithDescription("Search for Indicators of Compromise (IOCs) across the organization. Supports wildcards using '%' character (e.g., '%svchost.exe' for prefix match)."),
			mcp.WithString("ioc_type",
				mcp.Required(),
				mcp.Description("Type of IOC: 'file_hash', 'domain', 'ip', 'file_path', 'file_name', 'user', 'service_name', 'package_name', 'hostname'")),
			mcp.WithString("ioc_value",
				mcp.Required(),
				mcp.Description("The IOC value to search for (supports wildcards with % character, e.g., '%svchost.exe')")),
			mcp.WithString("info_type",
				mcp.Required(),
				mcp.Description("Type of information to retrieve: 'summary' (occurrence counts) or 'locations' (specific sensor locations)")),
			mcp.WithBoolean("case_sensitive",
				mcp.Description("Whether the search should be case-sensitive (default: false, always false for location searches)")),
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

			caseSensitive := false
			if cs, ok := args["case_sensitive"].(bool); ok {
				caseSensitive = cs
			}

			// Get organization
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Handle hostname specially (different endpoint)
			if iocType == "hostname" {
				results, err := org.SearchHostname(iocValue)
				if err != nil {
					return tools.ErrorResultf("failed to search hostname: %v", err), nil
				}

				// Format results for better readability
				formattedResults := make([]map[string]interface{}, len(results))
				for i, result := range results {
					formattedResults[i] = map[string]interface{}{
						"sensor_id": result.SID,
						"hostname":  result.Hostname,
					}
				}

				return tools.SuccessResult(map[string]interface{}{
					"ioc_type":  "hostname",
					"ioc_value": iocValue,
					"count":     len(results),
					"results":   formattedResults,
				}), nil
			}

			// Map IOC type to InsightObjectType
			var objectType lc.InsightObjectType
			switch iocType {
			case "hash", "file_hash":
				objectType = lc.InsightObjectTypes.FileHash
			case "domain":
				objectType = lc.InsightObjectTypes.Domain
			case "ip":
				objectType = lc.InsightObjectTypes.IP
			case "file_path":
				objectType = lc.InsightObjectTypes.FilePath
			case "file_name":
				objectType = lc.InsightObjectTypes.FileName
			case "user", "username":
				objectType = lc.InsightObjectTypes.Username
			case "service_name":
				objectType = lc.InsightObjectTypes.ServiceName
			case "package_name":
				objectType = lc.InsightObjectTypes.PackageName
			default:
				return tools.ErrorResultf("unsupported ioc_type '%s'. Valid types: file_hash, domain, ip, file_path, file_name, user, service_name, package_name, hostname", iocType), nil
			}

			// Create search parameters
			params := lc.IOCSearchParams{
				SearchTerm:    iocValue,
				ObjectType:    objectType,
				CaseSensitive: caseSensitive,
			}

			// Execute search based on info type
			switch infoType {
			case "summary":
				resp, err := org.SearchIOCSummary(params)
				if err != nil {
					return tools.ErrorResultf("failed to search IOC summary: %v", err), nil
				}

				// Format response for better readability
				result := map[string]interface{}{
					"ioc_type":   string(resp.Type),
					"ioc_value":  resp.Name,
					"from_cache": resp.FromCache,
				}

				// Handle time range counts (can be number or map)
				if resp.Last1Days != nil {
					if resp.Last1Days.IsWildcard() {
						result["last_1_days"] = resp.Last1Days.AsMap()
					} else {
						result["last_1_days"] = resp.Last1Days.AsNumber()
					}
				}

				if resp.Last7Days != nil {
					if resp.Last7Days.IsWildcard() {
						result["last_7_days"] = resp.Last7Days.AsMap()
					} else {
						result["last_7_days"] = resp.Last7Days.AsNumber()
					}
				}

				if resp.Last30Days != nil {
					if resp.Last30Days.IsWildcard() {
						result["last_30_days"] = resp.Last30Days.AsMap()
					} else {
						result["last_30_days"] = resp.Last30Days.AsNumber()
					}
				}

				if resp.Last365Days != nil {
					if resp.Last365Days.IsWildcard() {
						result["last_365_days"] = resp.Last365Days.AsMap()
					} else {
						result["last_365_days"] = resp.Last365Days.AsNumber()
					}
				}

				return tools.SuccessResult(result), nil

			case "locations", "location":
				resp, err := org.SearchIOCLocations(params)
				if err != nil {
					return tools.ErrorResultf("failed to search IOC locations: %v", err), nil
				}

				// Format locations as an array for easier consumption
				locations := make([]map[string]interface{}, 0, len(resp.Locations))
				for sensorID, loc := range resp.Locations {
					locations = append(locations, map[string]interface{}{
						"sensor_id": sensorID,
						"hostname":  loc.Hostname,
						"first_ts":  loc.FirstTS,
						"last_ts":   loc.LastTS,
					})
				}

				result := map[string]interface{}{
					"ioc_type":   string(resp.Type),
					"ioc_value":  resp.Name,
					"from_cache": resp.FromCache,
					"count":      len(locations),
					"locations":  locations,
				}

				return tools.SuccessResult(result), nil

			default:
				return tools.ErrorResultf("unsupported info_type '%s'. Valid types: summary, locations", infoType), nil
			}
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
			// Extract parameters
			iocsJSON, ok := args["iocs"].(string)
			if !ok || iocsJSON == "" {
				return tools.ErrorResult("iocs parameter is required"), nil
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

			// Parse IOCs JSON array
			var iocList []map[string]string
			if err := json.Unmarshal([]byte(iocsJSON), &iocList); err != nil {
				return tools.ErrorResultf("failed to parse iocs JSON: %v", err), nil
			}

			// Build the objects map for batch request
			objects := make(map[lc.InsightObjectType][]string)
			for _, ioc := range iocList {
				iocType, ok := ioc["type"]
				if !ok {
					return tools.ErrorResult("each IOC must have a 'type' field"), nil
				}
				iocValue, ok := ioc["value"]
				if !ok {
					return tools.ErrorResult("each IOC must have a 'value' field"), nil
				}

				// Map IOC type to InsightObjectType
				var objectType lc.InsightObjectType
				switch iocType {
				case "hash", "file_hash":
					objectType = lc.InsightObjectTypes.FileHash
				case "domain":
					objectType = lc.InsightObjectTypes.Domain
				case "ip":
					objectType = lc.InsightObjectTypes.IP
				case "file_path":
					objectType = lc.InsightObjectTypes.FilePath
				case "file_name":
					objectType = lc.InsightObjectTypes.FileName
				case "user", "username":
					objectType = lc.InsightObjectTypes.Username
				case "service_name":
					objectType = lc.InsightObjectTypes.ServiceName
				case "package_name":
					objectType = lc.InsightObjectTypes.PackageName
				default:
					return tools.ErrorResultf("unsupported ioc_type '%s'. Valid types: hash, domain, ip, file_path, file_name, user, service_name, package_name", iocType), nil
				}

				// Add to objects map
				objects[objectType] = append(objects[objectType], iocValue)
			}

			// Create the batch request
			req := lc.InsightObjectsBatchRequest{
				Objects:         objects,
				IsCaseSensitive: false, // Default to case insensitive
			}

			// Call InsightObjectsBatch
			resp, err := org.InsightObjectsBatch(req)
			if err != nil {
				return tools.ErrorResultf("failed to batch search IOCs: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
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
			mcp.WithDescription("Get the time range when a sensor has telemetry data. Time range must be less than 30 days."),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithNumber("start",
				mcp.Required(),
				mcp.Description("Start timestamp in Unix epoch seconds")),
			mcp.WithNumber("end",
				mcp.Required(),
				mcp.Description("End timestamp in Unix epoch seconds")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, ok := args["sid"].(string)
			if !ok {
				return tools.ErrorResult("sid parameter is required"), nil
			}

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

			// Validate time range (must be less than 30 days)
			if end-start > 30*24*3600 {
				return tools.ErrorResult("time range must be less than 30 days"), nil
			}

			// Get organization
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Use the SDK method which handles the correct API path and parameters
			timeline, err := org.GetTimeWhenSensorHasData(sid, start, end)
			if err != nil {
				return tools.ErrorResultf("failed to get sensor timeline: %v", err), nil
			}

			// Return the response
			resp := map[string]interface{}{
				"sid":        timeline.SID,
				"start":      timeline.Start,
				"end":        timeline.End,
				"timestamps": timeline.Timestamps,
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterGetEventByAtom registers the get_event_by_atom tool
func RegisterGetEventByAtom() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_event_by_atom",
		Description: "Get a specific event by its atom identifier",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("get_event_by_atom",
			mcp.WithDescription("Retrieve a specific event from Insight using its atom identifier. Requires both the sensor ID and atom."),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID) where the event originated")),
			mcp.WithString("atom",
				mcp.Required(),
				mcp.Description("The atom identifier of the event to retrieve")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract and validate SID
			sid, err := tools.ExtractAndValidateSID(args)
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			// Extract atom parameter
			atom, ok := args["atom"].(string)
			if !ok || atom == "" {
				return tools.ErrorResult("atom parameter is required"), nil
			}

			// Get organization
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Make GET request to /insight/{oid}/{sid}/{atom}
			path := fmt.Sprintf("insight/%s/%s/%s", org.GetOID(), sid, atom)
			var response lc.Dict
			if err := org.GenericGETRequest(path, nil, &response); err != nil {
				return tools.ErrorResultf("failed to get event: %v", err), nil
			}

			return tools.SuccessResult(response), nil
		},
	})
}

// RegisterGetAtomChildren registers the get_atom_children tool
func RegisterGetAtomChildren() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_atom_children",
		Description: "Get all children (descendants) of a specific atom",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("get_atom_children",
			mcp.WithDescription("Retrieve all child events (descendants) of a specific atom from Insight. This is useful for tracing the process tree and understanding the full execution chain from a parent event."),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID) where the events originated")),
			mcp.WithString("atom",
				mcp.Required(),
				mcp.Description("The parent atom identifier to get children for")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract and validate SID
			sid, err := tools.ExtractAndValidateSID(args)
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			// Extract atom parameter
			atom, ok := args["atom"].(string)
			if !ok || atom == "" {
				return tools.ErrorResult("atom parameter is required"), nil
			}

			// Get organization
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Make GET request to /insight/{oid}/{sid}/{atom}/children
			path := fmt.Sprintf("insight/%s/%s/%s/children", org.GetOID(), sid, atom)
			var response lc.Dict
			if err := org.GenericGETRequest(path, nil, &response); err != nil {
				return tools.ErrorResultf("failed to get atom children: %v", err), nil
			}

			return tools.SuccessResult(response), nil
		},
	})
}
