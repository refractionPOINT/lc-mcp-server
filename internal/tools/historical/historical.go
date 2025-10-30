package historical

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register historical data tools
	RegisterRunLCQLQuery()
	RegisterGetHistoricDetections()
	RegisterSearchIOCs()
}

// getSDKCache retrieves the SDK cache from context
func getSDKCache(ctx context.Context) (*auth.SDKCache, error) {
	return auth.GetSDKCache(ctx)
}

// getOrganization retrieves or creates an Organization instance from context
func getOrganization(ctx context.Context) (*lc.Organization, error) {
	cache, err := getSDKCache(ctx)
	if err != nil {
		return nil, err
	}

	return cache.GetFromContext(ctx)
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
				mcp.Description("Maximum number of results to return (default: 100)")),
			mcp.WithString("stream",
				mcp.Description("Stream to query: 'event', 'detect', or 'audit' (default: 'event')")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract query
			query, ok := args["query"].(string)
			if !ok || query == "" {
				return tools.ErrorResult("query parameter is required"), nil
			}

			// Extract limit (default 100)
			limit := 100
			if limitFloat, ok := args["limit"].(float64); ok {
				limit = int(limitFloat)
			}

			// Extract stream (default "event")
			stream := "event"
			if streamStr, ok := args["stream"].(string); ok && streamStr != "" {
				stream = streamStr
			}

			// Handle OID switching for UID mode
			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}
			}

			// Get organization
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// TODO: Go SDK needs Query() method
			// Need to add: func (org *Organization) Query(query string, stream string, limit int) ([]map[string]interface{}, error)
			// For now, return error indicating SDK limitation
			_ = org // Use org to avoid unused variable error
			_ = query
			_ = stream
			_ = limit

			result := map[string]interface{}{
				"error":   "not_implemented",
				"message": "Go SDK does not yet have Query() method. Need to add to go-limacharlie SDK.",
			}

			return tools.SuccessResult(result), nil
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
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
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

			// Handle OID switching for UID mode
			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}
			}

			// Get organization
			org, err := getOrganization(ctx)
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
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
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

			// Handle OID switching for UID mode
			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}
			}

			// Get organization
			org, err := getOrganization(ctx)
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
