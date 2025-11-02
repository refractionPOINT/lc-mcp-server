package hive

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register saved query management tools
	RegisterListSavedQueries()
	RegisterGetSavedQuery()
	RegisterSetSavedQuery()
	RegisterDeleteSavedQuery()
	RegisterRunSavedQuery()
}

// RegisterListSavedQueries registers the list_saved_queries tool
func RegisterListSavedQueries() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_saved_queries",
		Description: "List all saved LCQL queries",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("list_saved_queries",
			mcp.WithDescription("List all saved LCQL queries"),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for saved queries
			hive := lc.NewHiveClient(org)

			// List all saved queries from the query hive
			queries, err := hive.List(lc.HiveArgs{
				HiveName:     "query",
				PartitionKey: "global",
			})
			if err != nil {
				return tools.ErrorResultf("failed to list saved queries: %v", err), nil
			}

			// Convert to response format
			result := make(map[string]interface{})
			for name, data := range queries {
				result[name] = map[string]interface{}{
					"data":     data.Data,
					"enabled":  data.UsrMtd.Enabled,
					"tags":     data.UsrMtd.Tags,
					"comment":  data.UsrMtd.Comment,
					"metadata": data.SysMtd,
				}
			}

			return tools.SuccessResult(map[string]interface{}{
				"queries": result,
				"count":   len(result),
			}), nil
		},
	})
}

// RegisterGetSavedQuery registers the get_saved_query tool
func RegisterGetSavedQuery() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_saved_query",
		Description: "Get a specific saved query",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("get_saved_query",
			mcp.WithDescription("Get a specific saved query"),
			mcp.WithString("query_name",
				mcp.Required(),
				mcp.Description("Name of the saved query to retrieve")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			queryName, ok := args["query_name"].(string)
			if !ok || queryName == "" {
				return tools.ErrorResult("query_name parameter is required"), nil
			}

			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for saved queries
			hive := lc.NewHiveClient(org)

			// Get saved query
			query, err := hive.Get(lc.HiveArgs{
				HiveName:     "query",
				PartitionKey: "global",
				Key:          queryName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get saved query '%s': %v", queryName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"query": map[string]interface{}{
					"name":    queryName,
					"data":    query.Data,
					"enabled": query.UsrMtd.Enabled,
					"tags":    query.UsrMtd.Tags,
					"comment": query.UsrMtd.Comment,
					"metadata": map[string]interface{}{
						"created_at":  query.SysMtd.CreatedAt,
						"created_by":  query.SysMtd.CreatedBy,
						"last_mod":    query.SysMtd.LastMod,
						"last_author": query.SysMtd.LastAuthor,
						"guid":        query.SysMtd.GUID,
					},
				},
			}), nil
		},
	})
}

// RegisterSetSavedQuery registers the set_saved_query tool
func RegisterSetSavedQuery() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_saved_query",
		Description: "Save an LCQL query for later use",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("set_saved_query",
			mcp.WithDescription("Save an LCQL query for later use"),
			mcp.WithString("query_name",
				mcp.Required(),
				mcp.Description("Name for the saved query")),
			mcp.WithString("lcql_query",
				mcp.Required(),
				mcp.Description("The LCQL query string")),
			mcp.WithString("description",
				mcp.Description("Optional description of what the query does")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			queryName, ok := args["query_name"].(string)
			if !ok || queryName == "" {
				return tools.ErrorResult("query_name parameter is required"), nil
			}

			lcqlQuery, ok := args["lcql_query"].(string)
			if !ok || lcqlQuery == "" {
				return tools.ErrorResult("lcql_query parameter is required"), nil
			}

			description, _ := args["description"].(string)

			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for saved queries
			hive := lc.NewHiveClient(org)

			// Create query data
			queryData := map[string]interface{}{
				"query": lcqlQuery,
			}
			if description != "" {
				queryData["description"] = description
			}

			// Set saved query
			enabled := true
			_, err = hive.Add(lc.HiveArgs{
				HiveName:     "query",
				PartitionKey: "global",
				Key:          queryName,
				Data:         lc.Dict(queryData),
				Enabled:      &enabled,
			})
			if err != nil {
				return tools.ErrorResultf("failed to save query '%s': %v", queryName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully saved query '%s'", queryName),
			}), nil
		},
	})
}

// RegisterDeleteSavedQuery registers the delete_saved_query tool
func RegisterDeleteSavedQuery() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_saved_query",
		Description: "Delete a saved query",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_saved_query",
			mcp.WithDescription("Delete a saved query"),
			mcp.WithString("query_name",
				mcp.Required(),
				mcp.Description("Name of the saved query to delete")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			queryName, ok := args["query_name"].(string)
			if !ok || queryName == "" {
				return tools.ErrorResult("query_name parameter is required"), nil
			}

			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for saved queries
			hive := lc.NewHiveClient(org)

			// Delete saved query
			_, err = hive.Remove(lc.HiveArgs{
				HiveName:     "query",
				PartitionKey: "global",
				Key:          queryName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to delete saved query '%s': %v", queryName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted saved query '%s'", queryName),
			}), nil
		},
	})
}

// RegisterRunSavedQuery registers the run_saved_query tool
func RegisterRunSavedQuery() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "run_saved_query",
		Description: "Execute a saved query",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("run_saved_query",
			mcp.WithDescription("Execute a saved query"),
			mcp.WithString("query_name",
				mcp.Required(),
				mcp.Description("Name of the saved query to run")),
			mcp.WithNumber("limit",
				mcp.Description("Maximum number of results to return (default 100)")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			queryName, ok := args["query_name"].(string)
			if !ok || queryName == "" {
				return tools.ErrorResult("query_name parameter is required"), nil
			}

			limit := 100
			if limitParam, ok := args["limit"].(float64); ok {
				limit = int(limitParam)
			}

			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client to get the saved query
			hive := lc.NewHiveClient(org)

			// Get saved query
			savedQuery, err := hive.Get(lc.HiveArgs{
				HiveName:     "query",
				PartitionKey: "global",
				Key:          queryName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get saved query '%s': %v", queryName, err), nil
			}

			// Extract the query string from the data
			queryStr, ok := savedQuery.Data["query"].(string)
			if !ok {
				return tools.ErrorResult("saved query does not contain a valid query string"), nil
			}

			// Execute the query
			queryResp, err := org.Query(lc.QueryRequest{
				Query:      queryStr,
				LimitEvent: limit,
			})
			if err != nil {
				return tools.ErrorResultf("failed to execute query: %v", err), nil
			}

			// Extract events from response
			events := make([]interface{}, 0)
			if queryResp.Results != nil {
				for _, evt := range queryResp.Results {
					events = append(events, evt)
				}
			}

			return tools.SuccessResult(map[string]interface{}{
				"results":   events,
				"count":     len(events),
				"has_more":  queryResp.Cursor != "",
				"cursor":    queryResp.Cursor,
				"query_str": queryStr,
			}), nil
		},
	})
}
