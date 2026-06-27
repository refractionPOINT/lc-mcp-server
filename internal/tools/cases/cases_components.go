package cases

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// RegisterListCaseEntities registers the list_case_entities tool.
func RegisterListCaseEntities() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_case_entities",
		Description: "List entities (IOCs) linked to a case.",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("list_case_entities",
			mcp.WithDescription("List entities (IOCs) linked to a case."),
			mcp.WithNumber("case_number",
				mcp.Required(),
				mcp.Description("The case number whose entities to list")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			caseNumber, ok := getCaseNumber(args, "case_number")
			if !ok {
				return tools.ErrorResult("case_number parameter is required and must be a number"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := org.Cases().ListEntities(caseNumber)
			if err != nil {
				return tools.ErrorResultf("failed to list entities for case %d: %v", caseNumber, err), nil
			}
			return tools.SuccessResult(map[string]interface{}{"result": resp}), nil
		},
	})
}

// RegisterSearchCaseEntities registers the search_case_entities tool.
func RegisterSearchCaseEntities() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "search_case_entities",
		Description: "Search entities (IOCs) across cases by type and value.",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("search_case_entities",
			mcp.WithDescription("Search entities (IOCs) across cases by type and value."),
			mcp.WithString("entity_type",
				mcp.Required(),
				mcp.Description("Entity type (ip, domain, hash, url, user, email, file, process, registry, other)")),
			mcp.WithString("entity_value",
				mcp.Required(),
				mcp.Description("Entity value to search for")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			entityType, ok := args["entity_type"].(string)
			if !ok || entityType == "" {
				return tools.ErrorResult("entity_type parameter is required"), nil
			}
			entityValue, ok := args["entity_value"].(string)
			if !ok || entityValue == "" {
				return tools.ErrorResult("entity_value parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := org.Cases().SearchEntities(entityType, entityValue)
			if err != nil {
				return tools.ErrorResultf("failed to search entities: %v", err), nil
			}
			return tools.SuccessResult(map[string]interface{}{"result": resp}), nil
		},
	})
}

// RegisterAddCaseEntity registers the add_case_entity tool.
func RegisterAddCaseEntity() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "add_case_entity",
		Description: "Add an entity (IOC) to a case.",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("add_case_entity",
			mcp.WithDescription("Add an entity (IOC) to a case."),
			mcp.WithNumber("case_number",
				mcp.Required(),
				mcp.Description("The case number to add the entity to")),
			mcp.WithString("entity_type",
				mcp.Required(),
				mcp.Description("Entity type (ip, domain, hash, url, user, email, file, process, registry, other)")),
			mcp.WithString("entity_value",
				mcp.Required(),
				mcp.Description("Entity value (max 1024 chars)")),
			mcp.WithString("note",
				mcp.Description("Optional analyst note (max 2048 chars)")),
			mcp.WithString("verdict",
				mcp.Description("Optional verdict assessment")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			caseNumber, ok := getCaseNumber(args, "case_number")
			if !ok {
				return tools.ErrorResult("case_number parameter is required and must be a number"), nil
			}
			entityType, ok := args["entity_type"].(string)
			if !ok || entityType == "" {
				return tools.ErrorResult("entity_type parameter is required"), nil
			}
			entityValue, ok := args["entity_value"].(string)
			if !ok || entityValue == "" {
				return tools.ErrorResult("entity_value parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			opts := lc.EntityOptions{}
			if s, ok := args["note"].(string); ok {
				opts.Note = s
			}
			if s, ok := args["verdict"].(string); ok {
				opts.Verdict = s
			}

			resp, err := org.Cases().AddEntity(caseNumber, entityType, entityValue, opts)
			if err != nil {
				return tools.ErrorResultf("failed to add entity to case %d: %v", caseNumber, err), nil
			}
			return tools.SuccessResult(map[string]interface{}{"result": resp}), nil
		},
	})
}

// RegisterAddCaseDetection registers the add_case_detection tool.
func RegisterAddCaseDetection() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "add_case_detection",
		Description: "Link a detection to a case. The backend extracts detect_id, cat, source, routing and detect_mtd automatically.",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("add_case_detection",
			mcp.WithDescription("Link a detection to a case. The backend extracts detect_id, cat, source, routing and detect_mtd automatically."),
			mcp.WithNumber("case_number",
				mcp.Required(),
				mcp.Description("The case number to add the detection to")),
			mcp.WithObject("detection",
				mcp.Required(),
				mcp.Description("A full LimaCharlie detection dict")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			caseNumber, ok := getCaseNumber(args, "case_number")
			if !ok {
				return tools.ErrorResult("case_number parameter is required and must be a number"), nil
			}
			detection, ok := args["detection"].(map[string]interface{})
			if !ok {
				return tools.ErrorResult("detection parameter is required and must be an object"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := org.Cases().AddDetection(caseNumber, lc.Dict(detection))
			if err != nil {
				return tools.ErrorResultf("failed to add detection to case %d: %v", caseNumber, err), nil
			}
			return tools.SuccessResult(map[string]interface{}{"result": resp}), nil
		},
	})
}

// RegisterAddCaseTelemetry registers the add_case_telemetry tool.
func RegisterAddCaseTelemetry() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "add_case_telemetry",
		Description: "Link a telemetry event reference to a case. The backend extracts routing.this (atom), routing.sid and routing.event_type automatically.",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("add_case_telemetry",
			mcp.WithDescription("Link a telemetry event reference to a case. The backend extracts routing.this (atom), routing.sid and routing.event_type automatically."),
			mcp.WithNumber("case_number",
				mcp.Required(),
				mcp.Description("The case number to add the telemetry to")),
			mcp.WithObject("event",
				mcp.Required(),
				mcp.Description("A full LimaCharlie event dict")),
			mcp.WithString("note",
				mcp.Description("Optional analyst note (max 2048 chars)")),
			mcp.WithString("verdict",
				mcp.Description("Optional verdict assessment")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			caseNumber, ok := getCaseNumber(args, "case_number")
			if !ok {
				return tools.ErrorResult("case_number parameter is required and must be a number"), nil
			}
			event, ok := args["event"].(map[string]interface{})
			if !ok {
				return tools.ErrorResult("event parameter is required and must be an object"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			opts := lc.TelemetryOptions{}
			if s, ok := args["note"].(string); ok {
				opts.Note = s
			}
			if s, ok := args["verdict"].(string); ok {
				opts.Verdict = s
			}

			resp, err := org.Cases().AddTelemetry(caseNumber, lc.Dict(event), opts)
			if err != nil {
				return tools.ErrorResultf("failed to add telemetry to case %d: %v", caseNumber, err), nil
			}
			return tools.SuccessResult(map[string]interface{}{"result": resp}), nil
		},
	})
}

// RegisterAddCaseArtifact registers the add_case_artifact tool.
func RegisterAddCaseArtifact() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "add_case_artifact",
		Description: "Add a forensic artifact reference to a case.",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("add_case_artifact",
			mcp.WithDescription("Add a forensic artifact reference to a case."),
			mcp.WithNumber("case_number",
				mcp.Required(),
				mcp.Description("The case number to add the artifact to")),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The artifact path or location")),
			mcp.WithString("source",
				mcp.Required(),
				mcp.Description("The artifact source identifier")),
			mcp.WithString("artifact_type",
				mcp.Description("Optional artifact type (e.g. pcap, memory_dump)")),
			mcp.WithString("note",
				mcp.Description("Optional analyst note (max 2048 chars)")),
			mcp.WithString("verdict",
				mcp.Description("Optional verdict assessment")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			caseNumber, ok := getCaseNumber(args, "case_number")
			if !ok {
				return tools.ErrorResult("case_number parameter is required and must be a number"), nil
			}
			path, ok := args["path"].(string)
			if !ok || path == "" {
				return tools.ErrorResult("path parameter is required"), nil
			}
			source, ok := args["source"].(string)
			if !ok || source == "" {
				return tools.ErrorResult("source parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			opts := lc.ArtifactOptions{}
			if s, ok := args["artifact_type"].(string); ok {
				opts.ArtifactType = s
			}
			if s, ok := args["note"].(string); ok {
				opts.Note = s
			}
			if s, ok := args["verdict"].(string); ok {
				opts.Verdict = s
			}

			resp, err := org.Cases().AddArtifact(caseNumber, path, source, opts)
			if err != nil {
				return tools.ErrorResultf("failed to add artifact to case %d: %v", caseNumber, err), nil
			}
			return tools.SuccessResult(map[string]interface{}{"result": resp}), nil
		},
	})
}

// RegisterGetCaseDashboard registers the get_case_dashboard tool.
func RegisterGetCaseDashboard() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_case_dashboard",
		Description: "Get real-time case dashboard counts by status/severity with SLA breaches.",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("get_case_dashboard",
			mcp.WithDescription("Get real-time case dashboard counts by status/severity with SLA breaches."),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := org.Cases().DashboardCounts()
			if err != nil {
				return tools.ErrorResultf("failed to get case dashboard: %v", err), nil
			}
			return tools.SuccessResult(map[string]interface{}{"dashboard": resp}), nil
		},
	})
}

// RegisterGetCaseReport registers the get_case_report tool.
func RegisterGetCaseReport() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_case_report",
		Description: "Get a comprehensive SOC report with MTTA/MTTR/TP-FP metrics over a time range.",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("get_case_report",
			mcp.WithDescription("Get a comprehensive SOC report with MTTA/MTTR/TP-FP metrics over a time range."),
			mcp.WithString("from",
				mcp.Required(),
				mcp.Description("Start of the report range (RFC3339)")),
			mcp.WithString("to",
				mcp.Required(),
				mcp.Description("End of the report range (RFC3339)")),
			mcp.WithString("group_by",
				mcp.Description("Optional field to segment the data by (e.g. severity, region)")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			timeFrom, ok := args["from"].(string)
			if !ok || timeFrom == "" {
				return tools.ErrorResult("from parameter is required"), nil
			}
			timeTo, ok := args["to"].(string)
			if !ok || timeTo == "" {
				return tools.ErrorResult("to parameter is required"), nil
			}
			groupBy := ""
			if s, ok := args["group_by"].(string); ok {
				groupBy = s
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := org.Cases().ReportSummary(timeFrom, timeTo, groupBy)
			if err != nil {
				return tools.ErrorResultf("failed to get case report: %v", err), nil
			}
			return tools.SuccessResult(map[string]interface{}{"report": resp}), nil
		},
	})
}
