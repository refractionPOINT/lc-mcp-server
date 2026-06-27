package cases

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Case lifecycle
	RegisterCreateCase()
	RegisterListCases()
	RegisterGetCase()
	RegisterUpdateCase()
	RegisterBulkUpdateCases()
	RegisterMergeCases()
	RegisterAddCaseNote()

	// Investigation components
	RegisterListCaseEntities()
	RegisterSearchCaseEntities()
	RegisterAddCaseEntity()
	RegisterAddCaseDetection()
	RegisterAddCaseTelemetry()
	RegisterAddCaseArtifact()

	// Reporting
	RegisterGetCaseDashboard()
	RegisterGetCaseReport()
}

// toStringSlice converts a JSON array argument ([]interface{}) into a []string.
func toStringSlice(v interface{}) []string {
	raw, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// toIntSlice converts a JSON array argument ([]interface{}) of numbers into a []int.
func toIntSlice(v interface{}) []int {
	raw, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]int, 0, len(raw))
	for _, item := range raw {
		if f, ok := item.(float64); ok {
			out = append(out, int(f))
		}
	}
	return out
}

// getCaseNumber extracts a required integer case number argument.
func getCaseNumber(args map[string]interface{}, key string) (int, bool) {
	f, ok := args[key].(float64)
	if !ok {
		return 0, false
	}
	return int(f), true
}

// RegisterCreateCase registers the create_case tool.
func RegisterCreateCase() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "create_case",
		Description: "Create a new SOC case (via ext-cases). Optionally seed it with a detection, severity and summary.",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("create_case",
			mcp.WithDescription("Create a new SOC case (via ext-cases). Optionally seed it with a detection, severity and summary."),
			mcp.WithObject("detection",
				mcp.Description("Optional full LimaCharlie detection dict to seed the case with")),
			mcp.WithString("severity",
				mcp.Description("Optional case severity (critical, high, medium, low, info)")),
			mcp.WithString("summary",
				mcp.Description("Optional case summary (max 8192 chars)")),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			opts := lc.CreateCaseOptions{}
			if d, ok := args["detection"].(map[string]interface{}); ok {
				opts.Detection = lc.Dict(d)
			}
			if s, ok := args["severity"].(string); ok {
				opts.Severity = s
			}
			if s, ok := args["summary"].(string); ok {
				opts.Summary = s
			}

			resp, err := org.Cases().CreateCase(opts)
			if err != nil {
				return tools.ErrorResultf("failed to create case: %v", err), nil
			}
			return tools.SuccessResult(map[string]interface{}{"case": resp}), nil
		},
	})
}

// RegisterListCases registers the list_cases tool.
func RegisterListCases() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_cases",
		Description: "List cases with optional filters, sorting and pagination.",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("list_cases",
			mcp.WithDescription("List cases with optional filters, sorting and pagination."),
			mcp.WithArray("status",
				mcp.Description("Filter by status (new, in_progress, resolved, closed)")),
			mcp.WithArray("severity",
				mcp.Description("Filter by severity (critical, high, medium, low, info)")),
			mcp.WithArray("classification",
				mcp.Description("Filter by classification (pending, true_positive, false_positive)")),
			mcp.WithString("assignee",
				mcp.Description("Filter by assignee email")),
			mcp.WithString("search",
				mcp.Description("Full-text search across detection category and hostname")),
			mcp.WithString("sensor_id",
				mcp.Description("Filter to cases with any detection from this sensor ID")),
			mcp.WithArray("tag",
				mcp.Description("Filter by tag (multiple tags are AND-ed)")),
			mcp.WithString("sort",
				mcp.Description("Sort field (created_at, severity, case_number)")),
			mcp.WithString("order",
				mcp.Description("Sort order (asc, desc)")),
			mcp.WithNumber("page_size",
				mcp.Description("Page size (1-200, default 50)")),
			mcp.WithString("page_token",
				mcp.Description("Page token from a previous response")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			filters := lc.CaseListFilters{
				Status:         toStringSlice(args["status"]),
				Severity:       toStringSlice(args["severity"]),
				Classification: toStringSlice(args["classification"]),
				Tag:            toStringSlice(args["tag"]),
			}
			if s, ok := args["assignee"].(string); ok {
				filters.Assignee = s
			}
			if s, ok := args["search"].(string); ok {
				filters.Search = s
			}
			if s, ok := args["sensor_id"].(string); ok {
				filters.SensorID = s
			}
			if s, ok := args["sort"].(string); ok {
				filters.Sort = s
			}
			if s, ok := args["order"].(string); ok {
				filters.Order = s
			}
			if f, ok := args["page_size"].(float64); ok {
				filters.PageSize = int(f)
			}
			if s, ok := args["page_token"].(string); ok {
				filters.PageToken = s
			}

			resp, err := org.Cases().ListCases(filters)
			if err != nil {
				return tools.ErrorResultf("failed to list cases: %v", err), nil
			}
			return tools.SuccessResult(map[string]interface{}{"result": resp}), nil
		},
	})
}

// RegisterGetCase registers the get_case tool.
func RegisterGetCase() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_case",
		Description: "Get a single case by its case number, including the full event timeline.",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("get_case",
			mcp.WithDescription("Get a single case by its case number, including the full event timeline."),
			mcp.WithNumber("case_number",
				mcp.Required(),
				mcp.Description("The case number to retrieve")),
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

			resp, err := org.Cases().GetCase(caseNumber)
			if err != nil {
				return tools.ErrorResultf("failed to get case %d: %v", caseNumber, err), nil
			}
			return tools.SuccessResult(map[string]interface{}{"case": resp}), nil
		},
	})
}

// RegisterUpdateCase registers the update_case tool.
func RegisterUpdateCase() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "update_case",
		Description: "Update fields on a case (status, severity, assignees, classification, summary, conclusion, tags). Only provided fields are changed.",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("update_case",
			mcp.WithDescription("Update fields on a case (status, severity, assignees, classification, summary, conclusion, tags). Only provided fields are changed."),
			mcp.WithNumber("case_number",
				mcp.Required(),
				mcp.Description("The case number to update")),
			mcp.WithObject("fields",
				mcp.Required(),
				mcp.Description("Map of fields to update (status, severity, assignees, classification, summary, conclusion, tags)")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			caseNumber, ok := getCaseNumber(args, "case_number")
			if !ok {
				return tools.ErrorResult("case_number parameter is required and must be a number"), nil
			}
			fields, ok := args["fields"].(map[string]interface{})
			if !ok {
				return tools.ErrorResult("fields parameter is required and must be an object"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := org.Cases().UpdateCase(caseNumber, lc.Dict(fields))
			if err != nil {
				return tools.ErrorResultf("failed to update case %d: %v", caseNumber, err), nil
			}
			return tools.SuccessResult(map[string]interface{}{"case": resp}), nil
		},
	})
}

// RegisterBulkUpdateCases registers the bulk_update_cases tool.
func RegisterBulkUpdateCases() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "bulk_update_cases",
		Description: "Bulk-update up to 200 cases. The same fields are applied to every case number provided.",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("bulk_update_cases",
			mcp.WithDescription("Bulk-update up to 200 cases. The same fields are applied to every case number provided."),
			mcp.WithArray("case_numbers",
				mcp.Required(),
				mcp.Description("List of case numbers to update (max 200)")),
			mcp.WithObject("fields",
				mcp.Required(),
				mcp.Description("Map of fields to apply to all the given cases")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			caseNumbers := toIntSlice(args["case_numbers"])
			if len(caseNumbers) == 0 {
				return tools.ErrorResult("case_numbers parameter is required and must be a non-empty array of numbers"), nil
			}
			fields, ok := args["fields"].(map[string]interface{})
			if !ok {
				return tools.ErrorResult("fields parameter is required and must be an object"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := org.Cases().BulkUpdate(caseNumbers, lc.Dict(fields))
			if err != nil {
				return tools.ErrorResultf("failed to bulk-update cases: %v", err), nil
			}
			return tools.SuccessResult(map[string]interface{}{"result": resp}), nil
		},
	})
}

// RegisterMergeCases registers the merge_cases tool.
func RegisterMergeCases() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "merge_cases",
		Description: "Merge one or more source cases into a target case.",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("merge_cases",
			mcp.WithDescription("Merge one or more source cases into a target case."),
			mcp.WithNumber("target_case_number",
				mcp.Required(),
				mcp.Description("The case number that the source cases are merged into")),
			mcp.WithArray("source_case_numbers",
				mcp.Required(),
				mcp.Description("List of case numbers to merge into the target case")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			target, ok := getCaseNumber(args, "target_case_number")
			if !ok {
				return tools.ErrorResult("target_case_number parameter is required and must be a number"), nil
			}
			sources := toIntSlice(args["source_case_numbers"])
			if len(sources) == 0 {
				return tools.ErrorResult("source_case_numbers parameter is required and must be a non-empty array of numbers"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := org.Cases().Merge(target, sources)
			if err != nil {
				return tools.ErrorResultf("failed to merge cases: %v", err), nil
			}
			return tools.SuccessResult(map[string]interface{}{"result": resp}), nil
		},
	})
}

// RegisterAddCaseNote registers the add_case_note tool.
func RegisterAddCaseNote() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "add_case_note",
		Description: "Add a note to a case.",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("add_case_note",
			mcp.WithDescription("Add a note to a case."),
			mcp.WithNumber("case_number",
				mcp.Required(),
				mcp.Description("The case number to add the note to")),
			mcp.WithString("content",
				mcp.Required(),
				mcp.Description("The note content (max 8192 chars)")),
			mcp.WithString("note_type",
				mcp.Description("Note category (general, analysis, remediation, escalation, handoff, to_stakeholder, from_stakeholder)")),
			mcp.WithBoolean("is_public",
				mcp.Description("Whether the note is visible to stakeholders (default false)")),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			caseNumber, ok := getCaseNumber(args, "case_number")
			if !ok {
				return tools.ErrorResult("case_number parameter is required and must be a number"), nil
			}
			content, ok := args["content"].(string)
			if !ok || content == "" {
				return tools.ErrorResult("content parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			opts := lc.AddNoteOptions{}
			if s, ok := args["note_type"].(string); ok {
				opts.NoteType = s
			}
			if b, ok := args["is_public"].(bool); ok {
				opts.IsPublic = &b
			}

			resp, err := org.Cases().AddNote(caseNumber, content, opts)
			if err != nil {
				return tools.ErrorResultf("failed to add note to case %d: %v", caseNumber, err), nil
			}
			return tools.SuccessResult(map[string]interface{}{"result": resp}), nil
		},
	})
}
