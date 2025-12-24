package historical

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	RegisterExpandInvestigation()
}

// RegisterExpandInvestigation registers the expand_investigation tool
func RegisterExpandInvestigation() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "expand_investigation",
		Description: "Expand an investigation by fetching full event and detection data for all references",
		Profile:     "investigation_management",
		RequiresOID: true,
		Schema: mcp.NewTool("expand_investigation",
			mcp.WithDescription("Expand an investigation by fetching full event and detection data for all references. Provide either an investigation object or an investigation_name to fetch from Hive."),
			mcp.WithObject("investigation",
				mcp.Description("Investigation object to expand (mutually exclusive with investigation_name)")),
			mcp.WithString("investigation_name",
				mcp.Description("Name of investigation stored in Hive to fetch and expand (mutually exclusive with investigation)")),
		),
		Handler: handleExpandInvestigation,
	})
}

func handleExpandInvestigation(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	// Parameter validation
	investigation, hasInvestigation := args["investigation"].(map[string]interface{})
	investigationName, _ := args["investigation_name"].(string)
	hasInvestigationName := investigationName != ""

	if !hasInvestigation && !hasInvestigationName {
		return tools.ErrorResult("either 'investigation' or 'investigation_name' parameter is required"), nil
	}
	if hasInvestigation && hasInvestigationName {
		return tools.ErrorResult("'investigation' and 'investigation_name' are mutually exclusive - provide only one"), nil
	}

	// Get organization
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return tools.ErrorResultf("failed to get organization: %v", err), nil
	}

	// Build request
	reqData := lc.Dict{}
	if hasInvestigation {
		reqData["investigation"] = investigation
	} else {
		reqData["investigation_name"] = investigationName
	}

	// Call API
	var response map[string]interface{}
	endpoint := fmt.Sprintf("orgs/%s/investigation/expand", org.GetOID())

	if err := org.GenericPOSTRequest(endpoint, reqData, &response); err != nil {
		return tools.ErrorResultf("failed to expand investigation: %v", err), nil
	}

	return tools.SuccessResult(response), nil
}
