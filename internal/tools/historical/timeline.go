package historical

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	RegisterExpandTimeline()
}

// RegisterExpandTimeline registers the expand_timeline tool
func RegisterExpandTimeline() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "expand_timeline",
		Description: "Expand a timeline by fetching full event and detection data for all references",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("expand_timeline",
			mcp.WithDescription("Expand a timeline by fetching full event and detection data for all references. Provide either a timeline object or a timeline_name to fetch from Hive."),
			mcp.WithObject("timeline",
				mcp.Description("Timeline object to expand (mutually exclusive with timeline_name)")),
			mcp.WithString("timeline_name",
				mcp.Description("Name of timeline stored in Hive to fetch and expand (mutually exclusive with timeline)")),
		),
		Handler: handleExpandTimeline,
	})
}

func handleExpandTimeline(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	// Parameter validation
	timeline, hasTimeline := args["timeline"].(map[string]interface{})
	timelineName, _ := args["timeline_name"].(string)
	hasTimelineName := timelineName != ""

	if !hasTimeline && !hasTimelineName {
		return tools.ErrorResult("either 'timeline' or 'timeline_name' parameter is required"), nil
	}
	if hasTimeline && hasTimelineName {
		return tools.ErrorResult("'timeline' and 'timeline_name' are mutually exclusive - provide only one"), nil
	}

	// Get organization
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return tools.ErrorResultf("failed to get organization: %v", err), nil
	}

	// Build request
	reqData := lc.Dict{}
	if hasTimeline {
		reqData["timeline"] = timeline
	} else {
		reqData["timeline_name"] = timelineName
	}

	// Call API
	var response map[string]interface{}
	endpoint := fmt.Sprintf("orgs/%s/timeline/expand", org.GetOID())

	if err := org.GenericPOSTRequest(endpoint, reqData, &response); err != nil {
		return tools.ErrorResultf("failed to expand timeline: %v", err), nil
	}

	return tools.SuccessResult(response), nil
}
