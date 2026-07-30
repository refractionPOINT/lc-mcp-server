package forensics

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register YARA scanning tools
	RegisterYARAScanProcess()
	RegisterYARAScanFile()
	RegisterYARAScanDirectory()
	RegisterYARAScanMemory()
}

// RegisterYARAScanProcess registers the yara_scan_process tool
func RegisterYARAScanProcess() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "yara_scan_process",
		Description: "Scan a specific process with YARA rules",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("yara_scan_process",
			mcp.WithDescription("Scan a specific process with YARA rules"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithString("rule",
				mcp.Required(),
				mcp.Description(`The rule to compile and run: a literal YARA rule, a LimaCharlie YARA resource reference like "lcr://service/yara/my-source", an "https://" URL, or a base64-encoded rule`)),
			mcp.WithNumber("pid",
				mcp.Required(),
				mcp.Description("Process ID to scan")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, ok := args["sid"].(string)
			if !ok {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			rule, ok := args["rule"].(string)
			if !ok {
				return tools.ErrorResult("rule parameter is required"), nil
			}

			pid, ok := args["pid"].(float64)
			if !ok {
				return tools.ErrorResult("pid parameter is required"), nil
			}

			// yara_scan takes the rule as a required positional, not a flag.
			resp, err := sendSensorCommandWithPositional(ctx, sid, "yara_scan", []string{rule}, map[string]interface{}{
				"pid": int(pid),
			})
			if err != nil {
				return tools.ErrorResultf("YARA scan failed: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterYARAScanFile registers the yara_scan_file tool
func RegisterYARAScanFile() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "yara_scan_file",
		Description: "Scan a specific file with YARA rules",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("yara_scan_file",
			mcp.WithDescription("Scan a specific file with YARA rules"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithString("rule",
				mcp.Required(),
				mcp.Description(`The rule to compile and run: a literal YARA rule, a LimaCharlie YARA resource reference like "lcr://service/yara/my-source", an "https://" URL, or a base64-encoded rule`)),
			mcp.WithString("file_path",
				mcp.Required(),
				mcp.Description("Path to file to scan")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, ok := args["sid"].(string)
			if !ok {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			rule, ok := args["rule"].(string)
			if !ok {
				return tools.ErrorResult("rule parameter is required"), nil
			}

			filePath, ok := args["file_path"].(string)
			if !ok {
				return tools.ErrorResult("file_path parameter is required"), nil
			}

			// yara_scan takes the rule as a required positional, not a flag.
			resp, err := sendSensorCommandWithPositional(ctx, sid, "yara_scan", []string{rule}, map[string]interface{}{
				"filePath": filePath,
			})
			if err != nil {
				return tools.ErrorResultf("YARA scan failed: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterYARAScanDirectory registers the yara_scan_directory tool
func RegisterYARAScanDirectory() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "yara_scan_directory",
		Description: "Scan a directory with YARA rules",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("yara_scan_directory",
			mcp.WithDescription("Scan a directory with YARA rules"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithString("rule",
				mcp.Required(),
				mcp.Description(`The rule to compile and run: a literal YARA rule, a LimaCharlie YARA resource reference like "lcr://service/yara/my-source", an "https://" URL, or a base64-encoded rule`)),
			mcp.WithString("directory",
				mcp.Required(),
				mcp.Description("Directory path to scan")),
			mcp.WithString("file_pattern",
				mcp.Description("File pattern to match (e.g., '*.exe')")),
			mcp.WithNumber("depth",
				mcp.Description("Maximum recursion depth (default: 5)")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, ok := args["sid"].(string)
			if !ok {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			rule, ok := args["rule"].(string)
			if !ok {
				return tools.ErrorResult("rule parameter is required"), nil
			}

			directory, ok := args["directory"].(string)
			if !ok {
				return tools.ErrorResult("directory parameter is required"), nil
			}

			params := map[string]interface{}{
				"root-dir": directory,
			}

			if pattern, ok := args["file_pattern"].(string); ok && pattern != "" {
				params["file-exp"] = pattern
			}

			if depth, ok := args["depth"].(float64); ok {
				params["depth"] = int(depth)
			} else {
				params["depth"] = 5
			}

			// yara_scan takes the rule as a required positional, not a flag.
			resp, err := sendSensorCommandWithPositional(ctx, sid, "yara_scan", []string{rule}, params)
			if err != nil {
				return tools.ErrorResultf("YARA scan failed: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterYARAScanMemory registers the yara_scan_memory tool
func RegisterYARAScanMemory() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "yara_scan_memory",
		Description: "Scan process memory with YARA rules using process expression",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("yara_scan_memory",
			mcp.WithDescription("Scan process memory with YARA rules using process expression"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithString("rule",
				mcp.Required(),
				mcp.Description(`The rule to compile and run: a literal YARA rule, a LimaCharlie YARA resource reference like "lcr://service/yara/my-source", an "https://" URL, or a base64-encoded rule`)),
			mcp.WithString("process_expression",
				mcp.Required(),
				mcp.Description("Process expression to match (e.g., 'name:chrome.exe')")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, ok := args["sid"].(string)
			if !ok {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			rule, ok := args["rule"].(string)
			if !ok {
				return tools.ErrorResult("rule parameter is required"), nil
			}

			processExpr, ok := args["process_expression"].(string)
			if !ok {
				return tools.ErrorResult("process_expression parameter is required"), nil
			}

			// yara_scan takes the rule as a required positional, not a flag.
			resp, err := sendSensorCommandWithPositional(ctx, sid, "yara_scan", []string{rule}, map[string]interface{}{
				"processExpr": processExpr,
			})
			if err != nil {
				return tools.ErrorResultf("YARA scan failed: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}
