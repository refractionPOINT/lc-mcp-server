package config

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	RegisterEnableSecret()
	RegisterDisableSecret()
}

// setSecretEnabled flips only the Enabled flag of a secret hive record while
// preserving its existing tags, comment and expiry. It reads the current
// metadata first so the Update does not clobber other usr_mtd fields.
func setSecretEnabled(ctx context.Context, secretName string, enabled bool) (*mcp.CallToolResult, error) {
	if secretName == "" {
		return tools.ErrorResult("secret_name parameter is required"), nil
	}

	org, err := getOrganization(ctx)
	if err != nil {
		return tools.ErrorResultf("failed to get organization: %v", err), nil
	}

	hive := lc.NewHiveClient(org)

	args := lc.HiveArgs{
		HiveName:     "secret",
		PartitionKey: org.GetOID(),
		Key:          secretName,
	}

	// Read current metadata so we don't clobber tags/comment/expiry.
	mtd, err := hive.GetMTD(args)
	if err != nil {
		return tools.ErrorResultf("failed to get secret '%s' metadata: %v", secretName, err), nil
	}

	args.Enabled = &enabled
	args.Tags = mtd.UsrMtd.Tags
	comment := mtd.UsrMtd.Comment
	args.Comment = &comment
	expiry := mtd.UsrMtd.Expiry
	args.Expiry = &expiry

	if _, err := hive.Update(args); err != nil {
		return tools.ErrorResultf("failed to update secret '%s': %v", secretName, err), nil
	}

	state := "disabled"
	if enabled {
		state = "enabled"
	}
	return tools.SuccessResult(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Successfully %s secret '%s'", state, secretName),
	}), nil
}

// RegisterEnableSecret registers the enable_secret tool
func RegisterEnableSecret() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "enable_secret",
		Description: "Enable a secret",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("enable_secret",
			mcp.WithDescription("Enable a secret"),
			mcp.WithString("secret_name",
				mcp.Required(),
				mcp.Description("Name of the secret to enable")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			secretName, _ := args["secret_name"].(string)
			return setSecretEnabled(ctx, secretName, true)
		},
	})
}

// RegisterDisableSecret registers the disable_secret tool
func RegisterDisableSecret() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "disable_secret",
		Description: "Disable a secret",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("disable_secret",
			mcp.WithDescription("Disable a secret"),
			mcp.WithString("secret_name",
				mcp.Required(),
				mcp.Description("Name of the secret to disable")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			secretName, _ := args["secret_name"].(string)
			return setSecretEnabled(ctx, secretName, false)
		},
	})
}
