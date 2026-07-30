package config

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register installation key management tools
	RegisterListInstallationKeys()
	RegisterCreateInstallationKey()
	RegisterDeleteInstallationKey()
}

// RegisterListInstallationKeys registers the list_installation_keys tool
func RegisterListInstallationKeys() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_installation_keys",
		Description: "List all installation keys in the organization",
		Profile:     "fleet_management",
		RequiresOID: true,
		Schema: mcp.NewTool("list_installation_keys",
			mcp.WithDescription("List all installation keys in the organization"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// List installation keys
			keys, err := org.InstallationKeys()
			if err != nil {
				return tools.ErrorResultf("failed to list installation keys: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"keys":  keys,
				"count": len(keys),
			}), nil
		},
	})
}

// RegisterCreateInstallationKey registers the create_installation_key tool
func RegisterCreateInstallationKey() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "create_installation_key",
		Description: "Create a new installation key for sensor deployment",
		Profile:     "fleet_management",
		RequiresOID: true,
		Schema: mcp.NewTool("create_installation_key",
			mcp.WithDescription("Create a new installation key for sensor deployment"),
			mcp.WithArray("tags",
				mcp.Required(),
				mcp.Description("Tags to automatically apply to sensors using this key")),
			mcp.WithString("description",
				mcp.Required(),
				mcp.Description("Description of the installation key")),
			mcp.WithNumber("quota",
				mcp.Description("Optional enrollment budget for this key: the total number of sensors that may enroll with it, counted down as they do. Must be a whole number; omit for no limit.")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			tagsRaw, ok := args["tags"].([]interface{})
			if !ok {
				return tools.ErrorResult("tags parameter is required and must be an array"), nil
			}

			// Convert to string slice
			tags := make([]string, 0, len(tagsRaw))
			for i, tag := range tagsRaw {
				tagStr, ok := tag.(string)
				if !ok {
					return tools.ErrorResultf("tags[%d] must be a string", i), nil
				}
				tags = append(tags, tagStr)
			}

			description, ok := args["description"].(string)
			if !ok || description == "" {
				return tools.ErrorResult("description parameter is required"), nil
			}

			var quota *int64
			if v, ok := args["quota"]; ok && v != nil {
				q, ok := v.(float64)
				if !ok {
					return tools.ErrorResult("quota parameter must be a number"), nil
				}
				if q < 0 {
					return tools.ErrorResult("quota parameter must not be negative"), nil
				}
				n := int64(q)
				if float64(n) != q {
					return tools.ErrorResult("quota parameter must be a whole number"), nil
				}
				quota = &n
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// The SDK's AddInstallationKey does not forward a quota even though
			// the API route accepts one, so go through the route directly.
			req := lc.Dict{
				"tags":               tags,
				"desc":               description,
				"use_public_root_ca": false,
			}
			if quota != nil {
				req["quota"] = *quota
			}

			resp := lc.Dict{}
			if err := org.GenericPOSTRequest(fmt.Sprintf("installationkeys/%s", org.GetOID()), req, &resp); err != nil {
				return tools.ErrorResultf("failed to create installation key: %v", err), nil
			}
			iid, _ := resp["iid"].(string)

			result := map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created installation key with IID: %s", iid),
				"iid":     iid,
			}
			if quota != nil {
				result["quota"] = *quota
			}
			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterDeleteInstallationKey registers the delete_installation_key tool
func RegisterDeleteInstallationKey() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_installation_key",
		Description: "Delete an installation key",
		Profile:     "fleet_management",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_installation_key",
			mcp.WithDescription("Delete an installation key"),
			mcp.WithString("iid",
				mcp.Required(),
				mcp.Description("Installation key ID to delete")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			iid, ok := args["iid"].(string)
			if !ok || iid == "" {
				return tools.ErrorResult("iid parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Delete installation key
			err = org.DelInstallationKey(iid)
			if err != nil {
				return tools.ErrorResultf("failed to delete installation key: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted installation key '%s'", iid),
			}), nil
		},
	})
}
