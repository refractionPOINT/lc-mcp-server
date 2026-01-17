package admin

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register all group management tools
	RegisterListGroups()
	RegisterListGroupsDetailed()
	RegisterCreateGroup()
	RegisterGetGroupInfo()
	RegisterDeleteGroup()
	RegisterAddGroupMember()
	RegisterRemoveGroupMember()
	RegisterAddGroupOwner()
	RegisterRemoveGroupOwner()
	RegisterSetGroupPermissions()
	RegisterAddOrgToGroup()
	RegisterRemoveOrgFromGroup()
}

// RegisterListGroups registers the list_groups tool
func RegisterListGroups() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_groups",
		Description: "List groups accessible to user",
		Profile:     "platform_admin",
		RequiresOID: false, // User-level operation
		Schema: mcp.NewTool("list_groups",
			mcp.WithDescription("List all groups accessible to the current user. Returns group IDs and names."),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			client, err := tools.GetClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get client: %v", err), nil
			}

			groups, err := client.GetGroups()
			if err != nil {
				return tools.ErrorResultf("failed to list groups: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"groups": groups,
				"count":  len(groups),
			}), nil
		},
	})
}

// RegisterListGroupsDetailed registers the list_groups_detailed tool
func RegisterListGroupsDetailed() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_groups_detailed",
		Description: "List groups with full info",
		Profile:     "platform_admin",
		RequiresOID: false, // User-level operation
		Schema: mcp.NewTool("list_groups_detailed",
			mcp.WithDescription("List all groups with detailed information including members, owners, orgs, and permissions."),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			client, err := tools.GetClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get client: %v", err), nil
			}

			groups, err := client.GetGroupsConcurrent()
			if err != nil {
				return tools.ErrorResultf("failed to list groups: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"groups": groups,
				"count":  len(groups),
			}), nil
		},
	})
}

// RegisterCreateGroup registers the create_group tool
func RegisterCreateGroup() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "create_group",
		Description: "Create a new group",
		Profile:     "platform_admin",
		RequiresOID: false, // User-level operation
		Schema: mcp.NewTool("create_group",
			mcp.WithDescription("Create a new group. The current user becomes the group owner."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name for the new group")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			name, ok := args["name"].(string)
			if !ok || name == "" {
				return tools.ErrorResult("name parameter is required"), nil
			}

			client, err := tools.GetClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get client: %v", err), nil
			}

			response, err := client.CreateGroup(name)
			if err != nil {
				return tools.ErrorResultf("failed to create group: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": response.Success,
				"gid":     response.Data.GID,
				"name":    name,
			}), nil
		},
	})
}

// RegisterGetGroupInfo registers the get_group_info tool
func RegisterGetGroupInfo() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_group_info",
		Description: "Get detailed group info (requires gid)",
		Profile:     "platform_admin",
		RequiresOID: false, // User-level operation
		Schema: mcp.NewTool("get_group_info",
			mcp.WithDescription("Get detailed information about a specific group. User must be a group owner."),
			mcp.WithString("gid",
				mcp.Required(),
				mcp.Description("Group ID")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			gid, ok := args["gid"].(string)
			if !ok || gid == "" {
				return tools.ErrorResult("gid parameter is required"), nil
			}

			client, err := tools.GetClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get client: %v", err), nil
			}

			group := client.GetGroup(gid)
			info, err := group.GetInfo()
			if err != nil {
				return tools.ErrorResultf("failed to get group info: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"group_id":    info.GroupID,
				"name":        info.Name,
				"owners":      info.Owners,
				"members":     info.Members,
				"orgs":        info.Orgs,
				"permissions": info.Permissions,
			}), nil
		},
	})
}

// RegisterDeleteGroup registers the delete_group tool
func RegisterDeleteGroup() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_group",
		Description: "Delete a group (requires gid)",
		Profile:     "platform_admin",
		RequiresOID: false, // User-level operation
		Schema: mcp.NewTool("delete_group",
			mcp.WithDescription("Delete a group. User must be a group owner."),
			mcp.WithString("gid",
				mcp.Required(),
				mcp.Description("Group ID to delete")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			gid, ok := args["gid"].(string)
			if !ok || gid == "" {
				return tools.ErrorResult("gid parameter is required"), nil
			}

			client, err := tools.GetClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get client: %v", err), nil
			}

			group := client.GetGroup(gid)
			if err := group.Delete(); err != nil {
				return tools.ErrorResultf("failed to delete group: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted group: %s", gid),
			}), nil
		},
	})
}

// RegisterAddGroupMember registers the add_group_member tool
func RegisterAddGroupMember() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "add_group_member",
		Description: "Add member to group",
		Profile:     "platform_admin",
		RequiresOID: false, // User-level operation
		Schema: mcp.NewTool("add_group_member",
			mcp.WithDescription("Add a user as a member of the group. User must be a group owner."),
			mcp.WithString("gid",
				mcp.Required(),
				mcp.Description("Group ID")),
			mcp.WithString("email",
				mcp.Required(),
				mcp.Description("Email address of the user to add as member")),
			mcp.WithBoolean("invite_missing",
				mcp.Description("If true, send an invite to users who don't have a LimaCharlie account (default: false)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			gid, ok := args["gid"].(string)
			if !ok || gid == "" {
				return tools.ErrorResult("gid parameter is required"), nil
			}

			email, ok := args["email"].(string)
			if !ok || email == "" {
				return tools.ErrorResult("email parameter is required"), nil
			}

			inviteMissing := false
			if im, ok := args["invite_missing"].(bool); ok {
				inviteMissing = im
			}

			client, err := tools.GetClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get client: %v", err), nil
			}

			group := client.GetGroup(gid)
			if err := group.AddMember(email, inviteMissing); err != nil {
				return tools.ErrorResultf("failed to add group member: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully added member %s to group %s", email, gid),
				"gid":     gid,
				"email":   email,
			}), nil
		},
	})
}

// RegisterRemoveGroupMember registers the remove_group_member tool
func RegisterRemoveGroupMember() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "remove_group_member",
		Description: "Remove member from group",
		Profile:     "platform_admin",
		RequiresOID: false, // User-level operation
		Schema: mcp.NewTool("remove_group_member",
			mcp.WithDescription("Remove a user from the group's members. User must be a group owner."),
			mcp.WithString("gid",
				mcp.Required(),
				mcp.Description("Group ID")),
			mcp.WithString("email",
				mcp.Required(),
				mcp.Description("Email address of the member to remove")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			gid, ok := args["gid"].(string)
			if !ok || gid == "" {
				return tools.ErrorResult("gid parameter is required"), nil
			}

			email, ok := args["email"].(string)
			if !ok || email == "" {
				return tools.ErrorResult("email parameter is required"), nil
			}

			client, err := tools.GetClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get client: %v", err), nil
			}

			group := client.GetGroup(gid)
			if err := group.RemoveMember(email); err != nil {
				return tools.ErrorResultf("failed to remove group member: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully removed member %s from group %s", email, gid),
				"gid":     gid,
				"email":   email,
			}), nil
		},
	})
}

// RegisterAddGroupOwner registers the add_group_owner tool
func RegisterAddGroupOwner() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "add_group_owner",
		Description: "Add owner to group",
		Profile:     "platform_admin",
		RequiresOID: false, // User-level operation
		Schema: mcp.NewTool("add_group_owner",
			mcp.WithDescription("Add a user as an owner of the group. User must be a group owner."),
			mcp.WithString("gid",
				mcp.Required(),
				mcp.Description("Group ID")),
			mcp.WithString("email",
				mcp.Required(),
				mcp.Description("Email address of the user to add as owner")),
			mcp.WithBoolean("invite_missing",
				mcp.Description("If true, send an invite to users who don't have a LimaCharlie account (default: false)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			gid, ok := args["gid"].(string)
			if !ok || gid == "" {
				return tools.ErrorResult("gid parameter is required"), nil
			}

			email, ok := args["email"].(string)
			if !ok || email == "" {
				return tools.ErrorResult("email parameter is required"), nil
			}

			inviteMissing := false
			if im, ok := args["invite_missing"].(bool); ok {
				inviteMissing = im
			}

			client, err := tools.GetClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get client: %v", err), nil
			}

			group := client.GetGroup(gid)
			if err := group.AddOwner(email, inviteMissing); err != nil {
				return tools.ErrorResultf("failed to add group owner: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully added owner %s to group %s", email, gid),
				"gid":     gid,
				"email":   email,
			}), nil
		},
	})
}

// RegisterRemoveGroupOwner registers the remove_group_owner tool
func RegisterRemoveGroupOwner() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "remove_group_owner",
		Description: "Remove owner from group",
		Profile:     "platform_admin",
		RequiresOID: false, // User-level operation
		Schema: mcp.NewTool("remove_group_owner",
			mcp.WithDescription("Remove a user from the group's owners. User must be a group owner."),
			mcp.WithString("gid",
				mcp.Required(),
				mcp.Description("Group ID")),
			mcp.WithString("email",
				mcp.Required(),
				mcp.Description("Email address of the owner to remove")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			gid, ok := args["gid"].(string)
			if !ok || gid == "" {
				return tools.ErrorResult("gid parameter is required"), nil
			}

			email, ok := args["email"].(string)
			if !ok || email == "" {
				return tools.ErrorResult("email parameter is required"), nil
			}

			client, err := tools.GetClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get client: %v", err), nil
			}

			group := client.GetGroup(gid)
			if err := group.RemoveOwner(email); err != nil {
				return tools.ErrorResultf("failed to remove group owner: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully removed owner %s from group %s", email, gid),
				"gid":     gid,
				"email":   email,
			}), nil
		},
	})
}

// RegisterSetGroupPermissions registers the set_group_permissions tool
func RegisterSetGroupPermissions() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_group_permissions",
		Description: "Set group permissions",
		Profile:     "platform_admin",
		RequiresOID: false, // User-level operation
		Schema: mcp.NewTool("set_group_permissions",
			mcp.WithDescription("Set the permissions for a group. Replaces all existing permissions. User must be a group owner."),
			mcp.WithString("gid",
				mcp.Required(),
				mcp.Description("Group ID")),
			mcp.WithArray("permissions",
				mcp.Required(),
				mcp.Description("List of permissions to set for the group")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			gid, ok := args["gid"].(string)
			if !ok || gid == "" {
				return tools.ErrorResult("gid parameter is required"), nil
			}

			var permissions []string
			if perms, ok := args["permissions"].([]interface{}); ok {
				for _, p := range perms {
					if perm, ok := p.(string); ok {
						permissions = append(permissions, perm)
					}
				}
			}

			if len(permissions) == 0 {
				return tools.ErrorResult("permissions parameter is required and must not be empty"), nil
			}

			client, err := tools.GetClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get client: %v", err), nil
			}

			group := client.GetGroup(gid)
			if err := group.SetPermissions(permissions); err != nil {
				return tools.ErrorResultf("failed to set group permissions: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":     true,
				"message":     fmt.Sprintf("Successfully set permissions for group %s", gid),
				"gid":         gid,
				"permissions": permissions,
			}), nil
		},
	})
}

// RegisterAddOrgToGroup registers the add_org_to_group tool
func RegisterAddOrgToGroup() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "add_org_to_group",
		Description: "Add organization to group",
		Profile:     "platform_admin",
		RequiresOID: false, // User-level operation, OID is provided as parameter
		Schema: mcp.NewTool("add_org_to_group",
			mcp.WithDescription("Add an organization to a group. User must be a group owner."),
			mcp.WithString("gid",
				mcp.Required(),
				mcp.Description("Group ID")),
			mcp.WithString("oid",
				mcp.Required(),
				mcp.Description("Organization ID to add to the group")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			gid, ok := args["gid"].(string)
			if !ok || gid == "" {
				return tools.ErrorResult("gid parameter is required"), nil
			}

			oid, ok := args["oid"].(string)
			if !ok || oid == "" {
				return tools.ErrorResult("oid parameter is required"), nil
			}

			client, err := tools.GetClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get client: %v", err), nil
			}

			group := client.GetGroup(gid)
			if err := group.AddOrg(oid); err != nil {
				return tools.ErrorResultf("failed to add organization to group: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully added organization %s to group %s", oid, gid),
				"gid":     gid,
				"oid":     oid,
			}), nil
		},
	})
}

// RegisterRemoveOrgFromGroup registers the remove_org_from_group tool
func RegisterRemoveOrgFromGroup() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "remove_org_from_group",
		Description: "Remove organization from group",
		Profile:     "platform_admin",
		RequiresOID: false, // User-level operation, OID is provided as parameter
		Schema: mcp.NewTool("remove_org_from_group",
			mcp.WithDescription("Remove an organization from a group. User must be a group owner."),
			mcp.WithString("gid",
				mcp.Required(),
				mcp.Description("Group ID")),
			mcp.WithString("oid",
				mcp.Required(),
				mcp.Description("Organization ID to remove from the group")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			gid, ok := args["gid"].(string)
			if !ok || gid == "" {
				return tools.ErrorResult("gid parameter is required"), nil
			}

			oid, ok := args["oid"].(string)
			if !ok || oid == "" {
				return tools.ErrorResult("oid parameter is required"), nil
			}

			client, err := tools.GetClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get client: %v", err), nil
			}

			group := client.GetGroup(gid)
			if err := group.RemoveOrg(oid); err != nil {
				return tools.ErrorResultf("failed to remove organization from group: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully removed organization %s from group %s", oid, gid),
				"gid":     gid,
				"oid":     oid,
			}), nil
		},
	})
}
