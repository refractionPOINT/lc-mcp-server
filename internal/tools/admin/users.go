package admin

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register all user management tools
	RegisterListOrgUsers()
	RegisterAddOrgUser()
	RegisterRemoveOrgUser()
	RegisterGetUsersPermissions()
	RegisterAddUserPermission()
	RegisterRemoveUserPermission()
	RegisterSetUserRole()
}

// Valid user roles in LimaCharlie (imported from SDK)
var validUserRoles = map[string]bool{
	lc.UserRoleOwner:         true,
	lc.UserRoleAdministrator: true,
	lc.UserRoleOperator:      true,
	lc.UserRoleViewer:        true,
	lc.UserRoleBasic:         true,
}

// validateUserRole checks if a role is valid
func validateUserRole(role string) error {
	if !validUserRoles[role] {
		validRoles := []string{
			lc.UserRoleOwner,
			lc.UserRoleAdministrator,
			lc.UserRoleOperator,
			lc.UserRoleViewer,
			lc.UserRoleBasic,
		}
		return fmt.Errorf("invalid role '%s', must be one of: %s", role, strings.Join(validRoles, ", "))
	}
	return nil
}

// RegisterListOrgUsers registers the list_org_users tool
func RegisterListOrgUsers() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_org_users",
		Description: "List user emails in organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_org_users",
			mcp.WithDescription("List all user emails with access to the organization"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			users, err := org.GetUsers()
			if err != nil {
				return tools.ErrorResultf("failed to get users: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"users": users,
				"count": len(users),
			}), nil
		},
	})
}

// RegisterAddOrgUser registers the add_org_user tool
func RegisterAddOrgUser() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "add_org_user",
		Description: "Add user with role and optional invite",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("add_org_user",
			mcp.WithDescription("Add a user to the organization with a specified role. Valid roles: Owner, Administrator, Operator, Viewer, Basic"),
			mcp.WithString("email",
				mcp.Required(),
				mcp.Description("Email address of the user to add")),
			mcp.WithString("role",
				mcp.Required(),
				mcp.Description("Role to assign: Owner, Administrator, Operator, Viewer, or Basic")),
			mcp.WithBoolean("invite_missing",
				mcp.Description("If true, send an invite to users who don't have a LimaCharlie account (default: false)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			email, ok := args["email"].(string)
			if !ok || email == "" {
				return tools.ErrorResult("email parameter is required"), nil
			}

			role, ok := args["role"].(string)
			if !ok || role == "" {
				return tools.ErrorResult("role parameter is required"), nil
			}

			if err := validateUserRole(role); err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			inviteMissing := false
			if im, ok := args["invite_missing"].(bool); ok {
				inviteMissing = im
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			response, err := org.AddUser(email, inviteMissing, role)
			if err != nil {
				return tools.ErrorResultf("failed to add user: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":     response.Success,
				"email":       email,
				"role":        response.Role,
				"invite_sent": response.InviteSent,
			}), nil
		},
	})
}

// RegisterRemoveOrgUser registers the remove_org_user tool
func RegisterRemoveOrgUser() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "remove_org_user",
		Description: "Remove user from organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("remove_org_user",
			mcp.WithDescription("Remove a user from the organization"),
			mcp.WithString("email",
				mcp.Required(),
				mcp.Description("Email address of the user to remove")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			email, ok := args["email"].(string)
			if !ok || email == "" {
				return tools.ErrorResult("email parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			if err := org.RemoveUser(email); err != nil {
				return tools.ErrorResultf("failed to remove user: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully removed user: %s", email),
			}), nil
		},
	})
}

// RegisterGetUsersPermissions registers the get_users_permissions tool
func RegisterGetUsersPermissions() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_users_permissions",
		Description: "Get detailed permissions for all users",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_users_permissions",
			mcp.WithDescription("Get detailed permission information for all users in the organization, including direct users, users from groups, and group info"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			permissions, err := org.GetUsersPermissions()
			if err != nil {
				return tools.ErrorResultf("failed to get users permissions: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"user_permissions": permissions.UserPermissions,
				"direct_users":     permissions.DirectUsers,
				"from_groups":      permissions.FromGroups,
				"group_info":       permissions.GroupInfo,
			}), nil
		},
	})
}

// RegisterAddUserPermission registers the add_user_permission tool
func RegisterAddUserPermission() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "add_user_permission",
		Description: "Add permission to user",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("add_user_permission",
			mcp.WithDescription("Add a specific permission to a user in the organization"),
			mcp.WithString("email",
				mcp.Required(),
				mcp.Description("Email address of the user")),
			mcp.WithString("permission",
				mcp.Required(),
				mcp.Description("Permission to add")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			email, ok := args["email"].(string)
			if !ok || email == "" {
				return tools.ErrorResult("email parameter is required"), nil
			}

			permission, ok := args["permission"].(string)
			if !ok || permission == "" {
				return tools.ErrorResult("permission parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			if err := org.AddUserPermission(email, permission); err != nil {
				return tools.ErrorResultf("failed to add permission: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":    true,
				"message":    fmt.Sprintf("Successfully added permission '%s' to user %s", permission, email),
				"email":      email,
				"permission": permission,
			}), nil
		},
	})
}

// RegisterRemoveUserPermission registers the remove_user_permission tool
func RegisterRemoveUserPermission() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "remove_user_permission",
		Description: "Remove permission from user",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("remove_user_permission",
			mcp.WithDescription("Remove a specific permission from a user in the organization"),
			mcp.WithString("email",
				mcp.Required(),
				mcp.Description("Email address of the user")),
			mcp.WithString("permission",
				mcp.Required(),
				mcp.Description("Permission to remove")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			email, ok := args["email"].(string)
			if !ok || email == "" {
				return tools.ErrorResult("email parameter is required"), nil
			}

			permission, ok := args["permission"].(string)
			if !ok || permission == "" {
				return tools.ErrorResult("permission parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			if err := org.RemoveUserPermission(email, permission); err != nil {
				return tools.ErrorResultf("failed to remove permission: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":    true,
				"message":    fmt.Sprintf("Successfully removed permission '%s' from user %s", permission, email),
				"email":      email,
				"permission": permission,
			}), nil
		},
	})
}

// RegisterSetUserRole registers the set_user_role tool
func RegisterSetUserRole() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_user_role",
		Description: "Set user role (Owner, Administrator, Operator, Viewer, Basic)",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_user_role",
			mcp.WithDescription("Set the role for a user in the organization. Valid roles: Owner, Administrator, Operator, Viewer, Basic"),
			mcp.WithString("email",
				mcp.Required(),
				mcp.Description("Email address of the user")),
			mcp.WithString("role",
				mcp.Required(),
				mcp.Description("Role to set: Owner, Administrator, Operator, Viewer, or Basic")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			email, ok := args["email"].(string)
			if !ok || email == "" {
				return tools.ErrorResult("email parameter is required"), nil
			}

			role, ok := args["role"].(string)
			if !ok || role == "" {
				return tools.ErrorResult("role parameter is required"), nil
			}

			if err := validateUserRole(role); err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			response, err := org.SetUserRole(email, role)
			if err != nil {
				return tools.ErrorResultf("failed to set user role: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":     response.Success,
				"email":       email,
				"role":        response.Role,
				"permissions": response.Permissions,
			}), nil
		},
	})
}
