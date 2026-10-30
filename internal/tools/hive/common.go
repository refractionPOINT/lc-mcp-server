package hive

import (
	"context"
	"fmt"
	"regexp"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// getOrganization retrieves the organization from the context
func getOrganization(ctx context.Context) (*lc.Organization, error) {
	return tools.GetOrganization(ctx)
}

// hiveNameRe is the shape of every hive name (dr-general, external_adapter, ai_agent...).
// The name is interpolated into the request path, so anything else - a '/', '..', a
// query string - could re-route the call to a different path, and with it a different
// partition, than the one this server authorized.
var hiveNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// hiveNameArg reads and validates the hive_name argument.
func hiveNameArg(args map[string]interface{}) (string, *mcp.CallToolResult) {
	name, ok := args["hive_name"].(string)
	if !ok || name == "" {
		return "", tools.ErrorResult("hive_name parameter is required")
	}
	if !hiveNameRe.MatchString(name) {
		return "", tools.ErrorResult("hive_name may only contain letters, digits, '_' and '-' (at most 64 characters)")
	}
	return name, nil
}

// effectiveOID is the organization this call executes against: the OID on the request's
// auth context, which is what the transport's per-organization checks (org pinning and
// the ai_agent.operate permission) were made against.
func effectiveOID(ctx context.Context, org *lc.Organization) (string, error) {
	oid := org.GetOID()
	if authCtx, err := auth.FromContext(ctx); err == nil && authCtx.OID != "" {
		if oid != "" && oid != authCtx.OID {
			// Cannot happen with the SDK cache, which builds the organization from the
			// auth context. Refusing is the safe answer if it ever does.
			return "", fmt.Errorf("organization client (%s) does not match the request's organization (%s)", oid, authCtx.OID)
		}
		oid = authCtx.OID
	}
	if oid == "" {
		return "", fmt.Errorf("no organization is selected for this request")
	}
	return oid, nil
}

// resolvePartition returns the hive partition a call must use.
//
// Every hive that tenants can reach is partitioned by organization: the partition key IS
// the organization's OID (legion_config_hive hivedef: each non-root hive declares
// HivePartitionTypes.OID, the one other hive is root-only; the API gateway routes a hive
// request to the datacenter of the org named by the partition). So the partition is not
// a free parameter. It is always the effective OID, and an explicit partition_key is
// accepted only when it repeats that OID.
//
// This matters because the server authorizes a call against the effective OID only
// (org pinning, ai_agent.operate). A partition_key naming another organization would
// otherwise send the operation there after the check had passed for a different one.
// There is no legitimate non-organization partition to carve an exception for, so a
// differing value is refused rather than allowed for reads.
func resolvePartition(ctx context.Context, org *lc.Organization, args map[string]interface{}) (string, *mcp.CallToolResult) {
	oid, err := effectiveOID(ctx, org)
	if err != nil {
		return "", tools.ErrorResultf("%v", err)
	}
	raw, present := args["partition_key"]
	if !present || raw == nil {
		return oid, nil
	}
	pk, ok := raw.(string)
	if !ok {
		return "", tools.ErrorResult("partition_key must be a string")
	}
	if pk == "" || pk == oid {
		return oid, nil
	}
	return "", tools.ErrorResultf(
		"partition_key must be this organization's own OID (%s): hive records are partitioned by organization, so records of another partition cannot be reached from this call. "+
			"Omit partition_key, or use the 'oid' argument to operate on another organization you have access to",
		oid)
}

// requireOwnPartition is the lowest-layer form of the same rule for callers that build a
// partition themselves: an empty key means the organization's own, anything else must be
// that OID.
func requireOwnPartition(org *lc.Organization, partitionKey string) (string, error) {
	oid := org.GetOID()
	if oid == "" {
		return "", fmt.Errorf("no organization is selected for this request")
	}
	if partitionKey != "" && partitionKey != oid {
		return "", fmt.Errorf("partition key must be the organization's own OID: hive records are partitioned by organization")
	}
	return oid, nil
}
