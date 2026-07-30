package cloudsec

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// registerResolve registers the sensor <-> cloud-asset resolution reads.
func registerResolve() {
	register(toolDef{
		name: "cloudsec_resolve_sensors",
		description: "Resolve LimaCharlie sensor ids to the cloud asset (urn, with posture flags) each one runs on — the runtime-to-posture direction of the fusion mapping. " +
			"Sensors with no known cloud asset come back in 'unresolved'. Any batch size works: the request is chunked automatically. " +
			"'resolver_ready' false means the resolver is not provisioned here, which is different from 'no asset matched'.",
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithArray("sid", mcp.WithStringItems(),
				mcp.Required(),
				mcp.Description("Sensor id(s) to resolve")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return resolveBulk(ctx, args, "resolve/sensors", "sid")
		},
	})

	register(toolDef{
		name: "cloudsec_resolve_assets",
		description: "Resolve cloud asset urns to the LimaCharlie sensor ids running on each — the posture-to-runtime direction of the fusion mapping. " +
			"Urns with no sensor come back in 'unresolved'. Any batch size works: the request is chunked automatically. " +
			"'resolver_ready' false means the resolver is not provisioned here, which is different from 'no sensor matched'.",
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithArray("urn", mcp.WithStringItems(),
				mcp.Required(),
				mcp.Description("Cloud asset urn(s) to resolve")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return resolveBulk(ctx, args, "resolve/assets", "urn")
		},
	})
}

// resolveBulk runs a bulk resolve as URL-safe chunks and merges the responses. The
// ids ride as repeated query params, so an unbounded batch would blow the ~8 KB
// load-balancer URL limit long before the gateway's own 500-per-request clamp.
func resolveBulk(ctx context.Context, args map[string]interface{}, suffix, key string) (*mcp.CallToolResult, error) {
	values, ok := argStrings(args, key)
	if !ok || len(values) == 0 {
		return tools.ErrorResultf("%s parameter is required and must be a non-empty array", key), nil
	}

	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return tools.ErrorResultf("failed to get organization: %v", err), nil
	}
	path := orgPath(org, suffix)

	merge := resolveMerge{}
	for _, chunk := range chunkStrings(values, resolveChunkSize) {
		resp := map[string]interface{}{}
		if err := org.GenericGETRequest(path, lc.Dict{key: chunk}, &resp); err != nil {
			return tools.ErrorResultf("cloudsec request to %s failed: %s", path, describeErr(err)), nil
		}
		merge.add(resp)
	}
	return tools.SuccessResult(merge.result()), nil
}

// chunkStrings splits values into runs of at most size elements. size <= 0 yields a
// single chunk.
func chunkStrings(values []string, size int) [][]string {
	if size <= 0 || len(values) <= size {
		return [][]string{values}
	}
	out := make([][]string, 0, (len(values)+size-1)/size)
	for i := 0; i < len(values); i += size {
		end := i + size
		if end > len(values) {
			end = len(values)
		}
		out = append(out, values[i:end])
	}
	return out
}

// resolveMerge accumulates the per-chunk resolve responses.
type resolveMerge struct {
	resolved   []interface{}
	unresolved []interface{}
	// ready holds the resolver_ready value of every chunk that reported one. It is
	// merged pessimistically (all-chunks-AND) and stays ABSENT when no chunk
	// reported it, rather than being invented as false: without that distinction a
	// caller cannot tell "nothing matched" from "the resolver is not running here".
	ready []bool
}

func (m *resolveMerge) add(resp map[string]interface{}) {
	if v, ok := resp["resolved"].([]interface{}); ok {
		m.resolved = append(m.resolved, v...)
	}
	if v, ok := resp["unresolved"].([]interface{}); ok {
		m.unresolved = append(m.unresolved, v...)
	}
	if v, present := resp["resolver_ready"]; present {
		m.ready = append(m.ready, truthy(v))
	}
}

func (m *resolveMerge) result() map[string]interface{} {
	resolved := m.resolved
	if resolved == nil {
		resolved = []interface{}{}
	}
	unresolved := m.unresolved
	if unresolved == nil {
		unresolved = []interface{}{}
	}
	out := map[string]interface{}{
		"resolved":   resolved,
		"unresolved": unresolved,
	}
	if len(m.ready) > 0 {
		all := true
		for _, r := range m.ready {
			if !r {
				all = false
				break
			}
		}
		out["resolver_ready"] = all
	}
	return out
}

// truthy reads a resolver_ready value the way python's bool() does, so a backend
// that answers with a number or a non-empty string is not read as ready=false.
func truthy(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case nil:
		return false
	case float64:
		return t != 0
	case int:
		return t != 0
	case string:
		return t != ""
	}
	return true
}
