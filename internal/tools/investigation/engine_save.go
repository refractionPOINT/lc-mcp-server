package investigation

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/refractionpoint/lc-mcp-go/internal/tools/hive"
	"gopkg.in/yaml.v3"
)

const (
	planHive            = "investigation_plan"
	statusDraft         = "draft"
	statusActive        = "active"
	maxTestSummaryRunes = 2000
	// aiDraftTag marks a record this tool wrote, so a reviewer can find the drafts an agent made.
	aiDraftTag = "ai-draft"
	// createOnlyETag is sent with the write of a record that did not exist: it matches no stored etag, so the
	// hive refuses the write if the record exists by then.
	createOnlyETag = "create-only: the record must not exist"
)

// planNameRe is the shape of a template name this tool will create: the record key of the hive and the name
// a run, a policy and a case refer to.
var planNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// refusal is a save this tool will not make; its message tells the author what to do instead.
type refusal string

func (r refusal) Error() string { return string(r) }

func handleSavePlan(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	name, err := optString(args, "name")
	if err != nil {
		return fail(err)
	}
	src, err := optString(args, "yaml")
	if err != nil {
		return fail(err)
	}
	summary, err := optString(args, "test_summary")
	if err != nil {
		return fail(err)
	}
	overwrite, err := optBool(args, "overwrite")
	if err != nil {
		return fail(err)
	}
	if !planNameRe.MatchString(name) {
		return tools.ErrorResult("name must be lowercase letters, digits, - and _, start with a letter or digit and be at most 64 characters"), nil
	}
	if utf8.RuneCountInString(summary) > maxTestSummaryRunes {
		return tools.ErrorResultf("test_summary is over %d characters", maxTestSummaryRunes), nil
	}

	data, normalized, err := draftRecord(src)
	if err != nil {
		return fail(err)
	}

	// The engine must accept exactly what is stored: validate the normalized source, not the original.
	report, err := call(ctx, engineCall{method: http.MethodPost, suffix: "plans/validate", body: map[string]interface{}{"yaml": normalized}})
	if err != nil {
		return fail(err)
	}
	if report["valid"] != true || hasItems(report["errors"]) {
		return notSaved(map[string]interface{}{
			"saved":      false,
			"reason":     "the template does not validate; fix every error and call again",
			"validation": report,
		}), nil
	}

	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return tools.ErrorResultf("failed to get organization: %v", err), nil
	}
	oid := org.GetOID()

	// Fail closed on every check: when the engine or the hive cannot say what exists under this name, nothing
	// is written.
	if err := refuseIfLoaded(ctx, name); err != nil {
		return refuseOrFail(err)
	}
	client := hive.NewClient(org)
	existing, err := client.Get(lc.HiveArgs{HiveName: planHive, PartitionKey: oid, Key: name})
	var etag string
	tags := []string{aiDraftTag}
	switch {
	case err == nil:
		// Only a record that says it is a draft, or says nothing (a draft by the engine's default), is replaced:
		// "active" and any value this tool does not know are left alone.
		switch status := str(existing.Data["status"]); status {
		case statusDraft, "":
		case statusActive:
			return refuseOrFail(refusal(fmt.Sprintf("template %q is active: this tool never overwrites an active template. Save your version under a new name; a person decides in the console whether it replaces the active one.", name)))
		default:
			return refuseOrFail(refusal(fmt.Sprintf("the record %q has status %q, which is not draft: this tool only replaces drafts. Save under another name.", name, status)))
		}
		if !overwrite {
			return refuseOrFail(refusal(fmt.Sprintf("a draft named %q already exists: pass overwrite=true to replace it, or save under another name", name)))
		}
		etag = existing.SysMtd.Etag
		// A person's tags on the draft stay.
		tags = mergeTags(existing.UsrMtd.Tags, aiDraftTag)
	case hive.IsRecordNotFound(err):
		// No record yet: the write must create it. The hive refuses a conditional write whose etag differs
		// from the stored one, and no stored etag equals this one, so a record created (or promoted)
		// between the check above and the write is not overwritten.
		etag = createOnlyETag
	default:
		return tools.ErrorResultf("could not check whether %q exists: %v", name, err), nil
	}

	overrides := hive.MetadataOverrides{Tags: tags}
	if summary != "" {
		overrides.Comment = &summary
	}
	warning, err := hive.SetRecord(org, hive.RecordWrite{HiveName: planHive, Key: name, Data: lc.Dict(data), Overrides: overrides, ETag: etag})
	if err != nil {
		return tools.ErrorResultf("failed to save the draft %q: %v", name, err), nil
	}

	// Read it back: say what is stored, not what was sent.
	stored, err := client.Get(lc.HiveArgs{HiveName: planHive, PartitionKey: oid, Key: name})
	if err != nil {
		return tools.ErrorResultf("the draft %q was written but could not be read back: %v", name, err), nil
	}
	if str(stored.Data["status"]) != statusDraft {
		return tools.ErrorResultf("the record %q was written but its status reads %q, not draft: have a person check it in the console", name, str(stored.Data["status"])), nil
	}
	warnings := report["warnings"]
	if warnings == nil {
		warnings = []interface{}{}
	}
	out := map[string]interface{}{
		"saved":       true,
		"name":        name,
		"status":      statusDraft,
		"last_author": stored.SysMtd.LastAuthor,
		"etag":        stored.SysMtd.Etag,
		"warnings":    warnings,
		"next_step":   "The draft cannot run on its own. A person reviews it in the console (Investigations, Templates) and promotes it to active. Until then it runs only through investigate_test_plan or a run a person starts, with autonomy capped at suggest.",
	}
	if warning != "" {
		out["hive_warning"] = warning
	}
	return tools.SuccessResult(out), nil
}

// draftRecord parses the template source and returns the hive record data with status forced to draft, and the
// YAML of exactly that data. A template that says it is active is refused: the status is not the author's to
// set.
func draftRecord(src string) (map[string]interface{}, string, error) {
	if strings.TrimSpace(src) == "" {
		return nil, "", fmt.Errorf("yaml is required")
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		return nil, "", fmt.Errorf("the template is not valid YAML: %v", err)
	}
	if len(doc.Content) == 0 {
		return nil, "", fmt.Errorf("the template is empty")
	}
	if doc.Content[0].Kind != yaml.MappingNode {
		return nil, "", fmt.Errorf("the template must be a YAML mapping (description, applies_to, facts, ...)")
	}
	value, err := nodeValue(doc.Content[0])
	if err != nil {
		return nil, "", fmt.Errorf("the template is not valid YAML: %v", err)
	}
	data := value.(map[string]interface{})
	if v, ok := data["status"]; ok {
		s, isString := v.(string)
		switch {
		case isString && strings.EqualFold(strings.TrimSpace(s), statusActive):
			return nil, "", refusal("the template sets status: active. This tool only saves drafts; leave status out. A person promotes a draft in the console.")
		case isString && s == statusDraft:
		default:
			return nil, "", refusal(fmt.Sprintf("the template sets status to %v; leave status out, this tool saves drafts only", v))
		}
	}
	if _, ok := data["name"]; ok {
		return nil, "", refusal("the template has a `name:` key; the name is the save's `name` argument and is not part of the YAML")
	}
	data["status"] = statusDraft
	out, err := yaml.Marshal(data)
	if err != nil {
		return nil, "", fmt.Errorf("cannot encode the template: %v", err)
	}
	return data, string(out), nil
}

// nodeValue converts a YAML node to plain JSON-compatible values. Unlike yaml.Unmarshal into an interface{}, it
// keeps an unquoted date or timestamp as the text the author wrote: the engine reads it as that text, and a
// time.Time would be stored as a different string.
func nodeValue(n *yaml.Node) (interface{}, error) {
	switch n.Kind {
	case yaml.AliasNode:
		return nodeValue(n.Alias)
	case yaml.MappingNode:
		m := make(map[string]interface{}, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("line %d: a mapping key must be a plain value", k.Line)
			}
			v, err := nodeValue(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			m[k.Value] = v
		}
		return m, nil
	case yaml.SequenceNode:
		l := make([]interface{}, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := nodeValue(c)
			if err != nil {
				return nil, err
			}
			l = append(l, v)
		}
		return l, nil
	default:
		if n.Tag == "!!timestamp" {
			return n.Value, nil
		}
		var v interface{}
		if err := n.Decode(&v); err != nil {
			return nil, err
		}
		return v, nil
	}
}

// refuseIfLoaded refuses a name that the engine already serves as a managed template or as an active one.
func refuseIfLoaded(ctx context.Context, name string) error {
	out, err := call(ctx, engineCall{method: http.MethodGet, suffix: "templates"})
	if err != nil {
		return fmt.Errorf("could not list the org's templates to check the name: %w", err)
	}
	rows, _ := out["templates"].([]interface{})
	for _, r := range rows {
		row, ok := r.(map[string]interface{})
		if !ok || str(row["name"]) != name {
			continue
		}
		if row["managed"] == true {
			return refusal(fmt.Sprintf("%q is a platform-managed template: this tool never touches one. Save your version under a new name.", name))
		}
		if templateStatus(row) == statusActive {
			return refusal(fmt.Sprintf("template %q is active: this tool never overwrites an active template. Save your version under a new name.", name))
		}
	}
	return nil
}

// notSaved is the tool error for a save that did not happen. The body is JSON, so an agent reads `saved: false`
// and the reason the same way it reads a success.
func notSaved(body map[string]interface{}) *mcp.CallToolResult {
	return mcp.NewToolResultError(tools.ToJSON(body))
}

// refuseOrFail turns a refusal into the tool's structured "not saved" answer and anything else into a tool error.
func refuseOrFail(err error) (*mcp.CallToolResult, error) {
	if r, ok := err.(refusal); ok {
		return notSaved(map[string]interface{}{"saved": false, "reason": string(r)}), nil
	}
	return tools.ErrorResult(err.Error()), nil
}

// mergeTags is the existing tags plus add, in order, without duplicates.
func mergeTags(existing []string, add string) []string {
	out := make([]string, 0, len(existing)+1)
	seen := false
	for _, t := range existing {
		if t == add {
			if seen {
				continue
			}
			seen = true
		}
		out = append(out, t)
	}
	if !seen {
		out = append(out, add)
	}
	return out
}

func hasItems(v interface{}) bool {
	l, ok := v.([]interface{})
	return ok && len(l) > 0
}
