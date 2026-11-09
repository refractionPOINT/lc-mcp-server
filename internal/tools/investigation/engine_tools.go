package investigation

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// Profile is the MCP profile that carries the Investigation Engine tools.
const Profile = "investigation_engine"

// authoringLoop is the loop every authoring tool teaches, so an agent that has read any one of their
// descriptions knows where it is.
const authoringLoop = "Plan authoring loop: (1) investigate_authoring_kit once; (2) look at the org's real data " +
	"(get_detection / run_lcql_query for which fields exist, investigate_wave to try an operator on a real value); " +
	"(3) draft the YAML; (4) investigate_validate_plan until it reports no errors; (5) investigate_test_plan on real " +
	"past alerts, then read the disagreements, unknowns and costs and refine (back to 3); (6) investigate_save_plan, " +
	"which always saves a DRAFT. A person promotes a draft to active in the console; no tool can."

var sectionNames = map[string]bool{"schema": true, "guide": true, "operators": true, "examples": true, "policy": true, "codes": true}

func init() {
	register("investigate_operators",
		"List the operators a plan template can call in this org: per operator its class, cost class, arguments "+
			"(`args`: name, type, required) and the shape of the fact it produces (`output`), and whether this org may use it "+
			"(`available`, `why`). The authoring kit already contains this list; call this to re-read or filter it. "+
			"Requires investigation.get and insight.evt.get. "+authoringLoop,
		[]mcp.ToolOption{
			mcp.WithString("filter", mcp.Description("Keep only operators whose name, class or description contains this text (case-insensitive), for example `search` or `entity`.")),
			mcp.WithBoolean("brief", mcp.Description("Keep only name, class, description, available and why for each operator: a quick index. Call again with `filter` for the full row of one operator.")),
		}, handleOperators)

	register("investigate_authoring_kit",
		"Everything needed to write an investigation plan template, in ONE call: the template JSON Schema, the authoring "+
			"guide (how facts, signals, proofs, evidence, respond and report work, when a result is unknown or complete, the "+
			"common mistakes), the org's typed operator catalog (the fields each operator produces, which operators the org "+
			"may use), the platform's managed templates as examples, the org's effective policy and budgets, and every "+
			"validation code with its usual fix. Call it FIRST, once, and keep it: the full kit is about 25-30k tokens. Later, "+
			"pass `sections` to re-read only part of it. `size` says what was returned. Requires investigation.get and "+
			"insight.evt.get. "+authoringLoop,
		[]mcp.ToolOption{
			mcp.WithArray("sections", mcp.WithStringItems(), mcp.Description("Optional. Any of schema, guide, operators, examples, policy, codes. Omit for the whole kit.")),
		}, handleKit)

	register("investigate_validate_plan",
		"Check an investigation plan template (YAML) without running anything: structure, operator names and arguments, "+
			"every $reference and expression against the operators' typed outputs, dependency cycles, and the org's budgets. "+
			"Returns `valid`, `errors` and `warnings` (each with a `code`, a `path`, a message and often a `suggestion`: the "+
			"fix), the worst-case step count and cost class, and an `estimate` of the worst-case cost of one run. Fix every "+
			"error, and read every warning, then validate again until `errors` is empty. A template that does not validate "+
			"cannot be saved or tested. Requires investigation.get. "+authoringLoop,
		[]mcp.ToolOption{
			mcp.WithString("yaml", mcp.Required(), mcp.Description("The template source (YAML). The template name is not part of it; do not add a `name:` key.")),
		}, handleValidate)

	register("investigate_test_plan",
		"Dry-run a plan on REAL past alerts and report how it did. Runs the plan's real read-only operators, with the "+
			"caller's token, on each sample; nothing is written (no run, case, label or action) and any response step is only "+
			"listed in `would_propose`. Give exactly one of `yaml` (a draft in progress) or `template` (a stored template), and "+
			"`samples`: objects with ONE of {detection_id}, {case_id}, {detect_cat, last: 1..25} (the newest alerts of a "+
			"category), or {inputs, expected} (free inputs and an optional expected label true_positive|false_positive); at most "+
			"25 after expansion. A sample whose case is closed is judged against the case's classification: `agreement` is "+
			"agree, disagree, undecided or none, and `summary.agreement_rate` is the share that agreed. Use at least 5-10 samples "+
			"of the category and include known false positives AND known true positives. Read in this order: `validation` (if "+
			"state is invalid, fix the template), `summary`, then each `disagree`, then `undecided` samples: `unknowns` names the "+
			"facts that could not be resolved and why (the usual cause is a wrong field path or argument), `problem_steps` the "+
			"steps that failed. A test takes seconds to minutes: this call waits up to `wait_seconds`; if `done` is false, call "+
			"again with the returned `test_id` (and nothing else) to keep waiting. Requires investigation.set and "+
			"insight.evt.get; it counts against the org's concurrent run cap and bills LLM steps. "+authoringLoop,
		[]mcp.ToolOption{
			mcp.WithString("yaml", mcp.Description("Template source (YAML) to test as a draft. Give this or `template`.")),
			mcp.WithString("template", mcp.Description("Name of a stored template (draft or active) to test. Give this or `yaml`.")),
			mcp.WithArray("samples", mcp.Items(map[string]any{"type": "object"}), mcp.Description("The alerts to test on: objects with one of {detection_id}, {case_id}, {detect_cat, last}, {inputs, expected}.")),
			mcp.WithString("test_id", mcp.Description("Keep waiting on a test started earlier by this tool. Replaces yaml, template and samples.")),
			mcp.WithString("mode", mcp.Description("triage (default, the cheap pass) or full.")),
			mcp.WithBoolean("strict", mcp.Description("Treat any unknown as a failure of the plan. Default false.")),
			mcp.WithObject("overrides", mcp.Description("Optional tighten-only budget overrides, for example {\"budgets\": {\"max_wall_seconds\": 120}}.")),
			mcp.WithNumber("wait_seconds", mcp.Description("How long this call may block waiting for the test, 0..180. Default 60.")),
			mcp.WithBoolean("include_steps", mcp.Description("Also return every step of every sample (large). Default false: only the steps that did not succeed.")),
		}, handleTestPlan)

	register("investigate_save_plan",
		"Save a plan template as a DRAFT in the org's investigation_plan hive. It always writes `status: draft`; it refuses "+
			"a template that sets `status: active`, refuses a template that does not validate, never overwrites an active "+
			"template and never touches a platform-managed one. An existing draft is replaced only with `overwrite: true`. A "+
			"draft never runs on its own: it runs only through investigate_test_plan or a run a person starts (with autonomy "+
			"capped at suggest), and a person promotes it to active in the console. Pass `test_summary`: what you tested "+
			"(samples, agreement rate, unknowns, cost), so the reviewer sees it with the draft. Requires "+
			"investigation_plan.get, investigation_plan.set, investigation.get and insight.evt.get. "+authoringLoop,
		[]mcp.ToolOption{
			mcp.WithString("name", mcp.Required(), mcp.Description("The template name (the record key): lowercase letters, digits, - and _, at most 64 characters. Not the name of a managed template.")),
			mcp.WithString("yaml", mcp.Required(), mcp.Description("The template source (YAML) that validated clean. Leave `status` out.")),
			mcp.WithString("test_summary", mcp.Description("What the draft was tested on and how it did, up to 2000 characters. Stored as the record's comment.")),
			mcp.WithBoolean("overwrite", mcp.Description("Replace an existing DRAFT of the same name. Never replaces an active template. Default false.")),
		}, handleSavePlan)

	register("investigate_list_templates",
		"List the plan templates the engine has loaded for this org: name, version, description, `applies_to`, `managed` "+
			"(shipped by the platform) and `status` (draft or active). Use it to see what already exists before drafting, and "+
			"to pick a name that is free. Requires investigation.get and insight.evt.get.",
		[]mcp.ToolOption{
			mcp.WithString("status", mcp.Description("Keep only draft or active templates.")),
			mcp.WithBoolean("include_managed", mcp.Description("Include the platform-managed templates. Default true.")),
		}, handleListTemplates)

	register("investigate_start",
		"Start an investigation run: the engine gathers facts with its operators, weighs them and reaches a verdict "+
			"(true_positive, false_positive or inconclusive) with a proof. Give a `template` (or `auto` to pick by the alert) "+
			"and the thing to investigate: a `detection_id`, a `case_id`, an `entity_id` or a `question`. A draft template "+
			"runs with autonomy capped at suggest; an active one acts as the org's policy says (response actions may need a "+
			"person's approval). To try a draft on past alerts without a run, use investigate_test_plan instead. Poll with "+
			"investigate_get. Requires investigation.set and insight.evt.get.",
		[]mcp.ToolOption{
			mcp.WithString("template", mcp.Description("Template name. Give this or `auto`.")),
			mcp.WithBoolean("auto", mcp.Description("Pick the active template whose applies_to matches the alert.")),
			mcp.WithString("detection_id", mcp.Description("Detection to investigate.")),
			mcp.WithString("case_id", mcp.Description("Case to investigate.")),
			mcp.WithString("entity_id", mcp.Description("Entity to investigate.")),
			mcp.WithString("question", mcp.Description("Free-text question, for a template that takes one.")),
			mcp.WithObject("inputs", mcp.Description("Extra run inputs, name to value.")),
			mcp.WithString("urgency", mcp.Description("Optional urgency: low, normal or high.")),
			mcp.WithString("mode", mcp.Description("triage (default), full or scope.")),
			mcp.WithString("case", mcp.Description("create, none or attach:<case id>. Default per the org's policy.")),
			mcp.WithString("idempotency_key", mcp.Description("Starting twice with the same key returns the same run.")),
			mcp.WithNumber("wait_seconds", mcp.Description("Wait up to this many seconds (0..60) for the run to finish before answering.")),
		}, handleStart)

	register("investigate_get",
		"Read an investigation run. `view` is run (default: state, phase, verdict, actions, usage), steps (the step log, "+
			"plan graph and belief curve), events (the run's events after sequence `after`; long-polls up to `wait` seconds; "+
			"`done` is true when the run is over) or case (the case document the run wrote). Requires investigation.get and "+
			"insight.evt.get.",
		[]mcp.ToolOption{
			mcp.WithString("run_id", mcp.Required(), mcp.Description("The run id.")),
			mcp.WithString("view", mcp.Description("run (default), steps, events or case.")),
			mcp.WithNumber("after", mcp.Description("For events: return events after this sequence number. Default 0.")),
			mcp.WithNumber("wait", mcp.Description("For events: wait up to this many seconds (0..10) for a new event. Default 0.")),
		}, handleGet)

	register("investigate_wave",
		"Run a batch of the engine's operators NOW, with your token, and return their facts: no plan, no verdict. Use it "+
			"while drafting a plan to see what an operator really returns for a real value before writing the plan around "+
			"it. `steps` is a list of {id, op, args}; a step may reference another with \"$id.path\" and a name in `inputs`. "+
			"Results come back per step with `status` (ok or unknown, and the reason), `complete` and the `value`. Bounded "+
			"by the org's budgets. Requires investigation.set and insight.evt.get. "+authoringLoop,
		[]mcp.ToolOption{
			mcp.WithArray("steps", mcp.Required(), mcp.Items(map[string]any{"type": "object"}), mcp.Description("Operator calls: objects {id, op, args}. Ids are unique.")),
			mcp.WithNumber("deadline_ms", mcp.Description("Wall time allowed for the whole wave, in milliseconds. Default 30000.")),
			mcp.WithObject("inputs", mcp.Description("Named values the steps can reference as $name.")),
		}, handleWave)
}

// readOnlyTools are the tools that change nothing and are in the read-only profile. The authoritative
// classification is annotations_table.go; the schema declares the one hint the OAuth scope policy reads, and a
// test keeps the two equal.
var readOnlyTools = map[string]bool{
	"investigate_operators": true, "investigate_authoring_kit": true, "investigate_validate_plan": true,
	"investigate_list_templates": true, "investigate_get": true,
}

func register(name, description string, options []mcp.ToolOption, h tools.ToolHandler) {
	opts := append([]mcp.ToolOption{mcp.WithDescription(description), mcp.WithReadOnlyHintAnnotation(readOnlyTools[name])}, options...)
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        name,
		Description: description,
		Profile:     Profile,
		RequiresOID: true,
		Schema:      mcp.NewTool(name, opts...),
		Handler:     h,
	})
}

// fail is the tool error for a bad argument or a failed call.
func fail(err error) (*mcp.CallToolResult, error) {
	return tools.ErrorResult(err.Error()), nil
}

func handleOperators(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	filter, err := optString(args, "filter")
	if err != nil {
		return fail(err)
	}
	brief, err := optBool(args, "brief")
	if err != nil {
		return fail(err)
	}
	out, err := call(ctx, engineCall{method: http.MethodGet, suffix: "operators"})
	if err != nil {
		return fail(err)
	}
	return tools.SuccessResult(shapeOperators(out, filter, brief)), nil
}

// shapeOperators applies the filter and brief options to the engine's operator list.
func shapeOperators(out map[string]interface{}, filter string, brief bool) map[string]interface{} {
	rows, _ := out["operators"].([]interface{})
	needle := strings.ToLower(filter)
	kept := make([]interface{}, 0, len(rows))
	for _, r := range rows {
		row, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		if needle != "" {
			hay := strings.ToLower(str(row["name"]) + " " + str(row["class"]) + " " + str(row["description"]))
			if !strings.Contains(hay, needle) {
				continue
			}
		}
		if brief {
			row = pick(row, "name", "class", "description", "available", "why")
		}
		kept = append(kept, row)
	}
	out["operators"] = kept
	out["count"] = len(kept)
	return out
}

func handleKit(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	sections, err := stringList(args, "sections")
	if err != nil {
		return fail(err)
	}
	query := url.Values{}
	if len(sections) > 0 {
		for _, s := range sections {
			if !sectionNames[s] {
				return tools.ErrorResultf("unknown section %q: use schema, guide, operators, examples, policy or codes", s), nil
			}
		}
		query.Set("sections", strings.Join(sections, ","))
	}
	out, err := call(ctx, engineCall{method: http.MethodGet, suffix: "authoring-kit", query: query})
	if err != nil {
		return fail(err)
	}
	return tools.SuccessResult(out), nil
}

func handleValidate(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	src, err := optString(args, "yaml")
	if err != nil {
		return fail(err)
	}
	if strings.TrimSpace(src) == "" {
		return tools.ErrorResult("yaml is required"), nil
	}
	out, err := call(ctx, engineCall{method: http.MethodPost, suffix: "plans/validate", body: map[string]interface{}{"yaml": src}})
	if err != nil {
		return fail(err)
	}
	return tools.SuccessResult(out), nil
}

func handleListTemplates(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	status, err := optString(args, "status")
	if err != nil {
		return fail(err)
	}
	if status != "" && status != "draft" && status != "active" {
		return tools.ErrorResult("status must be draft or active"), nil
	}
	includeManaged := true
	if v, ok := args["include_managed"]; ok && v != nil {
		if includeManaged, ok = v.(bool); !ok {
			return tools.ErrorResult("include_managed must be a boolean"), nil
		}
	}
	out, err := call(ctx, engineCall{method: http.MethodGet, suffix: "templates"})
	if err != nil {
		return fail(err)
	}
	rows, _ := out["templates"].([]interface{})
	kept := make([]interface{}, 0, len(rows))
	for _, r := range rows {
		row, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		if status != "" && templateStatus(row) != status {
			continue
		}
		if !includeManaged && row["managed"] == true {
			continue
		}
		kept = append(kept, row)
	}
	out["templates"] = kept
	return tools.SuccessResult(out), nil
}

// templateStatus is the status of a list_templates row: anything that is not "active" is a draft.
func templateStatus(row map[string]interface{}) string {
	if str(row["status"]) == "active" {
		return "active"
	}
	return "draft"
}

func handleStart(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	arg := func(name string) string { s, _ := args[name].(string); return s }
	for _, name := range []string{"template", "detection_id", "case_id", "entity_id", "question", "urgency", "mode", "case", "idempotency_key"} {
		if _, err := optString(args, name); err != nil {
			return fail(err)
		}
	}
	auto, err := optBool(args, "auto")
	if err != nil {
		return fail(err)
	}
	inputs, err := optObject(args, "inputs")
	if err != nil {
		return fail(err)
	}
	wait, _, err := optInt(args, "wait_seconds")
	if err != nil {
		return fail(err)
	}
	if wait < 0 || wait > 60 {
		return tools.ErrorResult("wait_seconds must be between 0 and 60"), nil
	}
	if (arg("template") != "") == auto {
		return tools.ErrorResult("give exactly one of template or auto"), nil
	}
	trigger := map[string]interface{}{}
	for _, k := range []string{"detection_id", "case_id", "entity_id", "question"} {
		if v := arg(k); v != "" {
			trigger[k] = v
		}
	}
	if len(trigger) == 0 {
		return tools.ErrorResult("give one of detection_id, case_id, entity_id or question"), nil
	}
	plan := map[string]interface{}{}
	if t := arg("template"); t != "" {
		plan["template"] = t
	} else {
		plan["auto"] = true
	}
	body := map[string]interface{}{"trigger": trigger, "plan": plan}
	for _, k := range []string{"urgency", "mode", "case", "idempotency_key"} {
		if v := arg(k); v != "" {
			body[k] = v
		}
	}
	if inputs != nil {
		body["inputs"] = inputs
	}
	if wait > 0 {
		body["wait_seconds"] = wait
	}
	out, err := call(ctx, engineCall{method: http.MethodPost, suffix: "runs", body: body})
	if err != nil {
		return fail(err)
	}
	return tools.SuccessResult(out), nil
}

func handleGet(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	runID, err := optString(args, "run_id")
	if err != nil {
		return fail(err)
	}
	if err := pathID("run_id", runID); err != nil {
		return fail(err)
	}
	view, err := optString(args, "view")
	if err != nil {
		return fail(err)
	}
	after, _, err := optInt(args, "after")
	if err != nil {
		return fail(err)
	}
	wait, _, err := optInt(args, "wait")
	if err != nil {
		return fail(err)
	}
	if after < 0 || wait < 0 || wait > 10 {
		return tools.ErrorResult("after must be 0 or more and wait between 0 and 10"), nil
	}
	suffix := "runs/" + url.PathEscape(runID)
	query := url.Values{}
	switch view {
	case "", "run":
	case "steps":
		suffix += "/steps"
	case "case":
		suffix += "/case"
	case "events":
		suffix += "/events"
		query.Set("after", strconv.Itoa(after))
		query.Set("wait", strconv.Itoa(wait))
	default:
		return tools.ErrorResult("view must be run, steps, events or case"), nil
	}
	out, err := call(ctx, engineCall{method: http.MethodGet, suffix: suffix, query: query})
	if err != nil {
		return fail(err)
	}
	return tools.SuccessResult(out), nil
}

func handleWave(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	steps, err := optObjects(args, "steps")
	if err != nil {
		return fail(err)
	}
	if len(steps) == 0 {
		return tools.ErrorResult("steps is required: a list of {id, op, args}"), nil
	}
	deadline, given, err := optInt(args, "deadline_ms")
	if err != nil {
		return fail(err)
	}
	inputs, err := optObject(args, "inputs")
	if err != nil {
		return fail(err)
	}
	body := map[string]interface{}{"steps": steps}
	if given {
		if deadline <= 0 || deadline > 600000 {
			return tools.ErrorResult("deadline_ms must be between 1 and 600000"), nil
		}
		body["deadline_ms"] = deadline
	}
	if inputs != nil {
		body["inputs"] = inputs
	}
	out, err := call(ctx, engineCall{method: http.MethodPost, suffix: "waves", body: body})
	if err != nil {
		return fail(err)
	}
	return tools.SuccessResult(out), nil
}

func str(v interface{}) string {
	s, _ := v.(string)
	return s
}

// pick copies the named keys that are present.
func pick(m map[string]interface{}, keys ...string) map[string]interface{} {
	out := make(map[string]interface{}, len(keys))
	for _, k := range keys {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	return out
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
