package investigation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

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

// waveLoop is the loop a novel investigation follows with waves and fact packs. investigate_wave and
// investigate_packs both teach it.
const waveLoop = "Investigation loop (no template needed): (1) investigate_packs once: its index is enough to write the waves " +
	"(parameters, exports, reference forms), you do not need investigate_operators for it; (2) investigate_wave with one " +
	"step per pack or operator you need, each with `select` naming only the fields you will read; (3) set `stop_when` " +
	"to the expressions that would settle the question, so the engine cancels the rest the moment one is true; (4) read " +
	"the compact facts (`status`, `complete`, `value`, `stopped_by`, `usage`) and plan the next wave from them; (5) stop " +
	"when the question is answered. A step that is `unknown` or not `complete` established nothing: it is never an " +
	"absence. Do not set `full` unless a compact value hides something you need. Who and what is in the org: the " +
	"`org_roster` pack lists the machines (offline ones included) and their owners."

// preferWaves opens the description of the tools that run waves: when the same questions can be asked with the
// per-call read tools of this server, a wave is the way for any question that needs more than one check.
const preferWaves = "PREFER THIS for any question that needs more than one check (who and what is affected, what a host or a " +
	"user did, how widespread an indicator is): send all the checks in ONE investigate_wave instead of calling " +
	"list_sensors, get_historic_events, run_lcql_query, the mailsec_* and cloudsec_entity_* tools one at a time. The " +
	"engine runs them in parallel and returns compact answers; use the single read tools only for one lookup or for a " +
	"detail a wave did not return. "

// maxStopWhen is how many stop_when expressions a wave may carry.
const maxStopWhen = 8

// maxWaveDeadlineMS bounds a wave's deadline: the call holds its connection for that long.
const maxWaveDeadlineMS = 300000

var sectionNames = map[string]bool{"schema": true, "guide": true, "operators": true, "examples": true, "policy": true, "codes": true, "packs": true, "library": true}

func init() {
	register("investigate_operators",
		"List the operators a plan template can call in this org: per operator its class, cost class, arguments "+
			"(`args`: name, type, required) and the shape of the fact it produces (`output`), and whether this org may use it "+
			"(`available`, `why`). You only need this for a custom `op` step, or when drafting a plan template: waves that use "+
			"fact packs (investigate_packs) never need it. The authoring kit already contains this list, but all at once it is large (about 14k tokens): "+
			"call this with `brief` for the index, then with `names` for the full rows of the operators you will use. "+
			"Requires investigation.get and insight.evt.get. "+authoringLoop,
		[]mcp.ToolOption{
			mcp.WithString("filter", mcp.Description("Keep only operators whose name, class or description contains this text (case-insensitive), for example `search` or `entity`.")),
			mcp.WithArray("names", mcp.WithStringItems(), mcp.Description("Keep only these operators (exact names, for example [\"detection.get\", \"ioc.prevalence\"]): their full rows, args and output fields included.")),
			mcp.WithBoolean("brief", mcp.Description("Keep only name, class, description, available and why for each operator: a quick index. Then call again with `names` for the full rows of the operators you will use.")),
		}, handleOperators)

	register("investigate_authoring_kit",
		"Everything needed to write an investigation plan template, in ONE call: the template JSON Schema, the authoring "+
			"guide (how facts, signals, proofs, evidence, respond and report work, when a result is unknown or complete, the "+
			"common mistakes), the org's typed operator catalog (the fields each operator produces, which operators the org "+
			"may use), the default template library (ready-made templates to learn from or install), the org's effective "+
			"policy and budgets, and every validation code with its usual fix, and the fact packs a plan or a wave can use. "+
			"An org's templates are exactly its investigation_plan hive records; nothing is provided automatically. To install a "+
			"library template, read it from the `library` section and write it as an `investigation_plan/<name>` record with the "+
			"hive tools. Call it FIRST and keep what it says. The whole kit is about 33k tokens, more "+
			"than many clients accept in one tool result, so fetch it in pieces: sections=\"guide,policy,codes\" (read "+
			"first), then sections=\"schema,library\". The operators section alone is about 14k tokens and also too large "+
			"for some clients: get the operator index with investigate_operators (brief), then the full rows of the ones you "+
			"use with investigate_operators (names). `size` says what was returned. Requires investigation.get and "+
			"insight.evt.get. "+authoringLoop,
		[]mcp.ToolOption{
			mcp.WithArray("sections", mcp.WithStringItems(), mcp.Description("Optional. Any of schema, guide, operators, examples, policy, codes, packs, library. Omit for the whole kit.")),
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
			"template. An existing draft is replaced only with `overwrite: true`. A "+
			"draft never runs on its own: it runs only through investigate_test_plan or a run a person starts (with autonomy "+
			"capped at suggest), and a person promotes it to active in the console. Pass `test_summary`: what you tested "+
			"(samples, agreement rate, unknowns, cost), so the reviewer sees it with the draft. Requires "+
			"investigation_plan.get, investigation_plan.set, investigation.get and insight.evt.get. "+authoringLoop,
		[]mcp.ToolOption{
			mcp.WithString("name", mcp.Required(), mcp.Description("The template name (the record key): lowercase letters, digits, - and _, at most 64 characters.")),
			mcp.WithString("yaml", mcp.Required(), mcp.Description("The template source (YAML) that validated clean. Leave `status` out.")),
			mcp.WithString("test_summary", mcp.Description("What the draft was tested on and how it did, up to 2000 characters. Stored as the record's comment.")),
			mcp.WithBoolean("overwrite", mcp.Description("Replace an existing DRAFT of the same name. Never replaces an active template. Default false.")),
		}, handleSavePlan)

	register("investigate_list_templates",
		"List the plan templates of this org, which are its investigation_plan hive records: name, version, description, "+
			"`applies_to` and `status` (draft or active). The default library is not listed here: get it with "+
			"investigate_authoring_kit (sections=\"library\") and install a template by writing the record with the hive "+
			"tools. Use this to see what already exists before drafting, and to pick a name that is free. Requires investigation.get and insight.evt.get.",
		[]mcp.ToolOption{
			mcp.WithString("status", mcp.Description("Keep only draft or active templates.")),
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
		preferWaves+"Hands the engine a whole batch of questions at once and gets compact, typed answers. The engine runs every ready "+
			"step in parallel with YOUR token (no plan, no verdict, nothing stored), reuses what it already knows, and can "+
			"stop as soon as the answer is known. `steps` is a list of {id, op|use, args, select, limit}: `op` is an "+
			"operator (investigate_operators), `use` a fact pack (investigate_packs) with its parameters in `args`; "+
			"exactly one of them. A string argument that is a whole reference (\"$host__resolve.entity_id\", "+
			"\"$prev.hosts_30d\") reads another step's value and the step waits for it; a name in `inputs` is read as "+
			"$name. `select` lists the field paths of the step's value you want (`matches[*].entity_id`; for a pack, its "+
			"export names) and is checked before anything runs; `limit` (1..1000, default 10) caps the elements of every "+
			"list. `stop_when` is a list (at most 8) of boolean expressions over the step ids and fields "+
			"(`prev.hosts_30d >= 50 and kids.count == 0`, `host__resolve.found == false`): as soon as one is TRUE the "+
			"engine cancels the steps still running (`cancelled`, reason `irrelevant:stop_when`) and `stopped_by` names it. "+
			"An unknown is never false, so a step that is `unknown` or not `complete` cannot stop the wave. The answer is "+
			"COMPACT by default: per step `status` (ok, unknown with a `reason`, cancelled, or partial for a pack), "+
			"`complete` (false means a lower bound, not proof of absence), `ms` and the selected `value`; plus `usage` "+
			"(steps, cancelled, search events, wall ms). Send `full: true` only when the compact value hides something you "+
			"need, it returns raw values and costs many more tokens. `validate_only: true` checks the wave (unknown "+
			"operator, argument, field or reference come back with a suggestion) and runs nothing; an invalid wave is "+
			"refused with every error listed as `[code] path: message (did you mean ...)`: fix them and send again. "+
			"Bounded by the org's budgets. Requires investigation.set and insight.evt.get. "+waveLoop+" Also useful while "+
			"drafting a plan template, to see what an operator returns for a real value: "+authoringLoop,
		[]mcp.ToolOption{
			mcp.WithArray("steps", mcp.Required(), mcp.Items(map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":     map[string]any{"type": "string", "description": "Unique id, letters, digits and underscore, starting with a letter; no double underscore."},
					"op":     map[string]any{"type": "string", "description": "An operator of the catalog. Give op or use, not both."},
					"use":    map[string]any{"type": "string", "description": "A fact pack (investigate_packs). Give op or use, not both."},
					"args":   map[string]any{"type": "object", "description": "The operator's arguments, or the pack's parameters."},
					"select": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Field paths of the value to return (a pack's export names for use). Default: the operator's summary."},
					"limit":  map[string]any{"type": "integer", "description": "At most this many elements of every list (1..1000, default 10)."},
				},
			}), mcp.Description("Questions: objects {id, op or use, args, select, limit}. Ids are unique.")),
			mcp.WithArray("stop_when", mcp.WithStringItems(), mcp.Description("Expressions that would settle the question, over step ids and fields, for example [\"prev.hosts_30d >= 50\"]. The wave stops as soon as one is true. At most 8.")),
			mcp.WithBoolean("full", mcp.Description("Return the raw value of every step instead of the compact one. Default false: leave it off unless needed.")),
			mcp.WithBoolean("validate_only", mcp.Description("Only check the wave and return its errors, warnings and expanded steps; run nothing.")),
			mcp.WithNumber("deadline_ms", mcp.Description("Wall time allowed for the whole wave, in milliseconds. Default 30000.")),
			mcp.WithObject("inputs", mcp.Description("Named values the steps and stop_when can reference as $name.")),
		}, handleWave)

	register("investigate_packs",
		"Call this FIRST for a multi-check question, then answer it with investigate_wave (see its description: waves "+
			"replace many single read-tool calls). Lists the fact packs: named, versioned, tested bundles of questions "+
			"for the data sources supported by this engine version. Discover identity sign-in, SaaS audit, cloud resource "+
			"and vulnerability coverage from the returned index; do not assume every source is installed or has data. "+
			"`org_roster` lists the org's machines and the people who own them. By default a compact INDEX that is "+
			"enough on its own to write the waves: per pack what it does, its args with types (* required, =default) and "+
			"its exports with type, reference form (for `stop_when` and other steps' args) and a few words of meaning. "+
			"You do NOT need investigate_operators for pack-driven work; it is only for a custom `op` step. (In a read-only "+
			"profile investigate_wave is not offered: the index then only tells you which checks exist, run them with the "+
			"single read tools.) Pass `name` for "+
			"one pack's full row (every description, the operators it runs), or `full: true` for every full row (large). "+
			"Requires investigation.get and insight.evt.get. "+waveLoop,
		[]mcp.ToolOption{
			mcp.WithString("name", mcp.Description("Optional. Return only this pack, in full, for example host_context.")),
			mcp.WithBoolean("full", mcp.Description("Return the full row of every pack instead of the index. Default false.")),
		}, handlePacks)
}

// readOnlyTools are the tools that change nothing and are in the read-only profile. The authoritative
// classification is annotations_table.go; the schema declares the one hint the OAuth scope policy reads, and a
// test keeps the two equal.
var readOnlyTools = map[string]bool{
	"investigate_operators": true, "investigate_authoring_kit": true, "investigate_validate_plan": true,
	"investigate_list_templates": true, "investigate_get": true, "investigate_packs": true,
}

// register declares an Investigation Engine tool. Every tool of this package is declared through here, which is
// what puts them all behind the INVESTIGATION_ENGINE_ENABLED gate (see tools.EnvInvestigationEngine).
func register(name, description string, options []mcp.ToolOption, h tools.ToolHandler) {
	opts := append([]mcp.ToolOption{mcp.WithDescription(description), mcp.WithReadOnlyHintAnnotation(readOnlyTools[name])}, options...)
	tools.RegisterInvestigationEngineTool(&tools.ToolRegistration{
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
	names, err := stringList(args, "names")
	if err != nil {
		return fail(err)
	}
	out, err := call(ctx, engineCall{method: http.MethodGet, suffix: "operators"})
	if err != nil {
		return fail(err)
	}
	return tools.SuccessResult(shapeOperators(out, filter, names, brief)), nil
}

// shapeOperators applies the filter and brief options to the engine's operator list.
func shapeOperators(out map[string]interface{}, filter string, names []string, brief bool) map[string]interface{} {
	rows, _ := out["operators"].([]interface{})
	needle := strings.ToLower(filter)
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	kept := make([]interface{}, 0, len(rows))
	for _, r := range rows {
		row, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		if len(want) > 0 && !want[str(row["name"])] {
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
				return tools.ErrorResultf("unknown section %q: use schema, guide, operators, examples, policy, codes, packs or library", s), nil
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
	out, err := call(ctx, engineCall{method: http.MethodPost, suffix: "runs", body: body, timeout: time.Duration(wait)*time.Second + waitMargin})
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
		return tools.ErrorResult("steps is required: a list of {id, op or use, args, select, limit}"), nil
	}
	deadline, given, err := optInt(args, "deadline_ms")
	if err != nil {
		return fail(err)
	}
	inputs, err := optObject(args, "inputs")
	if err != nil {
		return fail(err)
	}
	stopWhen, err := expressionList(args, "stop_when")
	if err != nil {
		return fail(err)
	}
	full, err := optBool(args, "full")
	if err != nil {
		return fail(err)
	}
	validateOnly, err := optBool(args, "validate_only")
	if err != nil {
		return fail(err)
	}
	// What a step, a select or an expression says is the engine's to validate: its coded errors carry
	// suggestions, and are returned as they come.
	body := map[string]interface{}{"steps": steps}
	if given {
		if deadline <= 0 || deadline > maxWaveDeadlineMS {
			return tools.ErrorResultf("deadline_ms must be between 1 and %d", maxWaveDeadlineMS), nil
		}
		body["deadline_ms"] = deadline
	}
	if inputs != nil {
		body["inputs"] = inputs
	}
	if len(stopWhen) > 0 {
		body["stop_when"] = stopWhen
	}
	if full {
		body["full"] = true
	}
	if validateOnly {
		body["validate_only"] = true
	}
	out, err := call(ctx, engineCall{method: http.MethodPost, suffix: "waves", body: body, timeout: time.Duration(deadline)*time.Millisecond + waitMargin})
	if err != nil {
		return fail(err)
	}
	return tools.SuccessResult(out), nil
}

// expressionList reads an array of expressions. Unlike stringList it never splits on commas: an expression
// may contain them (`x in [1, 2]`).
func expressionList(args map[string]interface{}, name string) ([]string, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return nil, nil
	}
	list, ok := v.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an array of expression strings", name)
	}
	if len(list) > maxStopWhen {
		return nil, fmt.Errorf("%s has %d expressions, at most %d are allowed", name, len(list), maxStopWhen)
	}
	out := make([]string, 0, len(list))
	for i, item := range list {
		e, ok := item.(string)
		if !ok || strings.TrimSpace(e) == "" {
			return nil, fmt.Errorf("%s[%d] must be a non-empty expression string", name, i)
		}
		out = append(out, e)
	}
	return out, nil
}

func handlePacks(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	name, err := optString(args, "name")
	if err != nil {
		return fail(err)
	}
	full, err := optBool(args, "full")
	if err != nil {
		return fail(err)
	}
	query := url.Values{}
	name = strings.TrimSpace(name)
	if name != "" {
		query.Set("name", name)
	}
	out, err := call(ctx, engineCall{method: http.MethodGet, suffix: "packs", query: query})
	if err != nil {
		return fail(err)
	}
	if name == "" && !full {
		out = packIndex(out)
	}
	return tools.SuccessResult(out), nil
}

// packIndexHow is said once at the top of the index: how to read an entry and use a reference.
const packIndexHow = "Use a pack as a wave step {id, use: <name>, args: {<params>}, select: [<export names>]}. " +
	"args: name:type, * = required, =value is the default (types: str num bool int list obj any). exports are grouped " +
	"by the fact that holds them: <fact>: [name:type meaning]. In stop_when or another step's args an export is " +
	"<step id>__<fact>.<name>, e.g. step h on host_context: h__resolve.resolved; `name:type @path` means the path " +
	"after the fact is <path> instead of <name> (`@(fact)`: the whole fact); exports under `select_only` have no such form. This index is enough " +
	"to write the waves: investigate_operators is only needed for a custom `op` step. {name} returns one pack's full row."

var typeAbbrev = map[string]string{"string": "str", "number": "num", "boolean": "bool", "integer": "int", "array": "list", "object": "obj"}

func abbrevType(t string) string {
	if a, ok := typeAbbrev[t]; ok {
		return a
	}
	return t
}

// packIndex turns the engine's pack rows into an index that is enough on its own to choose and call a pack: per pack a
// one-line meaning, its params with types, and its exports with type, reference form and a few words of meaning. The
// operators, facts and long descriptions stay in the pack's full row.
func packIndex(out map[string]interface{}) map[string]interface{} {
	rows, _ := out["packs"].([]interface{})
	index := make([]interface{}, 0, len(rows))
	for _, r := range rows {
		row, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		entry := map[string]interface{}{"name": row["name"], "does": firstNonEmpty(str(row["brief"]), str(row["description"]))}
		var args []string
		for _, p := range asList(row["params"]) {
			if m, ok := p.(map[string]interface{}); ok {
				args = append(args, paramLine(m))
			}
		}
		entry["args"] = strings.Join(args, ", ")
		groups := map[string][]interface{}{}
		for _, e := range asList(row["exports"]) {
			if m, ok := e.(map[string]interface{}); ok {
				group, line := exportLine(m)
				groups[group] = append(groups[group], line)
			}
		}
		entry["exports"] = groups
		if c := str(row["cost_class"]); c != "" && c != "free" {
			entry["cost"] = c
		}
		index = append(index, entry)
	}
	res := map[string]interface{}{}
	for k, v := range out { // anything else the engine returns next to the packs stays
		res[k] = v
	}
	res["how"], res["packs"] = packIndexHow, index
	return res
}

// paramLine is `name:type*` (required) or `name:type=default`.
func paramLine(p map[string]interface{}) string {
	line := str(p["name"]) + ":" + abbrevType(str(p["type"]))
	if req, _ := p["required"].(bool); req {
		line += "*"
	}
	if d, ok := p["default"]; ok && d != nil {
		b, _ := json.Marshal(d)
		line += "=" + string(b)
	}
	return line
}

// exportLine is the group of an export (the fact that holds it, or select_only when no expression can read it) and its
// line `name:type [@path] meaning`.
func exportLine(e map[string]interface{}) (group, line string) {
	name := str(e["name"])
	line = name + ":" + abbrevType(str(e["type"]))
	group = "select_only"
	if ref := strings.TrimPrefix(str(e["ref"]), "<id>__"); ref != "" {
		group = ref
		path := ""
		if i := strings.IndexAny(ref, ".["); i >= 0 {
			group, path = ref[:i], strings.TrimPrefix(ref[i:], ".")
		}
		switch {
		case path == "":
			line += " @(fact)" // the export is the whole fact
		case path != name:
			line += " @" + path
		}
	}
	if b := firstNonEmpty(str(e["brief"]), str(e["description"])); b != "" {
		line += " " + b
	}
	return group, line
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func asList(v interface{}) []interface{} {
	l, _ := v.([]interface{})
	return l
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
