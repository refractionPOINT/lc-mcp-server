package investigation

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// The tools of this file are what an agent uses after a template is live: how it performs (stats, runs, labels),
// which template a trigger picks (coverage), and what an edit would have done to runs that already finished
// (compare). The loop they teach is the tail of the authoring loop.

// reviewLoop is said by every tool of this file, so an agent that has read any one of them knows where it is.
const reviewLoop = "Tuning loop for a LIVE template: investigate_stats (per template outcomes, which rule decided, what evidence was missing, " +
	"how many actions were suggested, approved, undone) -> investigate_list_runs (the runs behind a number) -> investigate_get " +
	"(one run) -> edit the YAML -> investigate_compare (replay the edit against finished runs, nothing is run or written) -> " +
	"investigate_test_plan on fresh alerts -> investigate_save_plan (a draft) for a person to promote. Never propose a change " +
	"to a live template before you have read its stats and replayed the edit."

const maxCompareRuns = 50

var runOutcomes = map[string]bool{
	"closed_by_rule": true, "escalated_by_rule": true, "closed_by_ai": true, "escalated_by_ai": true,
	"ai_recommends_benign": true, "ai_recommends_malicious": true, "couldnt_tell": true, "conflict": true, "undecided": true,
}

const runOutcomeList = "closed_by_rule, escalated_by_rule, closed_by_ai, escalated_by_ai, ai_recommends_benign, ai_recommends_malicious, couldnt_tell, conflict, undecided"

var runSorts = map[string]bool{"-created": true, "created": true, "time_to_verdict": true, "-time_to_verdict": true}

var labelAssessments = map[string]bool{"benign": true, "threat": true, "disputed": true, "unlabeled": true}

func init() {
	register("investigate_compare",
		"Replay an EDITED template against runs that already finished, offline: each run's recorded facts are re-evaluated "+
			"under the edit, so no operator is called, nothing is gathered and nothing is written, and it costs nothing. Use it BEFORE "+
			"proposing a change to a live template, to see which past runs would end differently (`changed`, the `diff` of outcome, "+
			"deciding rule and actions, and the facts the edit needs that the run never fetched: `not_recorded`, which the replay "+
			"treats as unknown, never as false). Give the edit as `yaml` (the template text) or `template` (a stored template, "+
			"for example a draft) and exactly one selection of runs: `run_id` (one run), `run_ids` (up to 50) or `last_template` "+
			"with `limit` (the newest finished runs of that template, up to 50). With neither yaml nor template the run's own "+
			"template is replayed, which reproduces its outcome. Only runs whose execution is over can be compared. "+
			"The answer holds `summary` (`requested`, `compared`, `failed`, `changed`, `unchanged`, `differs`, `transitions`: how many "+
			"runs move from one outcome to another) and per run `changed` and a compact `comparison` (set `full: true` for the raw one). "+
			"A run that cannot be compared carries an `error` and never fails the call: `unavailable` with `retryable` means the call's "+
			"time ran out, ask again for those runs. A replay shows only what the recorded evidence supports: a fact the edit adds is not "+
			"fetched, so confirm an edit that adds steps with investigate_test_plan. Requires investigation.set and insight.evt.get. "+reviewLoop,
		[]mcp.ToolOption{
			mcp.WithString("yaml", mcp.Description("The edited template source (YAML). Give this or `template`, or neither to replay each run's own template.")),
			mcp.WithString("template", mcp.Description("Name of a stored template to replay (draft or active). Give this or `yaml`.")),
			mcp.WithString("run_id", mcp.Description("Compare one finished run.")),
			mcp.WithArray("run_ids", mcp.WithStringItems(), mcp.Description("Compare these finished runs (1..50, no repeats).")),
			mcp.WithString("last_template", mcp.Description("Compare the newest finished runs of this template (use with `limit`).")),
			mcp.WithNumber("limit", mcp.Description("With last_template: how many runs, 1..50. Default 20.")),
			mcp.WithBoolean("full", mcp.Description("Return every comparison in full (large). Default false: base and variant are reduced to outcome, deciding rule and actions.")),
		}, handleCompare)

	register("investigate_coverage",
		"Which template a start that names no template (an alert from a rule, a case) would run, and which other active templates "+
			"also apply: the engine picks the template whose `applies_to` lists more keys, then more exact values, then the lower name. "+
			"Without arguments it answers one row per example trigger the active templates describe, and flags `tie` rows where two "+
			"templates are as specific as each other (the lower name wins silently: fix it by narrowing one `applies_to`). With "+
			"`category` (detect_cat), `rule`, `severity`, `source` (api, case or dr-rule) or `tags` it answers one row for that trigger: "+
			"`picked`, `reason`, `candidates` (`template`, `keys`, `exact`). `as_active: <template>` previews making that template "+
			"(a draft, or an active one) active: `picked` is who would run once it is, `picked_today` who runs now, so you see which "+
			"alerts a new template takes over BEFORE a person promotes it. Read-only: starts nothing. Requires investigation.get and "+
			"insight.evt.get. "+reviewLoop,
		[]mcp.ToolOption{
			mcp.WithString("category", mcp.Description("The trigger's detection category (an `applies_to.detect_cat` value).")),
			mcp.WithString("rule", mcp.Description("The trigger's D&R rule name.")),
			mcp.WithString("severity", mcp.Description("The trigger's severity.")),
			mcp.WithString("source", mcp.Description("What starts the run: api (default, a person), case or dr-rule.")),
			mcp.WithArray("tags", mcp.WithStringItems(), mcp.Description("The trigger's tags.")),
			mcp.WithString("as_active", mcp.Description("Name of a stored template to judge as if it were active.")),
		}, handleCoverage)

	register("investigate_stats",
		"How the org's templates perform: over a time window and, optionally, one template, the engine's performance report "+
			"(runs, time to verdict, operators, feedback counts), `by_template` (per template: runs, `outcomes`, `states`, median time to "+
			"verdict, AI spend), `deciding_rules` (how many runs each rule decided, `ai_review` for the AI), `missing_reasons` (per template and "+
			"step, how many runs lacked that evidence and why: the usual cause of `couldnt_tell`) and `actions` (per template and action "+
			"class: suggested, approved, denied, expired, auto_executed, withheld, failed, undone, held). Read it to find the template "+
			"worth improving: many `couldnt_tell` with one dominant missing reason means a step or a rule to fix; a rule that decides most "+
			"runs is the one to protect; actions that are often `undone` were wrong. These are counts over the most recent runs "+
			"(`window.truncated` says more matched). Requires investigation.get and insight.evt.get. "+reviewLoop,
		[]mcp.ToolOption{
			mcp.WithString("template", mcp.Description("Only this template's runs.")),
			mcp.WithString("since", mcp.Description("Start of the window (RFC 3339, for example 2026-11-01T00:00:00Z).")),
			mcp.WithString("until", mcp.Description("End of the window (RFC 3339).")),
		}, handleStats)

	register("investigate_list_runs",
		"List the org's investigation runs, newest first, as one compact row each (`run_id`, `state`, `template`, `created`, `verdict` "+
			"{outcome, label, decided_by}, `trigger` with its readable `label`, `case_id`, `sensors`, `message_id`, `budget_exhausted`, "+
			"`actions` count, `time_to_verdict_ms`). Filters combine: `template`, `state` (for example running, completed, failed, "+
			"budget_exhausted, cancelled), `outcome` ("+runOutcomeList+"), `sensor` (a sensor id: every run about that host), `detection_id`, "+
			"`case_id`, `message_id`, `origin_run` (the follow-ups of a run), `needs_person` (true: an action waits for a person), `kind` "+
			"(template or wave), `since`/`until` (RFC 3339). `sort` is -created (default), created, time_to_verdict or -time_to_verdict "+
			"(the slowest first). Page with `cursor` from `next_cursor`; `limit` is 1..200, default 25. Use it to pull the runs behind a number "+
			"of investigate_stats (for example outcome=couldnt_tell for one template) and read them with investigate_get, or to pick run ids "+
			"for investigate_compare. `full: true` returns the raw runs (large). Requires investigation.get and insight.evt.get. "+reviewLoop,
		[]mcp.ToolOption{
			mcp.WithString("template", mcp.Description("Only runs of this template.")),
			mcp.WithString("state", mcp.Description("Only runs in this state (running, completed, failed, budget_exhausted, cancelled, ...).")),
			mcp.WithString("outcome", mcp.Description("Only runs with this outcome: "+runOutcomeList+".")),
			mcp.WithString("sensor", mcp.Description("Only runs about this sensor id (the alert was on it, or an action targets it).")),
			mcp.WithString("detection_id", mcp.Description("Only runs started for this detection.")),
			mcp.WithString("case_id", mcp.Description("Only runs that wrote or attached to this case, or that this case triggered.")),
			mcp.WithString("message_id", mcp.Description("Only runs that investigate this message.")),
			mcp.WithString("origin_run", mcp.Description("Only the late-evidence follow-ups of this run.")),
			mcp.WithBoolean("needs_person", mcp.Description("true: only runs with an action waiting for a person now. false: only the others.")),
			mcp.WithString("kind", mcp.Description("template or wave.")),
			mcp.WithString("since", mcp.Description("Only runs created at or after this time (RFC 3339).")),
			mcp.WithString("until", mcp.Description("Only runs created before this time (RFC 3339).")),
			mcp.WithString("sort", mcp.Description("-created (default), created, time_to_verdict or -time_to_verdict.")),
			mcp.WithNumber("limit", mcp.Description("Runs per page, 1..200. Default 25.")),
			mcp.WithString("cursor", mcp.Description("The `next_cursor` of the previous page. A cursor belongs to its `sort`.")),
			mcp.WithBoolean("full", mcp.Description("Return the raw runs instead of compact rows (large). Default false.")),
		}, handleListRuns)

	register("investigate_get_labels",
		"Read the labels people (or independent integrations) put on a run: `benign`, `threat`, `disputed` or `unlabeled`, with who "+
			"and when, plus the older feedback labels the run carries. A label is a person's explicit statement of what the run should "+
			"have concluded, and the one place the engine's verdict is checked against one: compare it with `verdict.outcome` from "+
			"investigate_get. The engine never decides from a label. Requires investigation.get and insight.evt.get. "+reviewLoop,
		[]mcp.ToolOption{
			mcp.WithString("run_id", mcp.Required(), mcp.Description("The run id.")),
			mcp.WithBoolean("all", mcp.Description("Also include labels that are no longer active. Default false.")),
		}, handleGetLabels)

	register("investigate_submit_label",
		"Label a run: your assessment of what it should have concluded, `benign`, `threat`, `disputed` or `unlabeled` (withdraw). Only "+
			"do this when you have independent evidence (the analyst's closure of the case, a confirmed incident), never to agree with "+
			"the engine's own verdict. The label is attributed to the authenticated caller, nothing in the engine reads it to decide, and "+
			"it is the record a reviewer of the template sees. `revision` is a positive whole number per caller and run: 1 for a first label, "+
			"a higher number to correct it; sending the same revision with different content is refused (`conflict`). The engine's own "+
			"execution keys cannot label. Requires investigation.set and insight.evt.get.",
		[]mcp.ToolOption{
			mcp.WithString("run_id", mcp.Required(), mcp.Description("The run id.")),
			mcp.WithString("assessment", mcp.Required(), mcp.Description("benign, threat, disputed or unlabeled.")),
			mcp.WithNumber("revision", mcp.Required(), mcp.Description("Positive whole number: 1 for the first label of this caller on this run, higher to correct it.")),
		}, handleSubmitLabel)

	register("investigate_cancel",
		"Cancel a run that is still going (running, or decided with actions waiting): its open approvals expire and nothing more is "+
			"gathered or executed. A run that is already over is left exactly as it ended. With `revert_leases: true` it also reverts the "+
			"active leases (the containments) of the run that the caller holds the platform permission for; the others come back in "+
			"`skipped_reverts` and stay active. Cancel is not undo of a case or a label. Requires investigation.set and insight.evt.get.",
		[]mcp.ToolOption{
			mcp.WithString("run_id", mcp.Required(), mcp.Description("The run id.")),
			mcp.WithBoolean("revert_leases", mcp.Description("Also revert the run's active leases. Default false: they stay until they end.")),
		}, handleCancel)
}

func handleCompare(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	src, err := optString(args, "yaml")
	if err != nil {
		return fail(err)
	}
	template, err := optString(args, "template")
	if err != nil {
		return fail(err)
	}
	runID, err := optString(args, "run_id")
	if err != nil {
		return fail(err)
	}
	runIDs, err := stringList(args, "run_ids")
	if err != nil {
		return fail(err)
	}
	last, err := optString(args, "last_template")
	if err != nil {
		return fail(err)
	}
	limit, limitGiven, err := optInt(args, "limit")
	if err != nil {
		return fail(err)
	}
	full, err := optBool(args, "full")
	if err != nil {
		return fail(err)
	}
	if strings.TrimSpace(src) != "" && template != "" {
		return tools.ErrorResult("give yaml or template, not both"), nil
	}
	selections := 0
	for _, given := range []bool{runID != "", len(runIDs) > 0, last != ""} {
		if given {
			selections++
		}
	}
	if selections != 1 {
		return tools.ErrorResult("give exactly one of run_id, run_ids or last_template"), nil
	}
	if limitGiven && last == "" {
		return tools.ErrorResult("limit goes with last_template"), nil
	}
	body := map[string]interface{}{}
	if strings.TrimSpace(src) != "" {
		body["inline"] = src
	}
	if template != "" {
		body["template"] = template
	}
	if runID != "" {
		if err := pathID("run_id", runID); err != nil {
			return fail(err)
		}
		out, err := call(ctx, engineCall{method: http.MethodPost, suffix: "runs/" + url.PathEscape(runID) + "/compare", body: body, timeout: compareTimeout})
		if err != nil {
			return fail(err)
		}
		if !full {
			out = compactComparison(out)
		}
		return tools.SuccessResult(out), nil
	}
	if len(runIDs) > 0 {
		if len(runIDs) > maxCompareRuns {
			return tools.ErrorResultf("run_ids has %d runs, at most %d are allowed", len(runIDs), maxCompareRuns), nil
		}
		seen := map[string]bool{}
		ids := make([]interface{}, 0, len(runIDs))
		for _, id := range runIDs {
			if err := pathID("run_ids", id); err != nil {
				return fail(err)
			}
			if seen[id] {
				return tools.ErrorResultf("run_ids lists %s twice", id), nil
			}
			seen[id] = true
			ids = append(ids, id)
		}
		body["run_ids"] = ids
	} else {
		if !limitGiven {
			limit = 20
		}
		if limit < 1 || limit > maxCompareRuns {
			return tools.ErrorResultf("limit must be between 1 and %d", maxCompareRuns), nil
		}
		body["last"] = map[string]interface{}{"template": last, "limit": limit}
	}
	out, err := call(ctx, engineCall{method: http.MethodPost, suffix: "compare", body: body, timeout: compareTimeout})
	if err != nil {
		return fail(err)
	}
	if !full {
		results := asList(out["results"])
		for i, r := range results {
			if row, ok := r.(map[string]interface{}); ok && row["comparison"] != nil {
				if c, ok := row["comparison"].(map[string]interface{}); ok {
					row["comparison"] = compactComparison(c)
				}
				results[i] = row
			}
		}
	}
	return tools.SuccessResult(out), nil
}

// compareTimeout is what a compare is allowed: the gateway's own budget for a batch is 90 seconds.
var compareTimeout = 110 * time.Second

// compactComparison keeps of a comparison what a reviewer reads: per side the template, the outcome, what decided and the
// actions, then the diff and what the replay could not reuse.
func compactComparison(c map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range c {
		switch k {
		case "base", "variant":
			if side, ok := v.(map[string]interface{}); ok {
				out[k] = pick(side, "template", "outcome", "verdict", "decided", "decided_by", "actions")
				continue
			}
		}
		out[k] = v
	}
	return out
}

func handleCoverage(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	query := url.Values{}
	for _, k := range []string{"category", "rule", "severity", "source", "as_active"} {
		v, err := optString(args, k)
		if err != nil {
			return fail(err)
		}
		if v = strings.TrimSpace(v); v != "" {
			query.Set(k, v)
		}
	}
	if s := query.Get("source"); s != "" && s != "api" && s != "case" && s != "dr-rule" {
		return tools.ErrorResult("source must be api, case or dr-rule"), nil
	}
	tags, err := stringList(args, "tags")
	if err != nil {
		return fail(err)
	}
	if len(tags) > 0 {
		query.Set("tags", strings.Join(tags, ","))
	}
	out, err := call(ctx, engineCall{method: http.MethodGet, suffix: "templates/coverage", query: query})
	if err != nil {
		return fail(err)
	}
	return tools.SuccessResult(out), nil
}

func handleStats(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	query := url.Values{}
	for _, k := range []string{"template", "since", "until"} {
		v, err := optString(args, k)
		if err != nil {
			return fail(err)
		}
		if v = strings.TrimSpace(v); v == "" {
			continue
		}
		if k != "template" {
			if _, err := time.Parse(time.RFC3339, v); err != nil {
				return tools.ErrorResultf("%s must be an RFC 3339 time, for example 2026-11-01T00:00:00Z", k), nil
			}
		}
		query.Set(k, v)
	}
	out, err := call(ctx, engineCall{method: http.MethodGet, suffix: "stats", query: query})
	if err != nil {
		return fail(err)
	}
	return tools.SuccessResult(out), nil
}

// listRunsFilters maps this tool's string filters to the gateway's query names.
var listRunsFilters = []struct{ arg, param string }{
	{"template", "template"}, {"state", "state"}, {"outcome", "outcome"}, {"sensor", "sid"}, {"detection_id", "detection_id"},
	{"case_id", "case_id"}, {"message_id", "message_id"}, {"origin_run", "origin_run"}, {"kind", "kind"},
	{"since", "since"}, {"until", "until"}, {"sort", "sort"}, {"cursor", "cursor"},
}

func handleListRuns(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	query := url.Values{}
	for _, f := range listRunsFilters {
		v, err := optString(args, f.arg)
		if err != nil {
			return fail(err)
		}
		if v = strings.TrimSpace(v); v == "" {
			continue
		}
		switch f.arg {
		case "outcome":
			if !runOutcomes[v] {
				return tools.ErrorResultf("outcome must be one of %s", runOutcomeList), nil
			}
		case "kind":
			if v != "template" && v != "wave" {
				return tools.ErrorResult("kind must be template or wave"), nil
			}
		case "sort":
			if !runSorts[v] {
				return tools.ErrorResult("sort must be -created, created, time_to_verdict or -time_to_verdict"), nil
			}
		case "since", "until":
			if _, err := time.Parse(time.RFC3339, v); err != nil {
				return tools.ErrorResultf("%s must be an RFC 3339 time, for example 2026-11-01T00:00:00Z", f.arg), nil
			}
		}
		query.Set(f.param, v)
	}
	if v, ok := args["needs_person"]; ok && v != nil {
		b, err := optBool(args, "needs_person")
		if err != nil {
			return fail(err)
		}
		query.Set("needs_person", strconv.FormatBool(b))
	}
	limit, given, err := optInt(args, "limit")
	if err != nil {
		return fail(err)
	}
	if !given {
		limit = 25
	}
	if limit < 1 || limit > 200 {
		return tools.ErrorResult("limit must be between 1 and 200"), nil
	}
	query.Set("limit", strconv.Itoa(limit))
	full, err := optBool(args, "full")
	if err != nil {
		return fail(err)
	}
	out, err := call(ctx, engineCall{method: http.MethodGet, suffix: "runs", query: query})
	if err != nil {
		return fail(err)
	}
	if !full {
		rows := asList(out["runs"])
		compact := make([]interface{}, 0, len(rows))
		for _, r := range rows {
			if run, ok := r.(map[string]interface{}); ok {
				compact = append(compact, compactRun(run))
			}
		}
		out["runs"] = compact
	}
	return tools.SuccessResult(out), nil
}

// compactRun is one list row: enough to choose a run to read, never the run's steps or evidence.
func compactRun(run map[string]interface{}) map[string]interface{} {
	row := pick(run, "run_id", "kind", "state", "template", "template_version", "created", "case_id", "sensors", "message_id", "budget_exhausted", "title")
	if verdict, ok := run["verdict"].(map[string]interface{}); ok {
		v := pick(verdict, "outcome", "label", "decided")
		if by, ok := verdict["decided_by"].(map[string]interface{}); ok {
			v["decided_by"] = pick(by, "kind", "rule")
		}
		row["verdict"] = v
	}
	if request, ok := run["request"].(map[string]interface{}); ok {
		if trigger, ok := request["trigger"].(map[string]interface{}); ok {
			row["trigger"] = pick(trigger, "source", "rule", "label", "detection_id", "case_id", "entity_id", "category")
		}
	}
	if actions, ok := run["actions"].([]interface{}); ok {
		row["actions"] = len(actions)
	}
	if usage, ok := run["usage"].(map[string]interface{}); ok {
		if ttv, ok := usage["time_to_verdict_ms"]; ok {
			row["time_to_verdict_ms"] = ttv
		}
	}
	return row
}

func handleGetLabels(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	runID, err := optString(args, "run_id")
	if err != nil {
		return fail(err)
	}
	if err := pathID("run_id", runID); err != nil {
		return fail(err)
	}
	all, err := optBool(args, "all")
	if err != nil {
		return fail(err)
	}
	query := url.Values{}
	if all {
		query.Set("all", "true")
	}
	out, err := call(ctx, engineCall{method: http.MethodGet, suffix: "runs/" + url.PathEscape(runID) + "/labels", query: query})
	if err != nil {
		return fail(err)
	}
	return tools.SuccessResult(out), nil
}

func handleSubmitLabel(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	runID, err := optString(args, "run_id")
	if err != nil {
		return fail(err)
	}
	if err := pathID("run_id", runID); err != nil {
		return fail(err)
	}
	assessment, err := optString(args, "assessment")
	if err != nil {
		return fail(err)
	}
	if !labelAssessments[assessment] {
		return tools.ErrorResult("assessment must be benign, threat, disputed or unlabeled"), nil
	}
	revision, given, err := optInt(args, "revision")
	if err != nil {
		return fail(err)
	}
	if !given || revision < 1 {
		return tools.ErrorResult("revision is required: a positive whole number (1 for a first label, higher to correct it)"), nil
	}
	out, err := call(ctx, engineCall{method: http.MethodPost, suffix: "runs/" + url.PathEscape(runID) + "/labels", body: map[string]interface{}{"assessment": assessment, "revision": revision}})
	if err != nil {
		return fail(err)
	}
	return tools.SuccessResult(out), nil
}

func handleCancel(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	runID, err := optString(args, "run_id")
	if err != nil {
		return fail(err)
	}
	if err := pathID("run_id", runID); err != nil {
		return fail(err)
	}
	revert, err := optBool(args, "revert_leases")
	if err != nil {
		return fail(err)
	}
	body := map[string]interface{}{}
	if revert {
		body["revert_leases"] = true
	}
	out, err := call(ctx, engineCall{method: http.MethodPost, suffix: "runs/" + url.PathEscape(runID) + "/cancel", body: body})
	if err != nil {
		return fail(err)
	}
	return tools.SuccessResult(out), nil
}
