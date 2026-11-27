package investigation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// queueNotAvailable is what an agent reads when the gateway answers 501 not_implemented for a queue call: the
// engine of the org's region has not been updated to the run queue yet.
const queueNotAvailable = "The run queue is not available on this deployment yet."

// queueLoop is what the two queue tools teach: the queue is for seeing why runs wait, and a flush is a person's call.
const queueLoop = "The run queue: an org runs at most `limits.max_parallel_runs` investigations at once (a field of its settings, " +
	"1..2000, default 100); a start above that is never refused, it waits as a run in state `queued` and starts when a slot frees. " +
	"An optional `limits.runs_per_hour` caps the starts of an hour: a start above it is recorded as a terminal `capped` run, and the " +
	"next hour starts again. A `flushed` run is a queued start a person cancelled. "

func init() {
	register("investigate_queue",
		"Read the org's investigation run queue: how many starts wait (`queued`), are being claimed (`claimed`) and run (`running`) against "+
			"`max_parallel_runs`, how long the oldest has waited (`oldest_enqueued_at`, `oldest_wait_ms`), the queued count by urgency "+
			"(`by_band`), by detection rule (`by_rule`) and by template (`by_template`, each row with its `oldest_enqueued_at`), the hour's "+
			"counters (`hour`: `started`, `runs_per_hour`, `flushed`, `capped`, `start_failed`, `resets_at`) and the recent flushes with their "+
			"progress (`flushes`). Every field is always there: with nothing waiting `oldest_enqueued_at` is null, an org with no hourly cap "+
			"has `hour.runs_per_hour` null, and a start no detection rule made (a person's) is a `by_rule` row with no `rule` key. "+
			"The totals are exact and the breakdowns are complete. Use it to see why runs are slow to start and which rule "+
			"or template is filling the queue before you suggest a flush (investigate_flush_queue) or a change of the limits. "+
			"A queued run is also readable with investigate_list_runs (`state`: queued, flushed, capped). Requires investigation.get and insight.evt.get. "+queueLoop,
		nil, handleQueue)

	register("investigate_flush_queue",
		"FLUSH the run queue: CANCEL the queued investigation starts of one detection rule (`rule`), one template (`template`) or the whole "+
			"org (`all: true`); give exactly one of the three. Only starts that are queued and not yet running are cancelled: each becomes a "+
			"terminal `flushed` run that records who flushed it, when and your `note`, and its alert is left not investigated. Running "+
			"investigations are not touched, and a start that arrives after the flush began queues normally. THIS CANNOT BE UNDONE: a "+
			"flushed start is never run later. Call investigate_queue first and flush only what the caller asked for, by the narrowest scope "+
			"that does it (a rule or a template before `all`). Answers `flush_id`, `flushed` (how many so far) and `done` (plus `scope`, `by`, `actor`, `note`, `at`, `cutoff`, `done_at`); a large flush "+
			"finishes in the engine (`done: false`): read `flushes` of investigate_queue for its progress. `replayed: true` means an identical "+
			"flush made in the last minute answered this call: THIS call flushed nothing, `flushed` is that earlier flush's count, and starts queued "+
			"since still wait: never tell the caller you flushed N. The call is sent once and never retried; if it fails without an answer (a dropped connection, a timeout) the flush may still have been applied: read `flushes` of investigate_queue before flushing again. "+
			"Requires investigation.set and insight.evt.get. "+queueLoop,
		[]mcp.ToolOption{
			mcp.WithString("rule", mcp.Description("Flush the queued starts of this detection rule.")),
			mcp.WithString("template", mcp.Description("Flush the queued starts of this template.")),
			mcp.WithBoolean("all", mcp.Description("true: flush every queued start of the org. Never send false: give a rule or a template instead.")),
			mcp.WithString("note", mcp.Description("Why (for example the rule was fixed): kept on every flushed run and in the org's audit log.")),
		}, handleFlushQueue)
}

// queueError says plainly that an engine which does not serve the queue yet does not, and keeps its coded fields.
func queueError(err error) error {
	var engine *engineError
	if errors.As(err, &engine) && engine.Status == http.StatusNotImplemented && engine.Fields["error_code"] == "not_implemented" {
		return &engineError{Status: engine.Status, Message: queueNotAvailable, Fields: engine.Fields}
	}
	return err
}

func handleQueue(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	out, err := call(ctx, engineCall{method: http.MethodGet, suffix: "queue"})
	if err != nil {
		return fail(queueError(err))
	}
	return tools.SuccessResult(out), nil
}

func handleFlushQueue(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	rule, err := optString(args, "rule")
	if err != nil {
		return fail(err)
	}
	template, err := optString(args, "template")
	if err != nil {
		return fail(err)
	}
	all, err := optBool(args, "all")
	if err != nil {
		return fail(err)
	}
	note, err := optString(args, "note")
	if err != nil {
		return fail(err)
	}
	// A flush discards queued work: anything but exactly one well formed scope is refused before any call.
	if _, given := args["all"]; given && args["all"] != nil && !all {
		return fail(errors.New("all must be true or left out: to flush less than everything, give a rule or a template"))
	}
	body := map[string]interface{}{}
	scopes := 0
	for name, value := range map[string]string{"rule": rule, "template": template} {
		if _, given := args[name]; !given || args[name] == nil {
			continue
		}
		if strings.TrimSpace(value) == "" {
			return fail(errors.New(name + " must not be empty"))
		}
		body[name] = value
		scopes++
	}
	if all {
		body["all"] = true
		scopes++
	}
	if scopes != 1 {
		return fail(errors.New("give exactly one of rule, template or all (true)"))
	}
	if note != "" {
		body["note"] = note
	}
	out, err := call(ctx, engineCall{method: http.MethodPost, suffix: "queue/flush", body: body})
	if err != nil {
		if flushMayHaveBeenApplied(err) {
			err = fmt.Errorf("%w; the flush may have been applied: read `flushes` of investigate_queue before flushing again (a second flush has a later cutoff and also cancels starts that arrived after the first)", err)
		}
		return fail(queueError(err))
	}
	return tools.SuccessResult(out), nil
}

// flushMayHaveBeenApplied says whether a failed flush call may have reached the engine: no answer at all (a dropped
// connection, a timeout), or a server-side failure of the gateway or the engine (502, 503, 504 behind a proxy are how a
// timeout usually shows up). A refusal the engine gave (4xx) and the "queue not served yet" 501 applied nothing.
// Errors that occur before anything is sent are over-reported, which is the safe side.
func flushMayHaveBeenApplied(err error) bool {
	var engine *engineError
	if !errors.As(err, &engine) {
		return true
	}
	if engine.Status == http.StatusNotImplemented && engine.Fields["error_code"] == "not_implemented" {
		return false
	}
	return engine.Status >= 500
}
