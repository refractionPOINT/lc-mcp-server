package investigation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// The environment an AI session started by the Investigation Engine has: the run, the step's request and a one-time
// answer token.
const (
	envRunID       = "LC_IE_RUN_ID"
	envRequestID   = "LC_IE_REQUEST_ID"
	envAnswerToken = "LC_IE_ANSWER_TOKEN"
)

// minTokenLength refuses a token that cannot be the engine's (a 256-bit secret): scrubbing a short or common string
// would rewrite the result the agent reads.
const minTokenLength = 16

// redacted replaces the answer token wherever it would otherwise be shown.
const redacted = "[redacted]"

// The engine bounds an answer (64 KiB) and refuses a bigger one with invalid_answer: the tool does not duplicate the check.

// answerMeanings say what each refusal of an answer means, by the engine's error_code. An agent acts on the code.
var answerMeanings = map[string]string{
	"invalid_answer":   "The answer does not match what the step asked for (400). Nothing was recorded: fix the fields the message names (also in `fields` when the API relays them) and call investigate_answer again before the deadline.",
	"forbidden":        "The answer token does not match this request (403). Use the token of the session the engine started for this run and request.",
	"not_found":        "There is no such request on this run (404). Check run_id and request_id.",
	"already_answered": "This request already has an answer (409); a second answer is never taken. Do not retry.",
	"deadline_passed":  "The request's deadline passed (409): the step already counted as unknown (timeout). Too late to answer; do not retry.",
	"not_waiting":      "The run no longer waits for this answer (409): the session ended, the run was cancelled or it is over. Too late to answer; do not retry.",
	"not_implemented":  "The engine of this deployment does not take AI agent answers yet (501).",
}

func init() {
	register("investigate_answer",
		"Answer the `ai_agent` step of an Investigation Engine run that started THIS AI session: the engine started the session "+
			"for one step of a template (or a hand-off), waits for its answer, and goes on with it. `answer` is a JSON object with "+
			"the fields the step asked for (its `returns`) and a short `rationale`. `run_id`, `request_id` and `token` default from "+
			"the session's environment (LC_IE_RUN_ID, LC_IE_REQUEST_ID, LC_IE_ANSWER_TOKEN) when this server runs inside the session "+
			"(stdio); a server that does not run inside it needs all three as arguments. The token is a one-time secret: never put it in "+
			"an answer, a note, a case or a message; this tool never repeats it. A valid answer is taken once. Refusals carry "+
			"`error_code`: `invalid_answer` (400, the message names each field and why, and `fields` does when the API relays it; nothing was "+
			"recorded, fix and call again before the deadline), `forbidden` (403, wrong token), `not_found` (404), `already_answered`, `deadline_passed` or `not_waiting` "+
			"(409, too late: do not retry), `not_implemented` (501). The call is sent once. Requires investigation.get.",
		[]mcp.ToolOption{
			mcp.WithObject("answer", mcp.Required(), mcp.Description("The answer: the step's declared fields and a short rationale.")),
			mcp.WithString("run_id", mcp.Description("The run. Default: $LC_IE_RUN_ID when the server runs inside the session.")),
			mcp.WithString("request_id", mcp.Description("The step's request. Default: $LC_IE_REQUEST_ID when the server runs inside the session.")),
			mcp.WithString("token", mcp.Description("The one-time answer token. Default: $LC_IE_ANSWER_TOKEN when the server runs inside the session. Prefer the default: never copy it into text.")),
		}, handleAnswer)
}

// sessionEnv reads one variable of the session's environment, but only where this process IS the session's: the
// single-user stdio server. A shared HTTP server's own environment belongs to the operator, never to a caller.
func sessionEnv(ctx context.Context, name string) string {
	if !auth.HasLocalFilesystemAccess(ctx) {
		return ""
	}
	return strings.TrimSpace(os.Getenv(name))
}

// sessionRunID is the run whose AI session this server runs in, or "" (also for every HTTP request).
func sessionRunID(ctx context.Context) string { return sessionEnv(ctx, envRunID) }

// scrub keeps the token out of anything shown to the agent or logged.
func scrub(s, token string) string {
	if token == "" {
		return s
	}
	s = strings.ReplaceAll(s, token, redacted)
	// A JSON body used as a message carries the token in its escaped form (quotes, angle brackets, backslashes).
	if encoded, err := json.Marshal(token); err == nil {
		if inner := strings.Trim(string(encoded), `"`); inner != token {
			s = strings.ReplaceAll(s, inner, redacted)
		}
	}
	return s
}

func handleAnswer(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	answer, err := optObject(args, "answer")
	if err != nil {
		return fail(err)
	}
	if answer == nil {
		return tools.ErrorResult("answer is required: an object with the step's declared fields and a rationale"), nil
	}
	values := map[string]string{}
	for _, f := range []struct{ arg, env string }{{"run_id", envRunID}, {"request_id", envRequestID}, {"token", envAnswerToken}} {
		v, err := optString(args, f.arg)
		if err != nil {
			return failScrubbed(err, "")
		}
		if strings.TrimSpace(v) == "" {
			v = sessionEnv(ctx, f.env)
		}
		values[f.arg] = strings.TrimSpace(v)
	}
	token := values["token"]
	for _, name := range []string{"run_id", "request_id", "token"} {
		if values[name] == "" {
			return tools.ErrorResult(name + " is required: give it, or run this server inside the AI session the engine started (it reads $" +
				map[string]string{"run_id": envRunID, "request_id": envRequestID, "token": envAnswerToken}[name] + ")"), nil
		}
	}
	if len(token) < minTokenLength {
		return tools.ErrorResult("token is too short to be an answer token: give the value of $" + envAnswerToken + " unchanged"), nil
	}
	if containsString(answer, token) {
		// The answer is stored with the run and read by everyone who reads the run: the token never belongs in it.
		return tools.ErrorResult("the answer contains the answer token: remove it. The token is a secret and never part of an answer"), nil
	}
	runID, requestID := values["run_id"], values["request_id"]
	if !validID(runID) || !validID(requestID) {
		return tools.ErrorResult("run_id and request_id must be ids: letters, digits and . _ : - (at most 128 characters)"), nil
	}
	out, err := call(ctx, engineCall{
		method: http.MethodPost,
		suffix: "runs/" + url.PathEscape(runID) + "/agent-answers/" + url.PathEscape(requestID),
		body:   map[string]interface{}{"token": token, "answer": answer},
	})
	if err != nil {
		return failScrubbed(answerError(err, token), token)
	}
	// The answer to a valid call has no token in it; scrub anyway, so a future field can never leak it.
	return tools.SuccessResult(scrubValue(out, token).(map[string]interface{})), nil
}

func validID(s string) bool {
	if s == "" || len(s) > 128 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == ':', r == '-':
		default:
			return false
		}
	}
	return true
}

// answerError adds what the engine's code means to an engine refusal.
func answerError(err error, token string) error {
	var engine *engineError
	if !errors.As(err, &engine) {
		return err
	}
	// Scrubbed before the fields are JSON-encoded, for every refusal: an encoded token (escaped quotes, angle brackets)
	// would not match afterwards.
	fields := map[string]interface{}{}
	for k, v := range engine.Fields {
		fields[k] = scrubValue(v, token)
	}
	message := scrub(engine.Message, token)
	code, _ := engine.Fields["error_code"].(string)
	meaning, ok := answerMeanings[code]
	if !ok {
		if engine.Status == http.StatusForbidden && code == "" {
			meaning = "The API refused the answer (403): see the message. Usually the caller lacks investigation.get; an API key also needs a key id."
		} else {
			return &engineError{Status: engine.Status, Message: message, Fields: fields}
		}
	}
	return &engineError{Status: engine.Status, Message: message + " " + meaning, Fields: fields}
}

// failScrubbed is fail with the token removed from the text.
func failScrubbed(err error, token string) (*mcp.CallToolResult, error) {
	res, e := fail(err)
	if res != nil && token != "" {
		for i, c := range res.Content {
			if tc, ok := c.(mcp.TextContent); ok {
				tc.Text = scrub(tc.Text, token)
				res.Content[i] = tc
			}
		}
	}
	return res, e
}

// containsString reports whether any string of a decoded JSON value (a key or a value) holds s.
func containsString(v interface{}, s string) bool {
	switch x := v.(type) {
	case string:
		return strings.Contains(x, s)
	case map[string]interface{}:
		for k, e := range x {
			if strings.Contains(k, s) || containsString(e, s) {
				return true
			}
		}
	case []interface{}:
		for _, e := range x {
			if containsString(e, s) {
				return true
			}
		}
	}
	return false
}

// scrubValue removes the token from every string of a decoded JSON value.
func scrubValue(v interface{}, token string) interface{} {
	switch x := v.(type) {
	case string:
		return scrub(x, token)
	case map[string]interface{}:
		for k, e := range x {
			x[k] = scrubValue(e, token)
		}
		return x
	case []interface{}:
		for i, e := range x {
			x[i] = scrubValue(e, token)
		}
		return x
	}
	return v
}
