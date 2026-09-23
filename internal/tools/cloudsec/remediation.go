package cloudsec

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// Code Security remediation runs.
//
// Reads and create are ordinary tools: a created run never acts before a human approves
// it, and the gateway resolves every target from the finding.
//
// Approving, rejecting and cancelling go through ONE tool with an explicit two-step
// confirmation. The first call sends nothing: it reads the run and returns what the
// decision would apply to (action, targets, old digests, expected state, deadline,
// generation, target digest) plus a confirmation token. Only a second call carrying that
// token sends the decision. The token is an HMAC over the organization, run, decision,
// generation and target digest with a key the caller never sees, and it expires. It cannot
// be computed without the review call, stops matching when the run or its targets change,
// and does not carry over to another decision. The gateway then fences the decision on
// the same generation and digest and requires cloudsec.respond, which cloudsec.set does not
// imply: this tool adds a confirmation step, it never adds authority.

var runIDRe = regexp.MustCompile(`^rem_[0-9a-f]{32}$`)

// confirmationTTL bounds how long a reviewed decision stays confirmable.
const confirmationTTL = 5 * time.Minute

// decidableStates mirrors the server: which states each decision applies to.
var decidableStates = map[string][]string{
	"approve": {"awaiting_approval"},
	"reject":  {"awaiting_approval"},
	"cancel":  {"requested", "planning", "awaiting_approval", "executing"},
}

// confirmationKey signs confirmation tokens. With REDIS_ENCRYPTION_KEY configured (the
// shared key of an HTTP deployment) every replica derives the same key, so a token
// minted by one replica verifies on another. Otherwise the key is random per process: a
// token then only verifies on the process that minted it, which fails closed.
var confirmationKey = func() []byte {
	if shared := os.Getenv("REDIS_ENCRYPTION_KEY"); shared != "" {
		mac := hmac.New(sha256.New, []byte(shared))
		mac.Write([]byte("lc-mcp cloudsec remediation decision confirmation v1"))
		return mac.Sum(nil)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("cloudsec: no randomness for the confirmation key: " + err.Error())
	}
	return key
}()

// nowFunc is the clock, replaceable in tests.
var nowFunc = time.Now

func confirmationMAC(oid, runID, decision string, generation int64, scopeDigest string, expires int64) string {
	mac := hmac.New(sha256.New, confirmationKey)
	fmt.Fprintf(mac, "%s|%s|%s|%d|%s|%d", oid, runID, decision, generation, scopeDigest, expires)
	return hex.EncodeToString(mac.Sum(nil))
}

func mintConfirmation(oid, runID, decision string, generation int64, scopeDigest string) string {
	expires := nowFunc().Add(confirmationTTL).Unix()
	return strconv.FormatInt(expires, 10) + "." + confirmationMAC(oid, runID, decision, generation, scopeDigest, expires)
}

// checkConfirmation verifies a token against the run AS IT IS NOW.
func checkConfirmation(token, oid, runID, decision string, generation int64, scopeDigest string) error {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return fmt.Errorf("the confirmation token is malformed; review the run again")
	}
	expires, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return fmt.Errorf("the confirmation token is malformed; review the run again")
	}
	if nowFunc().Unix() > expires {
		return fmt.Errorf("the confirmation expired; review the run again")
	}
	want := confirmationMAC(oid, runID, decision, generation, scopeDigest, expires)
	if !hmac.Equal([]byte(parts[1]), []byte(want)) {
		return fmt.Errorf("the confirmation does not match this run and decision as they are now (the run or its targets changed, the token is for another run or decision, or it was minted by another server); review the run again")
	}
	return nil
}

// remediationRemote is the gateway, behind an interface so the decision flow is tested
// without a network.
type remediationRemote interface {
	oid() string
	getRun(ctx context.Context, runID string) (map[string]interface{}, error)
	decide(ctx context.Context, runID, decision string, body map[string]interface{}) (map[string]interface{}, error)
}

type gatewayRemote struct{ org *lc.Organization }

func (g gatewayRemote) oid() string { return g.org.GetOID() }

func (g gatewayRemote) getRun(ctx context.Context, runID string) (map[string]interface{}, error) {
	return decodeRaw(rawRequest(ctx, g.org, http.MethodGet, orgPath(g.org, "remediations/"+runID), nil, nil, defaultTimeout, maxJSONResponseBytes))
}

func (g gatewayRemote) decide(ctx context.Context, runID, decision string, body map[string]interface{}) (map[string]interface{}, error) {
	return postJSON(ctx, g.org, orgPath(g.org, "remediations/"+runID+"/"+decision), body, defaultTimeout)
}

var newRemediationRemote = func(ctx context.Context) (remediationRemote, error) {
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return nil, err
	}
	return gatewayRemote{org: org}, nil
}

func decodeRaw(body []byte, err error) (map[string]interface{}, error) {
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxJSONResponseBytes {
		return nil, fmt.Errorf("response exceeded %d bytes", maxJSONResponseBytes)
	}
	out := map[string]interface{}{}
	if len(strings.TrimSpace(string(body))) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w", err)
	}
	return out, nil
}

// rawJSON is a JSON read for tools that need a url.Values query.
func rawJSON(ctx context.Context, org *lc.Organization, method, suffix string, query url.Values) (*mcp.CallToolResult, error) {
	path := orgPath(org, suffix)
	resp, err := decodeRaw(rawRequest(ctx, org, method, path, query, nil, defaultTimeout, maxJSONResponseBytes))
	if err != nil {
		return tools.ErrorResultf("cloudsec request to %s failed: %s", path, describeErr(err)), nil
	}
	return tools.SuccessResult(resp), nil
}

// decideRemediation is the two-step decision flow. It returns the tool result.
func decideRemediation(ctx context.Context, remote remediationRemote, runID, decision, confirmation string) *mcp.CallToolResult {
	if !runIDRe.MatchString(runID) {
		return tools.ErrorResult("run_id must be rem_ followed by 32 lowercase hex")
	}
	states, ok := decidableStates[decision]
	if !ok {
		return tools.ErrorResult("decision must be approve, reject or cancel")
	}
	detail, err := remote.getRun(ctx, runID)
	if err != nil {
		return tools.ErrorResultf("could not read the run: %s", describeErr(err))
	}
	result, _ := detail["result"].(map[string]interface{})
	run, _ := result["run"].(map[string]interface{})
	if run == nil {
		return tools.ErrorResult("the gateway returned no run")
	}
	state, _ := run["state"].(string)
	decidable := false
	for _, s := range states {
		decidable = decidable || s == state
	}
	if !decidable {
		return tools.ErrorResultf("run %s is %q; it cannot be %s now", runID, state, strings.TrimSuffix(decision, "e")+"ed")
	}
	genFloat, gok := run["generation"].(float64)
	generation := int64(genFloat)
	scopeDigest, _ := run["scope_digest"].(string)
	if !gok || float64(generation) != genFloat || generation < 0 || (decision == "approve" && scopeDigest == "") {
		return tools.ErrorResult("the run does not carry a reviewable generation and target digest; it cannot be decided from here")
	}

	if confirmation == "" {
		scope, _ := run["scope"].(map[string]interface{})
		review := map[string]interface{}{
			"decision":     decision,
			"run_id":       runID,
			"finding_id":   run["finding_id"],
			"action":       run["action"],
			"state":        state,
			"targets":      scope["targets"],
			"old_digests":  scope["old_digests"],
			"truncated":    scope["truncated"],
			"expected":     run["expected"],
			"deadline_at":  run["deadline_at"],
			"generation":   generation,
			"scope_digest": scopeDigest,
		}
		return tools.SuccessResult(map[string]interface{}{
			"sent":               false,
			"review":             review,
			"confirmation":       mintConfirmation(remote.oid(), runID, decision, generation, scopeDigest),
			"expires_in_seconds": int(confirmationTTL.Seconds()),
			"next": "NOTHING WAS SENT. Show this review to the user and ask them to explicitly confirm the " + decision +
				". Only if they do, call this tool again with the same run_id and decision and this confirmation. " +
				"The confirmation stops matching if the run or its targets change. The gateway also requires the user's cloudsec.respond permission.",
		})
	}

	if err := checkConfirmation(confirmation, remote.oid(), runID, decision, generation, scopeDigest); err != nil {
		return tools.ErrorResult(err.Error())
	}
	body := map[string]interface{}{"generation": generation}
	if decision == "approve" {
		body["scope_digest"] = scopeDigest
	}
	resp, err := remote.decide(ctx, runID, decision, body)
	if err != nil {
		return tools.ErrorResultf("the %s was refused: %s", decision, describeErr(err))
	}
	resp["sent"] = true
	return tools.SuccessResult(resp)
}

func registerRemediation() {
	register(toolDef{
		name:        "cloudsec_list_remediations",
		description: "List Code Security remediation runs, newest first, optionally for one finding. Each run carries its state (requested, awaiting_approval, executing, monitoring, verified, persists, regressed, failed, expired, rejected, cancelled). Only 'verified' means the fix was observed on every in-scope deployment; a merged pull request is progress, not a fix.",
		readOnly:    true,
		params: []mcp.ToolOption{
			mcp.WithString("finding_id", mcp.Description("Only runs for this finding (fnd_ followed by 32 lowercase hex)")),
			mcp.WithString("cursor", mcp.Description("Opaque next-page cursor from result.next_cursor")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			query := url.Values{}
			if id := argString(args, "finding_id"); id != "" {
				if !findingIDRe.MatchString(id) {
					return tools.ErrorResult("finding_id must be fnd_ followed by 32 lowercase hex"), nil
				}
				query.Set("finding_id", id)
			}
			if c := argString(args, "cursor"); c != "" {
				if len(c) > 1024 || strings.ContainsAny(c, "\r\n\x00") {
					return tools.ErrorResult("invalid cursor"), nil
				}
				query.Set("cursor", c)
			}
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}
			return rawJSON(ctx, org, http.MethodGet, "remediations", query)
		},
	})
	register(toolDef{
		name:        "cloudsec_get_remediation",
		description: "Get one Code Security remediation run with its steps (transitions, dispatches, callbacks, verification observations and their reasons).",
		readOnly:    true,
		params: []mcp.ToolOption{
			mcp.WithString("run_id", mcp.Required(), mcp.Description("The run id: rem_ followed by 32 lowercase hex")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			id := argString(args, "run_id")
			if !runIDRe.MatchString(id) {
				return tools.ErrorResult("run_id must be rem_ followed by 32 lowercase hex"), nil
			}
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}
			return rawJSON(ctx, org, http.MethodGet, "remediations/"+id, nil)
		},
	})
	register(toolDef{
		name: "cloudsec_create_remediation",
		description: "Request a Code Security remediation run for a finding. The run does NOTHING until a human approves it; the server resolves every target from the finding, so no target can be named here. " +
			"Requires the user's cloudsec.respond permission (cloudsec.set does not imply it) and the remediation feature. Ask the user before requesting one.",
		destructive: false,
		params: []mcp.ToolOption{
			mcp.WithString("finding_id", mcp.Required(), mcp.Description("The finding to remediate (fnd_ followed by 32 lowercase hex)")),
			mcp.WithString("action", mcp.Required(), mcp.Description("Remediation action token, e.g. open_fix_pr")),
			mcp.WithString("idempotency_key", mcp.Description("Replay-safe key (letters, digits, . _ : -, at most 128); a repeat returns the same run. Generated when omitted")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			id, action, key := argString(args, "finding_id"), argString(args, "action"), argString(args, "idempotency_key")
			if !findingIDRe.MatchString(id) {
				return tools.ErrorResult("finding_id must be fnd_ followed by 32 lowercase hex"), nil
			}
			if action == "" || len(action) > 64 || strings.ContainsAny(action, " \r\n\x00/") {
				return tools.ErrorResult("action is required"), nil
			}
			if key == "" {
				b := make([]byte, 16)
				if _, err := rand.Read(b); err != nil {
					return tools.ErrorResult("could not generate an idempotency key"), nil
				}
				key = "mcp-" + hex.EncodeToString(b)
			}
			return callPOST(ctx, "findings/"+id+"/remediations", map[string]interface{}{"action": action, "idempotency_key": key}, defaultTimeout)
		},
	})
	register(toolDef{
		name: "cloudsec_decide_remediation",
		description: "Approve, reject or cancel a Code Security remediation run. TWO STEPS, ALWAYS. " +
			"Call it first WITHOUT 'confirmation': nothing is sent; it returns what the decision would apply to (action, targets, old digests, deadline, generation, target digest) and a confirmation token. " +
			"Show that review to the user and ask them to explicitly confirm. Only if they do, call again with the same run_id, decision and the token. " +
			"The token expires after 5 minutes and stops matching if the run or its targets change. The gateway requires the user's cloudsec.respond permission and refuses a stale decision.",
		destructive: true,
		params: []mcp.ToolOption{
			mcp.WithString("run_id", mcp.Required(), mcp.Description("The run id: rem_ followed by 32 lowercase hex")),
			mcp.WithString("decision", mcp.Required(), mcp.Description("approve | reject | cancel")),
			mcp.WithString("confirmation", mcp.Description("The token from the review call, sent only after the user explicitly confirmed")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			remote, err := newRemediationRemote(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}
			return decideRemediation(ctx, remote, argString(args, "run_id"), argString(args, "decision"), argString(args, "confirmation")), nil
		},
	})
}
