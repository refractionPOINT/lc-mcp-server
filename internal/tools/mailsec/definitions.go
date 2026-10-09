package mailsec

func paging() []parameter {
	return []parameter{
		field("cursor", "string", "Opaque next_cursor from the prior page. Return verbatim with unchanged filters; empty means the last page."),
		field("limit", "int", "Page size, 1–1000. Continue until next_cursor is empty."),
	}
}
func window() []parameter {
	return []parameter{
		field("since", "string", "Lower bound as RFC3339 or unix seconds."),
		field("until", "string", "Upper bound as RFC3339 or unix seconds."),
	}
}
func messageID() parameter {
	return required("msg_uuid", "string", "Stable message UUID from the index/event, never the provider_message_id, which changes on moves.")
}
func action() parameter {
	return required("action", "string", "Typed action: quarantine_message, trash_message, move_to_spam, restore_message, banner_message, unbanner_message, submit_to_triage or crawl_link. Bulk excludes the last two; server validates support.")
}
func attempt() parameter {
	return field("attempt", "string", "Opaque idempotency attempt. Change only for a deliberate separately recorded second run. For bulk it is part of preview confirmation; for campaign it is not.")
}
func reason() parameter {
	return field("reason", "string", "Audited reason, not part of the preview confirmation token.")
}
func force() parameter {
	return field("force", "bool", "Explicitly override alert_only for this execution. False/absent preserves mode; force is audited. Does not override exclusions or capability checks.")
}
func selection() parameter {
	return required("msg_uuids", "strings", "1–500 distinct message UUIDs. Trimmed, blank entries dropped, deduplicated and sorted for both preview and execute; never silently truncated.")
}

func definitions() []definition {
	defs := []definition{
		{name: "mailsec_get_coverage", method: "GET", path: "coverage", permission: "mailsec.get", readOnly: true,
			description: "Read protected, excluded and broken mailbox coverage, volume, verdicts, backfill and connection health. Default 24-hour volume is cached; explicit windows are rate-limited. volume.truncated means the request exceeds retained history, not complete counts.",
			params:      append(window(), field("window_days", "int", "Whole days back from now, 1–35. Cannot be combined with since/until."))},
		{name: "mailsec_list_messages", method: "GET", path: "messages", permission: "mailsec.get", readOnly: true,
			description: "Read one page of the mail triage queue. Repeated filters OR within a key and AND across keys. Message index retention is at most 35 days, shortened by org policy. Historical searches beyond it use platform LCQL over EMAIL_MESSAGE telemetry, then selected bulk preview; backfill rows do not emit live events.",
			params: append(append([]parameter{
				field("verdict", "strings", "malicious, suspicious, graymail, benign or unknown; repeatable."),
				field("state", "strings", "Message placement/lifecycle states; repeatable."),
				field("direction", "strings", "inbound, outbound or internal; repeatable. Outbound is observation only."),
				field("mailbox", "string", "Exact protected mailbox address."), field("sender_email", "string", "Exact sender address."),
				field("sender_root_domain", "string", "Sender registrable root domain."), field("campaign_id", "string", "Exact campaign ID."),
				field("link_domain", "string", "IOC pivot: registrable root domain linked by the message."), field("attachment_sha256", "string", "IOC pivot: attachment SHA-256."),
				field("user_reported", "bool", "True selects reported mail, false selects unreported; omit for either."), field("min_score", "int", "Minimum score, 0–100."),
				field("lane", "string", "live or backfill. Omit for either. Cannot be combined with mailbox, sender_email or campaign_id."),
				field("q", "string", "Text search, at most 512 characters. Requires since, an exact mailbox/sender/campaign/IOC pivot, or a single verdict."),
			}, window()...), paging()...)},
		{name: "mailsec_get_message", method: "GET", path: "messages/{msg_uuid}", permission: "mailsec.get", readOnly: true, params: []parameter{messageID()},
			description: "Read the message and parsed MDM with rationale, actions and revisions. mdm_source=stored is the judged copy including original enrichments; eml_reparse is a fallback without them. Expired content yields mdm:null with a reason; unknown UUID yields message:null. mail_type describes apparent purpose independently of threat."},
		{name: "mailsec_get_message_eml", method: "GET", path: "messages/{msg_uuid}/eml", permission: "mailsec.get AND mailsec.get.eml", readOnly: true,
			params:      []parameter{messageID(), required("justification", "string", "Required nonblank reason for taking original bytes out of the platform, logged with authenticated identity.")},
			description: "Privileged download of original message bytes. Returns validated eml_b64 and size, preserving arbitrary binary MIME rather than interpreting it as text. Downloads and refusals are audited and rate-limited; do not expose customer mail without authorization."},
		{name: "mailsec_list_similar_messages", method: "GET", path: "messages/{msg_uuid}/similar", permission: "mailsec.get", readOnly: true, params: []parameter{messageID()},
			description: "Read bounded recent clustering-key neighbours, not proven campaign members. Inspect matched_keys, since and body_since. No cursor or limit: use list_messages with campaign_id or time/IOC filters for paginated searches."},
		{name: "mailsec_list_verdict_revisions", method: "GET", path: "messages/{msg_uuid}/revisions", permission: "mailsec.get", readOnly: true,
			params:      []parameter{messageID(), field("limit", "int", "Maximum revisions, 1–1000. No cursor; revisions_truncated marks incomplete history.")},
			description: "Read verdict revision history oldest first: mode/actor (analyst for a user login, api for an API key, older entries may read ai), time, rationale and displaced prior verdict. Inspect revisions_truncated before treating it as an audit export."},
		{name: "mailsec_revise_verdict", method: "POST", path: "messages/{msg_uuid}/verdict", permission: "mailsec.act", destructive: true,
			params:      []parameter{messageID(), required("verdict", "string", "New verdict: malicious, suspicious, graymail, benign or unknown."), required("rationale", "strings", "1–10 nonblank rationale lines, each at most 280 characters."), field("score", "int", "Optional revised score, 0–100.")},
			description: "Record a justified verdict decision and append audited history; who decided is recorded by the server from the credential used (analyst for a user login, api for an API key), never supplied by the caller; this changes what the product says the message is, not its mailbox placement. applied:false means no change. Newly flagged evidence can be retained longer; changing back to benign does not undo that commitment."},
		{name: "mailsec_act_on_message", method: "POST", path: "messages/{msg_uuid}/actions", permission: "mailsec.act", destructive: true,
			params:      []parameter{messageID(), action(), attempt(), reason(), force()},
			description: "Execute a typed single-message action at the provider. alert_only means withheld, not performed; force_required asks for explicit override. Banner text is policy-owned, never caller HTML. submit_to_triage emits an action for an installed AI trigger, not a direct session start. crawl_link can spend analysis budget. Inspect result and audit."},
		{name: "mailsec_list_campaigns", method: "GET", path: "campaigns", permission: "mailsec.get", readOnly: true,
			params:      append(append([]parameter{field("state", "strings", "Repeatable campaign state."), field("verdict", "strings", "Repeatable campaign verdict."), field("min_members", "int", "Minimum members, nonnegative.")}, window()...), paging()...),
			description: "Read one page of campaigns, clusters attributed to the same attack, with state/verdict/member/time filters."},
		{name: "mailsec_get_campaign", method: "GET", path: "campaigns/{campaign_id}", permission: "mailsec.get", readOnly: true, params: []parameter{required("campaign_id", "string", "Campaign ID.")}, description: "Read campaign aggregates, members and clustering keys. Unknown ID returns campaign:null."},
		{name: "mailsec_preview_campaign_action", method: "POST", path: "campaigns/{campaign_id}/actions", permission: "mailsec.act", readOnly: true,
			params:      []parameter{required("campaign_id", "string", "Campaign ID."), action(), attempt(), reason()},
			description: "Preview a campaign sweep without changing mail. Returns exact members, mailbox blast radius and a member-bound confirm token. At most 500 members. Read-only behavior still requires mailsec.act on this route. Pass reviewed token explicitly to act_on_campaign; never generate it yourself."},
		{name: "mailsec_act_on_campaign", method: "POST", path: "campaigns/{campaign_id}/actions", permission: "mailsec.act", destructive: true,
			params:      []parameter{required("campaign_id", "string", "Campaign ID."), action(), required("confirm", "string", "Exact token returned by preview_campaign_action for the reviewed current member set."), attempt(), reason(), force()},
			description: "Execute a previewed campaign sweep. Changed membership invalidates confirmation. Idempotent per member by default; a deliberate new attempt records a second run. Per-member outcomes and alert_only are authoritative; this is not a transactional rollback."},
		{name: "mailsec_preview_bulk_action", method: "POST", path: "actions/bulk/preview", permission: "mailsec.get", readOnly: true,
			params:      []parameter{action(), selection(), attempt()},
			description: "Preview an explicitly selected bulk remediation; creates no job and changes no mail. Inspect every UUID, current placement, missing rows and mailbox blast radius. Token binds normalized IDs, action and attempt. Bulk supports placement/banner actions only, not submit_to_triage or crawl_link."},
		{name: "mailsec_execute_bulk_action", method: "POST", path: "actions/bulk/execute", permission: "mailsec.act", destructive: true,
			params:      []parameter{action(), selection(), required("confirm", "string", "Token from preview_bulk_action; repeat identical action, selection and attempt."), attempt(), reason(), force()},
			description: "Execute the reviewed selection asynchronously. accepted and bulk_id confirm a job; poll get_bulk_action for outcomes. Same request adopts same job; force runs as a distinct audited job. No automatic polling/retry or invented confirmation. Partial failure is not rollback."},
		{name: "mailsec_get_bulk_action", method: "GET", path: "actions/bulk/{bulk_id}", permission: "mailsec.get", readOnly: true, params: []parameter{required("bulk_id", "string", "Bulk job handle from accepted execute.")},
			description: "Read bulk progress and per-message outcomes. States running, complete, interrupted; stalled:true means no worker heartbeat. Resend the same reviewed execute only deliberately to resume stalled work; never claim alert_only, failed or interrupted rows were remediated."},
		{name: "mailsec_get_sender_profile", method: "GET", path: "senders/{key}", permission: "mailsec.get", readOnly: true, params: []parameter{required("key", "string", "Bare email/domain or qualified email:address/domain:domain key.")}, description: "Read this organization's accumulated sender history and prevalence. No profile means no history, not a quiet known sender."},
		{name: "mailsec_get_action", method: "GET", path: "actions/{action_id}", permission: "mailsec.get", readOnly: true, params: []parameter{required("action_id", "string", "Action audit ID.")}, description: "Read an action's recorded decision, identity, provider outcome and request payload, including a raw-EML access justification."},
		{name: "mailsec_analyze", method: "POST", path: "analyze", permission: "mailsec.get", readOnly: true,
			params:      []parameter{field("eml_b64", "string", "Original RFC822 bytes encoded as base64 (preferred)."), field("eml", "string", "Raw RFC822 text alternative; use base64 for binary MIME."), field("org_domains", "strings", "Organization domains for direction/impersonation."), field("direction", "string", "inbound, outbound or internal; omit if unknown.")},
			description: "Parse and judge a submitted EML using currently enabled organization mail rules and policy. Persists nothing and touches no mailbox. This does not evaluate an unsaved candidate rule. Tenant-state enrichments it cannot provide are disclosed; verdict availability is explicit."},
		{name: "mailsec_list_reports", method: "GET", path: "reports", permission: "mailsec.get", readOnly: true, params: append([]parameter{field("status", "strings", "open, triaging or resolved; repeatable."), field("oldest_first", "bool", "True orders by age for an SLA view; omit for newest first.")}, paging()...), description: "Read one page of the abuse-mailbox report queue. original_found:false is a genuine source gap, not a loading state."},
		{name: "mailsec_get_report", method: "GET", path: "reports/{report_id}", permission: "mailsec.get", readOnly: true, params: []parameter{required("report_id", "string", "Report ID.")}, description: "Read one report and its original message linkage. Unknown ID returns report:null."},
		{name: "mailsec_resolve_report", method: "POST", path: "reports/{report_id}/resolve", permission: "mailsec.set", destructive: true, params: []parameter{required("report_id", "string", "Report ID."), required("disposition", "string", "true_positive, false_positive or benign. unknown is not a resolution.")}, description: "Close a user report with an audited disposition. already_resolved reports a raced/already-set outcome; resolving does not itself remediate live mail."},
		{name: "mailsec_reopen_report", method: "POST", path: "reports/{report_id}/reopen", permission: "mailsec.set", params: []parameter{required("report_id", "string", "Report ID.")}, description: "Reopen a report closed too early or contradicted by new evidence. Already-open succeeds and says so."},
		{name: "mailsec_validate_rule", method: "POST", path: "rules/validate", permission: "mailsec.get", readOnly: true, params: []parameter{required("rule", "object", "Single dr-mail rule body: name, fp_notes, phase, detect and other rule fields. Not a Hive wrapper."), field("rule_id", "string", "Ordinary dr-mail record key, no reserved prefix.")}, description: "Validate a candidate mail rule without saving it. Invalid rules return valid:false and reasons; inspect those even on HTTP success. Save accepted records explicitly through generic Hive tools."},
		{name: "mailsec_backtest_rule", method: "POST", path: "rules/backtest", permission: "mailsec.get", readOnly: true, params: append([]parameter{required("rule", "object", "Candidate pre_verdict dr-mail body; post_verdict is refused."), field("rule_id", "string", "Candidate record key.")}, window()...), description: "Replay a candidate over retained indexed/raw mail, not full telemetry history. Original runtime enrichments are not reconstructed; mail_type preserves recorded purpose or privately classifies legacy rows. Inspect coverage_note, skipped_no_raw, skipped_unparse and truncated. precision:null means no analyst-labelled matches. Rate-limited expensive read."},
		{name: "mailsec_test_connection", method: "POST", path: "connections/{record}/test", permission: "mailsec.act", params: []parameter{required("record", "string", "SAVED mailsec_provider record name, never inline credentials."), field("include_watch", "bool", "Opt in to establishing/replacing a real Workspace push watch (side effect, idempotent, provider-expiring).")}, description: "Probe credential, scopes, real directory access and Workspace notification configuration; every check names remediation. Optional failure can leave ok:true. Default performs provider probes without establishing a watch; annotation is conservatively writable because include_watch may change provider state."},
		{name: "mailsec_get_onboarding", method: "GET", path: "onboarding", permission: "mailsec.get", readOnly: true, params: []parameter{field("provider", "string", "m365 or gworkspace (default)."), field("project_id", "string", "Customer's Google Cloud project for Workspace setup commands."), field("sa_email", "string", "Customer's service-account email for setup commands."), field("topic", "string", "Workspace Pub/Sub topic name override."), field("subscription", "string", "Workspace pull subscription name override.")}, description: "Fetch current provider scopes and setup steps. Supplying customer Workspace values fills setup commands; otherwise placeholders remain. Creates no resources. Workspace requires domain-wide delegation plus topic/pull subscription in the service account project; no polling fallback."},
		{name: "mailsec_prepare_tenant_purge", method: "GET", path: "tenant", permission: "mailsec.act AND billing.ctrl AND user.ctrl", readOnly: true, description: "Prepare permanent deletion of all Email Security data and connection/policy configuration. Returns warning and single-use confirmation token valid five minutes; deletes nothing. Owner authority required even for preview. Delivered provider mail remains untouched."},
		{name: "mailsec_purge_tenant", method: "DELETE", path: "tenant", permission: "mailsec.act AND billing.ctrl AND user.ctrl", destructive: true, params: []parameter{required("confirmation", "string", "Single-use token from prepare_tenant_purge, valid five minutes. Supply only after explicit authorization to destroy all tenant mailsec evidence."), field("reason", "string", "Optional audited reason, at most 1024 characters.")}, description: "IRREVERSIBLY delete all Email Security records, stored raw/parsed content and connection/policy config, stopping provider notifications. Never automatically preview, confirm or retry. complete:false is an incomplete purge with counts. A timeout does not mean failure: accepted purge can continue on backend; inspect audit before retrying with a fresh token."},
	}
	return defs
}
