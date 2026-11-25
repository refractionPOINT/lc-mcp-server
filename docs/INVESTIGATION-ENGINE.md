# Investigation Engine tools

The `investigation_engine` profile (and the read-only `investigation_engine_readonly`) exposes the
Investigation Engine through the LimaCharlie gateway routes `/v1/investigate/{oid}/...`. A plan template is a
YAML document that says what to gather for an alert (`gather`), which rules decide it (`rules`: `escalate` and
`close`, each with an id and a sentence for the case), optionally one AI review for what rules cannot decide
(`ai_review`), and what to do about it (`act`, `case`). An `act` entry says which rules fire it with `on_rules: [<rule id> | ai_review]`; the key is `on_rules`, not `on`, because YAML 1.1 parsers read a bare `on:` as the boolean `true`. A `gather` step says what the case shows of it with `record:` (one entry or a list): `kind: entity` (with `entity_type`, `indicator`, `malicious_when`, `benign_when`; an unknown never asserts a verdict; `each` with `item_key`, `outcome_key`, `outcome_map`, `absence` and `outcome_notes` writes one entity per list element), `telemetry`, or `artifact` (`ref` holds ids only). A `use:` step takes none. The engine adds, with no template, the telemetry of the steps a rule or the review reads, an `entity.get` step's entity and the message artifact of each message step. There is no scoring: a run ends with an outcome and the rule
(or the AI) behind it. Writing one by hand is long work, so the tools are built for an AI agent to author them, with
a person promoting the result.

> **Off by default.** The `investigate_*` tools and both profiles exist only when the server is started with
> `INVESTIGATION_ENGINE_ENABLED=true` (or `1`). Without it they are not registered: they are absent from `tools/list`
> on every endpoint including `all`, `/mcp/investigation_engine` is not a route, `MCP_PROFILE=investigation_engine` is
> an invalid profile, and naming one in `X-MCP-Tools` is an invalid tool name. No other profile changes. The variable
> is read once at startup.

| Tool | Does | Permissions |
|------|------|-------------|
| `investigate_authoring_kit` | One call: template schema, authoring guide, the org's typed operator catalog, the default template library, effective policy, every validation code. `sections` (schema, guide, operators, examples, policy, codes, packs, library) re-reads part of it | `investigation.get`, `insight.evt.get` |
| `investigate_operators` | The operator catalog, with `filter` and `brief` | same |
| `investigate_validate_plan` | Type-checks a template: structure, operators, references, expressions, budgets | `investigation.get` |
| `investigate_test_plan` | Dry run on real past alerts (detections, cases, or the newest alerts of a category). Waits and polls, returns per alert which rule decided or what the AI recommended, how each agrees with the analyst, what was missing, and costs. Nothing is written | `investigation.set`, `insight.evt.get` |
| `investigate_save_plan` | Saves the template to the `investigation_plan` hive, **always as a draft** | `investigation_plan.get/set`, `investigation.get`, `insight.evt.get` |
| `investigate_list_templates` | The org's templates (its `investigation_plan` records): name, status (draft/active). `stored: true` also lists records that do not load (with `load_error`); `validation: true` adds each template's validation summary | `investigation.get`, `insight.evt.get` |
| `investigate_start`, `investigate_get` | Start a run, read its outcome, steps (with each step's narrative), events or case | `investigation.set` / `.get`, `insight.evt.get` |
| `investigate_delete` | Delete a run by `run_id` (destructive); not offered in the read-only profile | `investigation.set`, `insight.evt.get` |
| `investigate_wave` | Run a batch of questions (operators or fact packs) in parallel and get compact typed answers, stopping as soon as a `stop_when` expression is true. Also a way to see what an operator returns before writing a plan around it | `investigation.set`, `insight.evt.get` |
| `investigate_packs` | The fact packs (named bundles of questions: host context, process tree, hash spread, the org's machines and owners, ...) as a compact index that is enough to write the waves: parameters with types, exports with type, reference form and a short meaning. `name` returns one pack in full | `investigation.get`, `insight.evt.get` |
| `investigate_compare` | Replays an edited template (`yaml`, or a stored `template`) against one finished run, a list of run ids (up to 50) or the newest finished runs of a template (`last_template`, `limit`), offline: recorded facts only, no operator call, nothing written. Returns per run whether the outcome `changed`, the `diff` (outcome, deciding rule, actions), what the edit needs that the run never fetched (`not_recorded`) and a `summary` with the outcome `transitions`. Read-only profile too | `investigation.set`, `insight.evt.get` |
| `investigate_stats` | How templates perform over a window: per template outcomes and states, median time to verdict and AI spend (`by_template`), which rule decided how many runs (`deciding_rules`), which evidence was missing and why (`missing_reasons`) and the action counters (suggested, approved, undone, ...). `template`, `since`, `until` | `investigation.get`, `insight.evt.get` |
| `investigate_list_runs` | The runs behind a number, as compact rows: filters `template`, `state`, `outcome`, `sensor`, `detection_id`, `case_id`, `message_id`, `origin_run`, `needs_person`, `kind`, a time window (`since`, `until`), `sort` and paging (`limit`, `cursor`). `full` returns raw runs | same |
| `investigate_coverage` | Which template a start with no named template runs for a trigger (`category`, `rule`, `severity`, `source`, `tags`), the other templates that apply, and `tie` rows where two active templates are equally specific. `as_active: <template>` previews making a draft active (`picked` vs `picked_today`) | same |
| `investigate_get_labels` | The labels people put on a run (`benign`, `threat`, `disputed`, `unlabeled`) | same |
| `investigate_submit_label` | Labels a run (`assessment`, a positive `revision`); only with independent evidence. Not offered in the read-only profile | `investigation.set`, `insight.evt.get` |
| `investigate_cancel` | Cancels a run that is still going; `revert_leases` also reverts the leases the caller may revert. Not offered in the read-only profile | `investigation.set`, `insight.evt.get` |

## How a run ends

A run ends with one `verdict.outcome`:

| Outcome | Meaning | `label` |
|---|---|---|
| `closed_by_rule`, `escalated_by_rule` | a rule decided; `verdict.decided_by` holds the rule id and its sentence | false_positive, true_positive |
| `closed_by_ai`, `escalated_by_ai` | the AI review (or an AI-assisted rule) decided, because the org policy's `ai_may_decide` allows it for the template | false_positive, true_positive |
| `ai_recommends_benign`, `ai_recommends_malicious` | the AI recommends; a person acts on it (`verdict.recommendation`: label, `self_rated_confidence`, rationale, citations) | inconclusive |
| `couldnt_tell` | nothing decided; `verdict.missing` says which steps could not be established, why and who needed them | inconclusive |
| `conflict` | a rule on each side held | inconclusive |

`self_rated_confidence` is the AI's own rating: it is shown, never used. `investigate_get` with `view: steps`
returns each step's `narrative` (`why` it ran, what it `found`, what it was `used` for) and the policy's
`ai_may_decide` position (`off`, `escalate` or `close_and_escalate`). Whether the AI may decide is the org's
`investigation_policy` (`ai_may_decide`), set by a person; no tool here changes it. A template's `gather` steps may
carry `only_if`, a condition that skips a step (reading as unknown) unless it holds.

## Templates and the default library

An org's templates are exactly its `investigation_plan` Hive records; the engine adds none on its own. The engine
ships a default library of ready-made templates, one per kind of alert (for example `mailsec-message`,
`endpoint-detection`, `suspicious-process`, `appcontrol`, `identity-sign-in`, `saas-admin-action`,
`cloud-exposure-finding`, `code-finding`, `phishing-campaign`). It is content, not part of any org: read it with
`investigate_authoring_kit` (`sections: ["library"]`) and install a template by writing it as an
`investigation_plan/<name>` record with the Hive tools. Fact packs (`use:`) are the engine's built-in standard
library, like operators; they are not templates.

## The authoring loop

1. `investigate_authoring_kit` once.
2. Look at the org's real data (`get_detection`, `run_lcql_query`, `investigate_wave`).
3. Draft the YAML.
4. `investigate_validate_plan` until `errors` is empty.
5. `investigate_test_plan` on real past alerts, including known false and true positives; read which rule
   decided each alert and where a rule disagreed with the analyst, what the AI recommended on the rest, and what
   stayed unknown; refine, test again.
6. `investigate_save_plan` with a `test_summary` of what was tested.

## After the template is live

A person promotes the draft; from then on the template meets real alerts, and the loop continues with what
those runs show. Do not propose a change to a live template before steps 1 and 3.

1. `investigate_stats` (optionally for one `template` and a window): outcomes, which rule decided the runs, what
   evidence was missing and why, how many actions were suggested, approved or undone. Many `couldnt_tell` with one
   dominant missing reason points at a step or a rule to fix; a rule that decides most runs is the one to protect;
   an action that is often undone was wrong.
2. `investigate_list_runs` for the runs behind a number (for example `template` + `outcome: couldnt_tell`, or
   `needs_person: true`), then `investigate_get` on a few, and `investigate_get_labels` to see what people said.
3. Edit the YAML.
4. `investigate_compare` the edit against the finished runs it concerns (`last_template` + `limit`, or the run ids
   from step 2). It replays recorded facts only, so it is free and instant. Read `summary.transitions` (which
   outcomes move to which), then the `diff` of each changed run. A fact the edit adds is not fetched (it shows in
   `not_recorded` and reads as unknown), so confirm an edit that adds steps with `investigate_test_plan` on fresh alerts.
5. `investigate_coverage` when `applies_to` changes: `as_active` shows which alerts a draft would take over from
   which template, and the `tie` rows where two active templates are equally specific.
6. `investigate_save_plan` (a draft, with a `test_summary` that quotes the compare), for a person to promote.

`investigate_compare` and the other reads are in both profiles. `investigate_submit_label` and `investigate_cancel`
change something and are only in the full profile. There is no tool for the org's switches (pause, circuit
breaker, settings): a person sets those in the console.

## Investigating a novel case without a template

For a one-off question no template covers, an agent drives waves directly. When the plain read tools (`list_sensors`,
`get_historic_events`, the `mailsec_*` and `cloudsec_entity_*` tools) are offered too, the tool descriptions steer an agent
to put a question that needs more than one check in one wave rather than call them one by one:

1. `investigate_packs` once: the packs, their arguments and exports (each export has a reference form usable in
   `stop_when`). The index is enough on its own: `investigate_operators` (6 to 9 KB per lookup) is only needed for a
   custom `op` step. For an indicator-driven question (no alert) start with the `org_roster` pack: the org's machines
   (offline ones included) and the people who own them.
2. `investigate_wave` with one step per pack (`use`) or operator (`op`). Each step may carry `select` (only the field
   paths the agent will read) and `limit`.
3. `stop_when`: the expressions that would settle the question. The engine cancels the remaining steps as soon as one is
   true and reports `stopped_by`. An unknown is never false, so an incomplete step cannot stop the wave.
4. Read the compact answer (`status`, `complete`, `value`, `usage`), plan the next wave from it, and stop when the
   question is answered. `full: true` returns raw values and is rarely needed; `validate_only: true` checks a wave
   without running it. An invalid wave is refused with `[code] path: message (did you mean ...)` for each error.

## What `investigate_save_plan` refuses

A draft never runs on its own; a person promotes it to active in the console. A template in the earlier format
(`facts`, `proofs`, ...) does not validate (`legacy_template_format`) and is never saved. The tool therefore:

- always writes `status: draft`, and refuses a template that sets `status: active` or any other value;
- refuses a template that does not validate;
- never overwrites an active template, whether the engine lists it as active or the hive record says so;
- replaces an existing draft only with `overwrite: true`, conditional on the record not having changed since it
  was read (the hive's etag);
- fails closed: when the engine or the hive cannot say what exists under the name, nothing is written.
