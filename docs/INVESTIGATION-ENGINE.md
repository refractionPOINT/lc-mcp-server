# Investigation Engine tools

The `investigation_engine` profile (and the read-only `investigation_engine_readonly`) exposes the
Investigation Engine through the LimaCharlie gateway routes `/v1/investigate/{oid}/...`. A plan template is a
YAML document that says which facts to gather for an alert, how to weigh them and what to respond with. Writing
one by hand is long work, so the tools are built for an AI agent to author them, with a person promoting the
result.

> **Off by default.** The `investigate_*` tools and both profiles exist only when the server is started with
> `INVESTIGATION_ENGINE_ENABLED=true` (or `1`). Without it they are not registered: they are absent from `tools/list`
> on every endpoint including `all`, `/mcp/investigation_engine` is not a route, `MCP_PROFILE=investigation_engine` is
> an invalid profile, and naming one in `X-MCP-Tools` is an invalid tool name. No other profile changes. The variable
> is read once at startup.

| Tool | Does | Permissions |
|------|------|-------------|
| `investigate_authoring_kit` | One call: template schema, authoring guide, the org's typed operator catalog, managed examples, effective policy, every validation code. `sections` re-reads part of it | `investigation.get`, `insight.evt.get` |
| `investigate_operators` | The operator catalog, with `filter` and `brief` | same |
| `investigate_validate_plan` | Type-checks a template: structure, operators, references, expressions, budgets | `investigation.get` |
| `investigate_test_plan` | Dry run on real past alerts (detections, cases, or the newest alerts of a category). Waits and polls, returns the agreement rate, disagreements, unknowns and costs. Nothing is written | `investigation.set`, `insight.evt.get` |
| `investigate_save_plan` | Saves the template to the `investigation_plan` hive, **always as a draft** | `investigation_plan.get/set`, `investigation.get`, `insight.evt.get` |
| `investigate_list_templates` | Templates the engine loaded: name, status (draft/active), managed | `investigation.get`, `insight.evt.get` |
| `investigate_start`, `investigate_get` | Start a run, read its state, steps, events or case | `investigation.set` / `.get`, `insight.evt.get` |
| `investigate_wave` | Run a batch of questions (operators or fact packs) in parallel and get compact typed answers, stopping as soon as a `stop_when` expression is true. Also a way to see what an operator returns before writing a plan around it | `investigation.set`, `insight.evt.get` |
| `investigate_packs` | The fact packs (named bundles of questions: host context, process tree, hash spread, ...) with their parameters and exports | `investigation.get`, `insight.evt.get` |

## The authoring loop

1. `investigate_authoring_kit` once.
2. Look at the org's real data (`get_detection`, `run_lcql_query`, `investigate_wave`).
3. Draft the YAML.
4. `investigate_validate_plan` until `errors` is empty.
5. `investigate_test_plan` on real past alerts, including known false and true positives; read the
   disagreements and unknowns, refine, test again.
6. `investigate_save_plan` with a `test_summary` of what was tested.

## Investigating a novel case without a template

For a one-off question no template covers, an agent drives waves directly:

1. `investigate_packs` once: the packs, their arguments and exports (each export has a `ref` usable in `stop_when`).
2. `investigate_wave` with one step per pack (`use`) or operator (`op`). Each step may carry `select` (only the field
   paths the agent will read) and `limit`.
3. `stop_when`: the expressions that would settle the question. The engine cancels the remaining steps as soon as one is
   true and reports `stopped_by`. An unknown is never false, so an incomplete step cannot stop the wave.
4. Read the compact answer (`status`, `complete`, `value`, `usage`), plan the next wave from it, and stop when the
   question is answered. `full: true` returns raw values and is rarely needed; `validate_only: true` checks a wave
   without running it. An invalid wave is refused with `[code] path: message (did you mean ...)` for each error.

## What `investigate_save_plan` refuses

A draft never runs on its own; a person promotes it to active in the console. The tool therefore:

- always writes `status: draft`, and refuses a template that sets `status: active` or any other value;
- refuses a template that does not validate;
- never overwrites an active template, whether the engine lists it as active or the hive record says so;
- never touches a platform-managed template (save a copy under a new name);
- replaces an existing draft only with `overwrite: true`, conditional on the record not having changed since it
  was read (the hive's etag);
- fails closed: when the engine or the hive cannot say what exists under the name, nothing is written.
