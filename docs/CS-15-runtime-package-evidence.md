# CS-15 runtime package evidence

`cloudsec_check_finding_runtime` answers one question for one open package finding:
**did that code actually run** on the finding's cloud resource? The answer is
informational — it never changes the finding's `lc_risk`, status, fingerprint or
disposition, and no rung is on its own a reason to close, suppress or deprioritise a
finding.

## The ladder

Plan 24 decision D6 fixes the answer to five rungs and no more.

| Rung | Means | Precondition |
|---|---|---|
| `unknown` | No usable evidence | Anything missing, stale, expired, foreign, unattributable or conflicting |
| `present` | An agent is there; the telemetry cannot carry a claim | A summary exists but a completeness gate failed |
| `not_observed` | A **complete** window saw the package never run | Every completeness gate passed |
| `loaded` | Mapped into a running process | One unambiguous attributed module observation |
| `executing` | Is the running executable | One unambiguous attributed process-image observation |

The unknown rung has two accepted spellings and one rendered form. Go's zero value is the
empty string, so an unset status is unknown by construction; a public API renders it
through `findings.WireRuntimeStatus` as the literal `"unknown"`, because an empty string
in a JSON enum reads as a missing field rather than as an answer. Both decode here — and
accepting the rendered form is not optional, since every status the backend emits goes
through that renderer.

## What the answer is not

`not_observed` is the only negative rung and **it is not a safety claim**. It says a
complete telemetry window did not see the code run. It does not say the package is gone,
that the finding is fixed, or that the vulnerability is not exploitable, and nothing this
tool returns proves anything about exploitability.

**A telemetry lapse never produces a negative** (plan §18 gate 12). An interrupted or
too-young window, a shed write, a truncated watch list, a versionless package, an
unattributable package and a conflicting package inventory all come back as `present` or
unknown, each with a `reason` naming the gate that failed. Read the reason before
reporting an unknown.

Every verdict carries `level` (`observed` | `derived` | `unknown` — never `verified` and
never `asserted`) and, where known, the window edges `observed_at` / `stale_at`, so state
the freshness when reporting one. `sensors_complete: false` means the sensor set could not
be fully enumerated, which makes every whole-resource negative impossible.

## Read `accepted` before `status`

The response envelope is `{"accepted": bool, "runtime": {…} | null}`.

`accepted: false` means **the check did not run**, and `reason` is then an availability
reason rather than a verdict — `feature_disabled`, `no_resource`, `no_packages`,
`no_sensors` or `cache_unavailable`. The runtime-evidence feature is **default-off**, so
`feature_disabled` is the answer for most orgs today. None of these is a statement that
nothing ran, and reporting one as a negative would be the exact failure the ladder exists
to prevent. An unknown finding id returns `"runtime": null`.

## Asking starts the measurement

The route is a POST even though it reads, and that is deliberate: the check **publishes
the finding's packages as relevant** so the sensor-side producer begins summarizing them.
Nothing is watched until somebody asks, and a sensor stops being watched within one TTL of
the last time anybody did. So this tool does have a side effect — it does not mutate
customer state, which is why it is annotated read-only, but it is not accurate to say it
stores nothing.

The consequence for a caller is that **a cold first call is expected to be inconclusive**.
`complete: false` with a `retry_after_seconds` means the window has not matured yet, so ask
again rather than reporting an immature window as a finished answer. Any other unsettled
state is final.

## Reading the answer

Pass `verdict: true` to get the single verdict to report: **the server's own
whole-resource verdict**, plus the coverage it rests on. It is a field read, not a local
fold — the backend already computes `runtimeevidence.CheckResult.Headline()` and publishes
it at the top of the `runtime` object.

Do not reduce the per-package rows yourself. The negative rung ranks **below** `present`
on purpose, so one package with an incomplete window — or a partial sensor enumeration —
vetoes a whole-resource negative. Taking the strongest row silently loses that veto, which
is the mistake this option exists to prevent.

Without the flag the full response comes back with every status folded onto the ladder and
the rows sorted by package key. A token this build does not recognise becomes `unknown`
with an explicit `status_recognized: false` beside it; the server's `reason` is never
overwritten, because `no_evidence` means "no summary exists for this sensor" and asserting
that would invent a coverage fact nobody established.

## Legacy spelling

`dormant` was the old name for `not_observed`. It is decoded on read (plan §14) and never
emitted. The CIEM identity-dormancy facet (`dormant_90d`, `dormant_admin`), the
AI-sessions session status and sensor sleep mode keep the word and are unrelated
vocabularies.

## Compatibility

The gateway route `POST /cloudsec/{oid}/findings/{id}/runtime-check` (plan 24 §6,
permission `cloudsec.get`, 600 requests per hour per authenticated identity) may not be
deployed in every datacenter yet. A 404 / unknown-route error means exactly that; it must
never be reported as "nothing ran". The tool returns the error rather than an empty
verdict, because a runtime check that quietly answers from nothing is the failure this
package exists to prevent.

Roll back by removing the tool from the two `cloud_security*` profiles (both
`internal/tools/registry.go` and `configs/profiles.yaml`). It enables nothing, changes no
IAM, and writes no customer-visible state.

Package: https://github.com/maximelb/claude-config/issues/150
Epic: https://github.com/maximelb/claude-config/issues/134
Contract: https://github.com/refractionPOINT/go-cloudsec/pull/413
