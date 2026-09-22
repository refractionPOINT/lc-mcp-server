# CS-15 runtime package evidence

`cloudsec_check_finding_runtime` answers one question for one open package finding:
**did that code actually run** on the finding's cloud resource? It is a read — it
computes a verdict on demand and stores nothing — and it is informational: it never
changes the finding's `lc_risk`, status, fingerprint or disposition.

## The ladder

Plan 24 decision D6 fixes the answer to five rungs and no more.

| Rung | Means | Precondition |
|---|---|---|
| `""` (unknown) | No usable evidence | Anything missing, stale, expired, foreign, unattributable or conflicting |
| `present` | An agent is there; the telemetry cannot carry a claim | A summary exists but a completeness gate failed |
| `not_observed` | A **complete** window saw the package never run | Every completeness gate passed |
| `loaded` | Mapped into a running process | One unambiguous attributed module observation |
| `executing` | Is the running executable | One unambiguous attributed process-image observation |

The unknown rung's wire spelling is the **empty string**, so an absent `status` and
`status: ""` mean the same thing.

## What the answer is not

`not_observed` is the only negative rung and **it is not a safety claim**. It says a
complete telemetry window did not see the code run. It does not say the package is
gone, that the finding is fixed, or that the vulnerability is not exploitable, and no
rung here is on its own a reason to close, suppress or deprioritise a finding.

**A telemetry lapse never produces a negative** (plan §18 gate 12). An interrupted or
too-young window, a shed write, a truncated watch list, a versionless package, an
unattributable package and a conflicting package inventory all come back as `present`
or unknown, each with a `reason` from the closed vocabulary naming the gate that
failed. Read the reason before reporting an unknown.

Every verdict carries `level` (`observed` | `derived` | `unknown` — never `verified`
and never `asserted`) and the window edges `observed_at` / `stale_at`, so state the
freshness when reporting one. `sensors_complete: false` means the sensor set could not
be fully enumerated, which makes every whole-resource negative impossible.
`complete: false` with a `retry_after` means a window is still maturing and asking
again later could change the answer; any other unsettled state is final.

## Folding the rows

Pass `headline: true` to get the single verdict to report, rather than reducing the
rows yourself. The negative rung ranks **below** `present` on purpose, so one package
with an incomplete window — or a partial sensor enumeration — vetoes a whole-resource
negative. A maximum over the rungs silently loses that veto; `runtimeHeadline` mirrors
`runtimeevidence.Aggregate` exactly, except that it stamps no `source` on a
locally-folded unknown (claiming the producer token for a reduction performed in this
server would invent provenance).

## Legacy spelling

`dormant` was the old name for `not_observed`. It is decoded on read (plan §14) and
never emitted; a token this build does not recognise decodes to unknown with reason
`no_evidence`, never to a verdict. The CIEM identity-dormancy facet (`dormant_90d`,
`dormant_admin`), the AI-sessions session status and sensor sleep mode keep the word
and are unrelated vocabularies.

## Compatibility

The gateway route `POST /cloudsec/{oid}/findings/{id}/runtime-check` (plan 24 §6,
permission `cloudsec.get`) is a **separate slice and may not be deployed in every
datacenter yet**. A 404 / unknown-route error means exactly that; it must never be
reported as "nothing ran". The tool deliberately returns the error rather than an
empty verdict — a runtime check that quietly answers from nothing is the failure this
whole package exists to prevent.

Roll back by removing the tool from the two `cloud_security*` profiles; it enables
nothing, changes no IAM, and writes no resource.

Package: https://github.com/maximelb/claude-config/issues/150
Epic: https://github.com/maximelb/claude-config/issues/134
Contract: https://github.com/refractionPOINT/go-cloudsec/pull/413
