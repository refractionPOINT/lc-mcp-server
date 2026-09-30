# Cloud Security — the AppSec code lane, from an IDE agent

MCP tools put LimaCharlie Cloud Security's **code lane** — repository scanning: dependency
vulnerabilities (SCA), secrets, infrastructure-as-code misconfiguration, static-analysis weaknesses,
licence risk and end-of-life runtimes — inside Claude Code, Cursor, or any other MCP client.

| Tool | What it does | Profile |
|---|---|---|
| `cloudsec_code_repos` | The repositories the lane sees, with their scan state and open-finding rollup | `cloud_security`, `cloud_security_readonly` |
| `cloudsec_code_findings` | The findings for one or more repositories, or the cross-filtered facet counts | `cloud_security`, `cloud_security_readonly` |
| `cloudsec_code_fixes` | Rank dependency upgrades by the findings they close | `cloud_security`, `cloud_security_readonly` |
| `cloudsec_code_capabilities` | Read per-connection scan and write capabilities | `cloud_security`, `cloud_security_readonly` |
| `cloudsec_code_status` | Read hosted scan-run status | `cloud_security`, `cloud_security_readonly` |
| `cloudsec_code_sbom` | Get retained SBOM export metadata and a short-lived download URL | `cloud_security`, `cloud_security_readonly` |
| `cloudsec_code_image_repos`, `cloudsec_code_image_repo_facets` | Read image repositories and cross-filtered facets | `cloud_security`, `cloud_security_readonly` |
| `cloudsec_code_images`, `cloudsec_code_image` | Read digest-global images, source lineage and workload evidence | `cloud_security`, `cloud_security_readonly` |
| `cloudsec_code_scan_local` | Scan a working copy **on this machine**, optionally ingesting the report | `cloud_security` |
| `cloudsec_code_ingest` | Push a lossless scanner report, SARIF or CycloneDX document | `cloud_security` |
| `cloudsec_code_rescan` | Queue a hosted scan of one repository/ref | `cloud_security` |
| `cloudsec_code_pr_check` | Queue a provider-verified PR check that publishes source-control status/comments | `cloud_security` |
| `cloudsec_code_webhook` | Repair a GitHub App's global webhook using an existing organization adapter | `cloud_security` |
| `cloudsec_code_autofix` | Opens a dependency-fix pull request in the customer's repository (a WRITE) | `cloud_security` |

Advanced reads include `cloudsec_code_provenance`,
`cloudsec_get_finding_evidence_chain`, `cloudsec_get_code_coverage` and
`cloudsec_get_code_impact`. Runtime package evidence is described in
[CS-15-runtime-package-evidence.md](CS-15-runtime-package-evidence.md).
These capabilities depend on backend rollout, schema and evidence coverage.
Tool availability is not proof that a capability is enabled for this organization.

Everything here wraps `api.limacharlie.io/v1/cloudsec/{oid}/code/*` and the findings routes' `repo`
selector — the same surface `limacharlie cloudsec code …` uses. Local scanning runs on the machine hosting the server; the other tools use server-side data.
Start with [security-product onboarding](SECURITY-PRODUCTS.md) for credentials and a read-only pilot.

## Before it can return anything

Hosted code scanning is **opt-in per organization** and needs two configuration
records:

1. A source-control provider is connected — a `cloudsec_provider` hive record.
2. A `code_scanning` record exists in the `cloudsec_policy` hive, naming which repositories are in
   scope and which engines run.

Both are hive records, so an agent reads and writes them with the generic hive tools (`get_rule` /
`set_rule` with `hive_name`), not through these tools. **An empty answer from a code tool usually
means setup or coverage is incomplete, not that the code is clean**. BYO ingestion
with `cloudsec_code_ingest` needs an enabled in-scope scan policy, but does not
require a source-control connection. A local-only scan does not produce hosted
results until its report is ingested.

The whole `/cloudsec/*` surface also needs the org subscribed to the `ext-cloud-security` extension
and the caller to hold `ai_agent.operate` and `cloudsec.get`. Ingest needs
`cloudsec.set`; AutoFix, remediation run creation and decisions need the distinct
`cloudsec.respond` permission. Tool registration does not enable a backend feature.

## Setup — Claude Code

```bash
cd /path/to/lc-mcp-server
go build -o lc-mcp-server ./cmd/server

claude mcp add \
  --env LC_OID=YOUR_ORGANIZATION_UUID \
  --env LC_API_KEY=YOUR_API_KEY \
  --env MCP_MODE=stdio \
  --env MCP_PROFILE=cloud_security_readonly \
  --transport stdio limacharlie-cloudsec \
  -- /absolute/path/to/lc-mcp-server
```

Then, in a session: `/mcp` lists the server and its tools.

Begin with `cloud_security_readonly`. Reconnect with `cloud_security` when you
need a local scan, ingest or an explicitly requested fix; generic Hive setup uses
`platform_admin`. Profiles select tools but do not grant permissions.

## Setup — Cursor

Use `~/.cursor/mcp.json` for your personal configuration:

```json
{
  "mcpServers": {
    "limacharlie-cloudsec": {
      "command": "/absolute/path/to/lc-mcp-server",
      "args": [],
      "env": {
        "LC_OID": "<your-organization-id>",
        "LC_API_KEY": "<your-api-key>",
        "MCP_MODE": "stdio",
        "MCP_PROFILE": "cloud_security_readonly",
        "LOG_LEVEL": "warn"
      }
    }
  }
}
```

`LOG_LEVEL=warn` matters more here than it looks: the server logs to stderr, and a chatty stderr in
stdio mode is noise in the client's transport log.

## Reading findings: why `repo` is required

`cloudsec_code_findings` **will not list without at least one `repo`.** The findings backend has no
"any repository" selector, so dropping the constraint does not mean "all code findings" — it means
the organization's whole worklist, cloud findings included, returned under a tool named for the code
lane. Three of the lane's classes (`vulnerability`, `misconfig`, `malware`) are shared with the cloud
lane, so a class filter does not scope to code either.

The unscoped mode is `facets: true`, and it is honest because the `repo` facet counts only findings
that *have* a repository. So the order is:

```text
cloudsec_code_findings { "facets": true }        → which repositories carry what
cloudsec_code_repos    { "has_findings": true }  → the same, per repository, with scan state
cloudsec_code_findings { "repo": ["owner/name"], "severity": ["CRITICAL","HIGH"] }
```

`repo` is repeatable and the gateway honours at most 100 values.

`repo` is matched **exactly** against a key whose owner and name segments are both ASCII
lower-cased in the stored repository key, while a finding's own `code.repo_name` is the platform's *display*
casing. The shared findings selector folds what you pass, so reading `Example/API`
off a finding and feeding it back now works. A key that is genuinely wrong still returns zero rows:
an empty page under a single `repo` filter carries a `note` saying which of the three cases it is —
the key is right and nothing matched, the key is wrong and here is the real one, or no such
repository is in the inventory.

Provenance rides on each finding as `code.detected_via`: `lc-code-scanner` for the hosted sandbox
scan, `lc-code-scanner-byo` for a pushed local scan, `sarif-ingest` / `cyclonedx-ingest` for a
converted document. To *filter* on it, use `source`, which groups those tokens server-side inside the
keyset query: `hosted`, `ingest`, `other`, `none`, or `both`. Prefer it over folding `detected_via`
yourself — a page-at-a-time fold makes every count a count of one page.

## Scanning the working copy

```text
cloudsec_code_scan_local { "path": "/home/me/src/api" }
```

Requirements, all of which produce a clear refusal rather than a confusing failure:

- **stdio mode only.** The scan runs a container on the machine hosting the server. In stdio mode
  that is the caller's own machine; on a shared HTTP deployment it would be one tenant asking the
  server to read a directory it chose.
- **A compatible scanner and the `limacharlie` CLI on PATH.** Docker is needed
  for the container path; a configured local scanner binary avoids that prerequisite.
  The scan is delegated to
  `limacharlie cloudsec code scan`, which owns the scanner image pin and the container contract, so a
  local scan follows the selected CLI and scanner version. PyPI `limacharlie` 5.6.2
  does not contain `cloudsec code scan`: use a development SDK containing CodeSec
  support and verify `limacharlie cloudsec code scan --help`. See the
  [CLI installation guide](https://docs.limacharlie.io/cloud-security/code-security/getting-started/#cli-installation). If it is installed somewhere unusual, the
  **operator** names it with `LC_CODE_SCANNER_CLI` — deliberately an environment variable and not a
  tool argument, because the text a calling agent reads (a repository name, a finding's evidence) is
  tenant-influenced, and an argument naming an executable would be a way to turn that into one.
- **Minutes, not seconds.** Default and maximum timeout is 30 minutes, matching the hosted job cap.

The default scanner image requires registry pull access. An anonymous pull is not
sufficient. The operator can set `LC_CODE_SCANNER_IMAGE` for an authorized compatible
image or `LC_CODE_SCANNER_BINARY` for a local scanner executable; they map to the
CLI's `--image` and `--binary`, and cannot be selected by an MCP caller. Use a
development CLI containing those options until they are released. Hosted scanning
or direct BYO ingestion avoids the local container prerequisite.

`scanners` defaults to `sca,iac,licenses`; `sast` and `images` are also available locally.
**`secrets` is refused**, and that is deliberate: a credential's identity in this pipeline is a digest
keyed by a value only the hosted lane holds, so locally-found secrets would neither deduplicate
against the hosted scan's nor be accepted by the ingest.

Local SAST uses scanner-local rules by default. It does not automatically load
organization `cloudsec_code_rule` records: the delegated local-only CLI has no
organization credentials. The operator can set `LC_CODE_SCANNER_RULES_FILE` to a
compatible exported code-rule JSON file; this forwards the CLI's `--rules-file`
option. The assistant cannot choose that file through tool arguments. An absent
rule set must not be reported as a clean SAST scan.

Pass `output_path` whenever you pass `ingest`. The report otherwise lives only in the scan's
temporary directory, which is removed as soon as the scanner returns — so a push that fails for any
ordinary reason (not subscribed, the repository not in the collected inventory, no enabled
`code_scanning` policy, the free-tier quota, a transient 502) costs the whole scan again. The failure
message says which case you are in.

With `ingest: true` and a `repo`, the report is pushed through **this server's own credential** to
`/code/ingest`. The report format is loss-free, so it lands on exactly the rows a hosted scan of the
same repository would write; re-pushing an identical report writes nothing, and a pushed report can
only close findings *it* previously reported — never one the hosted scanner found. Without `ingest`, the findings report is not uploaded to LimaCharlie. Docker image
pulls, scanner dependency/intelligence lookups, and optional rule downloads may
still use the network. A local scan does not update the hosted estate until ingested.

## `cloudsec_code_autofix`

For an eligible SCA finding, requests a dependency-fix pull request:

```text
cloudsec_code_autofix {"finding_id": "FINDING_ID_FROM_THE_WORKLIST"}
```

Use the exact `fnd_` ID returned by the worklist, not a CVE or package name.

**The response returns a governed remediation run, not proof of a pull request.**
This operation needs `cloudsec.respond`; `cloudsec.set` alone is refused. The caller
is recorded as both requester and approver for the `open_fix_pr` run. Follow it with
`cloudsec_get_remediation` using the returned `run_id`. Repeating the request before
its PR is opened can return the same run with `replayed: true`.

The clone, edit and pull request happen asynchronously. Read the run's `state`,
`change` and `failure_reason` before reporting an outcome. A created PR is not a
verified deployed fix: `verified` means the fix was observed in every in-scope
deployment. Missing write credentials, policy/scope/quota issues, malicious
packages, no fixed version, unsupported ecosystems, an existing PR or exhausted
budgets fail the run with a reason. A disabled workflow is refused immediately;
there is no fallback that bypasses governed remediation.

A write-capable credential is **explicit and opt-in**. GitHub uses Contents and
Pull requests read/write App permissions; GitLab.com and Bitbucket write support
depends on workflow availability and separately configured write credentials.
Inspect `cloudsec_code_capabilities` after configuring the credential. A queued
request is not evidence that the provider can complete a fix. See the
[AutoFix guide](https://docs.limacharlie.io/cloud-security/code-security/autofix/)
for supported edits and lockfiles. Optional AI-proposed fixes are unavailable
until the backend enables that capability; tenant settings alone cannot enable it.

## Other code and image workflows

Read repository scan state before interpreting findings, and follow hosted runs
with `cloudsec_code_status`. `cloudsec_code_rescan` takes a `repo` and optional
`ref`; its acknowledgement queues work rather than completing a scan.

`cloudsec_code_sbom` takes the repository key and returns export metadata plus a
short-lived signed URL. The tool does not follow the URL or send the organization
token to object storage. Download the returned artifact through a separate
approved client if needed.

```text
cloudsec_code_image_repos {"limit": 20}
cloudsec_code_images {"lineage_status": ["verified"], "limit": 20}
cloudsec_code_image {"digest": "sha256:64_HEXADECIMAL_CHARACTERS"}
```

Replace the digest placeholder with an actual returned `sha256:` digest. Source
lineage is distinct from signing. `asserted` or `inferred` does not mean verified
provenance; missing or stale source/workload evidence stays unknown. Image lists
accept `lineage_status` arrays; repository facets with `lineage_facet: true` count
digest-global lineage rather than narrowing it to selected repositories. New
filters require a supporting backend; older readers must not silently drop them.

`cloudsec_code_ingest` takes `source` (`report`, `sarif` or `cyclonedx`), `repo`,
optional revision/provider context, and exactly one of `document` (JSON object)
or `document_b64` (base64 JSON, optionally gzip-compressed). The envelope is bounded to 20 MiB. It reads
no remote URL or local file; omit raw source, credentials and secrets from the
submitted report. Only a complete successful producer report can retire that
producer's prior findings, and it cannot close hosted findings.

`cloudsec_code_pr_check` needs the actual provider pull/merge-request number,
head revision and action. GitHub also needs `base_sha`; `edited` is GitHub-only
and requires the prior base for a real retarget. GitLab base is optional and
Bitbucket permits abbreviated head revisions. This publishes source-control
status/comments when the provider workflow is enabled, so review that write
before requesting it. The provider's verified revisions take precedence.

`cloudsec_code_webhook` repairs an existing GitHub App's **global** webhook and
can affect multiple installations. It needs `cloudsec.set` and the applicable
adapter/secret permissions. Use the existing adapter URL and signing secret;
do not invent either or expose the secret in conversation. GitLab/Bitbucket use
their own webhook setup. This is an administration change, not a read-only
diagnostic or a prerequisite for a first posture review.

For Microsoft 365 CloudSec onboarding, `cloudsec_mint_m365_certificate` requires
`cloudsec.set` and `secret.set`. It returns only the public certificate; the private
key remains in the secret store. Upload the returned public certificate to the
Entra application. Repeated generation is idempotent; `replace: true` immediately
rotates the stored private key and can interrupt an existing connection until
the new public certificate is uploaded.

## Pointing at another gateway

`LC_API_URL` repoints every LimaCharlie REST call this process makes — the SDK reads, the raw
cloudsec POSTs, and the `PostJSON` helper alike:

```bash
export LC_API_URL="https://your-authorized-gateway.example"
```

It is a **server-level** setting read once from the process environment, never a per-request
argument: a caller-chosen API host would redirect this server's credentialed requests at a host of
their choosing. A value that is not an `http(s)` URL is ignored and production is used, because a
malformed override otherwise turns every call into an opaque transport failure.

This exists for staging. A route reaches the experimental gateway days or weeks before production, so
without it a tool written against a new route cannot be exercised end to end at all.

## Build provenance

`cloudsec_code_provenance_push` accepts a bounded JSON `document` string and sends
its bytes unchanged. It never fetches a URL or reads a file. Use metadata-only LC
provenance, SLSA v1 or offline Sigstore bundles; do not pass raw source, snippets,
credentials, environment variables or build output. The server assigns tenant and
trust context. Signature verification failure is a refusal, not an asserted claim.

`cloudsec_code_provenance` reads normalized attestations by `repo_urn`, `commit`,
`digest` and `cursor`. Decisions include the full conflicting claim set regardless
of filters. Only the read belongs to `cloud_security_readonly`; pushes require
`cloudsec.set` and are additive. Feature rollout and schema installation remain
separate prerequisites; tool registration grants no production authorization.
