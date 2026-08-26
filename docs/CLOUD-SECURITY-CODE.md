# Cloud Security — the AppSec code lane, from an IDE agent

Four MCP tools put LimaCharlie Cloud Security's **code lane** — repository scanning: dependency
vulnerabilities (SCA), secrets, infrastructure-as-code misconfiguration, static-analysis weaknesses,
licence risk and end-of-life runtimes — inside Claude Code, Cursor, or any other MCP client.

| Tool | What it does | Profile |
|---|---|---|
| `cloudsec_code_repos` | The repositories the lane sees, with their scan state and open-finding rollup | `cloud_security`, `cloud_security_readonly` |
| `cloudsec_code_findings` | The findings for one or more repositories, or the cross-filtered facet counts | `cloud_security`, `cloud_security_readonly` |
| `cloudsec_code_scan_local` | Scans a working copy **on this machine** with the same scanner the hosted lane runs, and optionally pushes the result | `cloud_security` |
| `cloudsec_code_autofix` | **Reserved.** Refuses every call with a machine-readable reason | `cloud_security` |

Everything here wraps `api.limacharlie.io/v1/cloudsec/{oid}/code/*` and the findings routes' `repo`
selector — the same surface `limacharlie cloudsec code …` uses. Nothing is recomputed client-side.

## Before it can return anything

The code lane is **opt-in per organization** and two things have to be true, neither of which these
tools can turn on:

1. A source-control provider is connected — a `cloudsec_provider` hive record.
2. A `code_scanning` record exists in the `cloudsec_policy` hive, naming which repositories are in
   scope and which engines run.

Both are hive records, so an agent reads and writes them with the generic hive tools (`get_rule` /
`set_rule` with `hive_name`), not through these tools. **An empty answer from a code tool usually
means one of those two is missing, not that the code is clean** — which is why every one of the four
descriptions says so.

The whole `/cloudsec/*` surface also needs the org subscribed to the `ext-cloud-security` extension
and the caller to hold `cloudsec.get` (and `cloudsec.set` for `cloudsec_code_scan_local` with
`ingest`).

## Setup — Claude Code

```bash
cd /path/to/lc-mcp-server
go build -o lc-mcp-server ./cmd/server

claude mcp add limacharlie-cloudsec \
  --env LC_OID=<your-organization-id> \
  --env LC_API_KEY=<your-api-key> \
  --env MCP_MODE=stdio \
  --env MCP_PROFILE=cloud_security \
  -- /absolute/path/to/lc-mcp-server
```

Then, in a session: `/mcp` lists the server and its tools.

`MCP_PROFILE=cloud_security` keeps the tool list to the ~53 Cloud Security tools. Use
`cloud_security_readonly` for a session that must not be able to write, or `all` for the whole
platform.

## Setup — Cursor

`~/.cursor/mcp.json` (or `.cursor/mcp.json` in a project, to scope the credential to one repository):

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
        "MCP_PROFILE": "cloud_security",
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

```
cloudsec_code_findings { "facets": true }        → which repositories carry what
cloudsec_code_repos    { "has_findings": true }  → the same, per repository, with scan state
cloudsec_code_findings { "repo": ["owner/name"], "severity": ["CRITICAL","HIGH"] }
```

`repo` is repeatable and the gateway honours at most 100 values.

Provenance rides on each finding as `code.detected_via`: `lc-code-scanner` for the hosted sandbox
scan, `lc-code-scanner-byo` for a pushed local scan, `sarif-ingest` / `cyclonedx-ingest` for a
converted document. **There is no server-side selector on it** — read it per finding rather than
expecting to filter by it.

## Scanning the working copy

```
cloudsec_code_scan_local { "path": "/home/me/src/api" }
```

Requirements, all of which produce a clear refusal rather than a confusing failure:

- **stdio mode only.** The scan runs a container on the machine hosting the server. In stdio mode
  that is the caller's own machine; on a shared HTTP deployment it would be one tenant asking the
  server to read a directory it chose.
- **Docker and the `limacharlie` CLI on PATH.** The scan is delegated to
  `limacharlie cloudsec code scan`, which owns the scanner image pin and the container contract, so a
  local scan and the hosted scan cannot drift apart. Pass `cli` if it is installed somewhere unusual.
- **Minutes, not seconds.** Default and maximum timeout is 30 minutes, matching the hosted job cap.

`scanners` defaults to `sca,iac,licenses`; `sast` and `images` are also available locally.
**`secrets` is refused**, and that is deliberate: a credential's identity in this pipeline is a digest
keyed by a value only the hosted lane holds, so locally-found secrets would neither deduplicate
against the hosted scan's nor be accepted by the ingest.

With `ingest: true` and a `repo`, the report is pushed through **this server's own credential** to
`/code/ingest`. The report format is loss-free, so it lands on exactly the rows a hosted scan of the
same repository would write; re-pushing an identical report writes nothing, and a pushed report can
only close findings *it* previously reported — never one the hosted scanner found. Without `ingest`,
nothing leaves the machine, and the result says so explicitly so a scan that found plenty is not
misread as a clean estate.

## `cloudsec_code_autofix`

Registered, listed, and refuses every call with:

```json
{
  "error": "cloudsec_code_autofix is reserved and not available yet",
  "reason": "code_autofix_not_available",
  "retryable": false,
  "remediation": "Read the finding's fixed_version with cloudsec_code_findings, apply the bump yourself, and verify it with cloudsec_code_scan_local before pushing."
}
```

It exists so the tool surface is stable and so an agent gets one clear answer instead of guessing.
Dependency AutoFix pull requests are not built, and the write-scoped source-control credential they
would need does not exist either — the connector this organization uses is read-only, permanently.

## Pointing at a non-production gateway

`LC_API_URL` repoints every LimaCharlie REST call this process makes:

```bash
--env LC_API_URL=https://lc-api-go-exp-<hash>.<region>.run.app
```

It is a **server-level** setting read once from the process environment, never a per-request
argument: a caller-chosen API host would redirect this server's credentialed requests at a host of
their choosing. A value that is not an `http(s)` URL is ignored and production is used, because a
malformed override otherwise turns every call into an opaque transport failure.

This exists for staging. A route reaches the experimental gateway days or weeks before production, so
without it a tool written against a new route cannot be exercised end to end at all.
