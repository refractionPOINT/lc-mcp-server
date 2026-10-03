# Start with CloudSec, CodeSec or MailSec

Use this guide to connect an AI assistant to an existing LimaCharlie organization,
check coverage, and review a small pilot before enabling responses.

Check your client's tool list after connecting. Product subscriptions,
permissions and backend capabilities are configured separately from the client.

## Choose a profile and credentials

| Your task | `MCP_PROFILE` | Minimum product permission |
|---|---|---|
| Review CloudSec posture and CodeSec results | `cloud_security_readonly` | `cloudsec.get` |
| CloudSec triage, code ingest or local scanning | `cloud_security` | Reads need `cloudsec.get`; writes generally need `cloudsec.set` |
| Request CodeSec AutoFix or decide remediation runs | `cloud_security` | `cloudsec.respond` |
| Review MailSec coverage, messages and histories | `email_security_readonly` | `mailsec.get` |
| MailSec diagnostics and response actions | `email_security` | Grant the additional permission for each operation in the MailSec guide |
| Create provider, policy or credential records and subscribe extensions | `platform_admin` | Permissions for the specific Hive and extension operation |

The default server also requires **`ai_agent.operate`** for organization-scoped
tools. Profiles select which tools an assistant can call; they do not grant API
permissions. Use a read-only key with a read-only profile for the first review.
Do not add generic API dispatch or administration to that review session.

Create an organization API key in **Access Management → REST API** with the
permissions above. Copy the organization's UUID from its settings or URL;
the organization name is not an OID. For multi-organization access, see the
[README authentication modes](../README.md#authentication-modes); pass `oid` on
calls that select an organization.

## Connect a local client

Build from the repository with the Go version required by `go.mod` (currently
Go 1.27.1 or newer):

```bash
go build -o lc-mcp-server ./cmd/server
```

For [Claude Code](https://code.claude.com/docs/en/mcp):

```bash
claude mcp add \
  --env LC_OID=YOUR_ORGANIZATION_UUID \
  --env LC_API_KEY=YOUR_API_KEY \
  --env MCP_MODE=stdio \
  --env MCP_PROFILE=cloud_security_readonly \
  --transport stdio limacharlie-cloudsec \
  -- /absolute/path/to/lc-mcp-server
```

For MailSec, use `MCP_PROFILE=email_security_readonly` and a distinct server name,
such as `limacharlie-mailsec`. Restart or reconnect the client and inspect `/mcp`
or its equivalent tool list. For Cursor, use the JSON entry in the
[CodeSec guide](CLOUD-SECURITY-CODE.md#setup--cursor), changing the profile as needed.
Keep credentials in your personal client configuration rather than committing
them into a repository.

You can also connect to `https://mcp.limacharlie.io/mcp/cloud_security_readonly`
or `/mcp/email_security_readonly` using OAuth or the organization-key bearer format
`API_KEY:ORGANIZATION_UUID`. A server-wide configured profile can override the
URL profile. An
unrecognized profile endpoint can return 404; confirm the returned tools.
Keep the API key's permissions read-only even when using a profile endpoint.
See the [authentication instructions](https://docs.limacharlie.io/6-developer-guide/mcp-server/).

## Prepare one pilot connection

If a provider is already connected, start with the read-only review below. For a
new connection, use the product's console wizard or CLI guide to provision the
cloud or email provider's credentials first:

- [CloudSec setup](https://docs.limacharlie.io/cloud-security/setup-cli/)
- [CodeSec: one repository](https://docs.limacharlie.io/cloud-security/code-security/getting-started/)
- [MailSec: one mailbox](https://docs.limacharlie.io/email-security/setup-cli/)

An administration MCP session exposes the same configuration operations:

| Tool | Use |
|---|---|
| `subscribe_to_extension` | Enable `ext-cloud-security` or `ext-email-security` by `extension_name` |
| `get_hive_schema` | Inspect the schema for a provider or policy Hive |
| `validate_hive_record` | Validate proposed `data` for a `hive_name` and `key` before saving |
| `get_rule` / `list_rules` | Read existing records by `hive_name` and `rule_name` |
| `set_rule` | Save the product's JSON data as `rule_content`, with `hive_name`, `rule_name` and `enabled` |
| `set_hive_record_enabled` | Enable/disable a record while preserving its data |

Use `cloudsec_provider` / `cloudsec_policy` for CloudSec and CodeSec;
use `mailsec_provider` / `mailsec_policy` for MailSec. Credentials belong in the
`secret` Hive, referenced as `hive://secret/RECORD_NAME` from the provider.
The secret's data is `{"secret": "CREDENTIAL_VALUE"}`; a credential JSON document
is serialized as that string value, rather than inserted directly as Hive data.
For CodeSec, the policy data has `policy_type: "code_scanning"` and a nested
`code_scanning` object. The Hive record and its nested scan policy must both be
enabled. Use the linked product examples for the provider-specific schema.

Subscription needs `ext.conf.set`. Provider access uses separate
`cloudsec_provider.get/set` or `mailsec_provider.get/set` permissions; policy
access uses `cloudsec.get/set` or `mailsec.get/set`. Secret writes need `secret.set`.
MCP record updates preserve metadata by reading it first; grant the relevant
`.get.mtd` or `.get` as well when supplying `enabled`, tags or comments. The
metadata-only tool needs the corresponding `.set` or `.set.mtd` plus metadata
read access. Never pass credential values through an assistant merely to review
posture; use the console or a controlled setup workflow to store them.

For CodeSec, select one repository before expanding policy scope. For MailSec,
select one mailbox and keep policies alert-only during the pilot. Subscribing to
MailSec seeds default detection rules; it does not enable response automations.
Review the proposed provider scope and any automation changes before saving them.

## First read-only review

Ask: **"Show the scan status and overview, then explain the highest-risk open
findings. Check collection and scanner coverage before drawing conclusions."**

The CloudSec assistant can call:

```text
cloudsec_get_scan_status {}
cloudsec_get_overview {}
cloudsec_list_findings {"severity": ["CRITICAL", "HIGH"], "limit": 20}
```

For CodeSec:

```text
cloudsec_code_capabilities {}
cloudsec_code_repos {"limit": 20}
cloudsec_code_findings {"repo": ["example/api"], "severity": ["CRITICAL", "HIGH"]}
```

Replace `example/api` with the repository key returned by `cloudsec_code_repos`.
An empty finding page is not a coverage statement. Read scan status, partial
results and capability reasons. Keep filters unchanged while following
`next_cursor`; a short page can still have another page.

For MailSec, follow the [coverage → messages → history workflow](MAIL-SECURITY.md).
Use a benign pilot message to confirm ingestion and the action history before
expanding mailbox scope or enabling remediation.

## Additional CloudSec workflows

| Task | Tools |
|---|---|
| Hosted scan/SBOM | `cloudsec_code_status`, `cloudsec_code_sbom`, `cloudsec_code_rescan` |
| PR checks/BYO findings | `cloudsec_code_pr_check`, `cloudsec_code_webhook`, `cloudsec_code_ingest` |
| Container images | `cloudsec_code_image_repos`, `cloudsec_code_image_repo_facets`, `cloudsec_code_images`, `cloudsec_code_image` |
| Entra public certificate generation | `cloudsec_mint_m365_certificate` |
| IaC attribution | `cloudsec_code_iac_map_extract`, `cloudsec_code_iac_map_push`, `cloudsec_code_iac_map_status` |
| Historical compliance | `cloudsec_list_compliance_runs`, `cloudsec_create_compliance_run`, `cloudsec_export_compliance_run` |
| Compliance attestations/drift | `cloudsec_list_compliance_attestations`, `cloudsec_create_compliance_attestation`, `cloudsec_list_compliance_events` |
| Assessment/delivery schedules | `cloudsec_list_compliance_schedules`, `cloudsec_set_compliance_schedule` |
| Azure containment | `cloudsec_get_azure_scope_hierarchy` |

The [CodeSec guide](CLOUD-SECURITY-CODE.md) explains scanner, PR, image and
certificate prerequisites. Compliance reads belong to the read-only profile;
creating a run, attestation or schedule writes durable records and needs
`cloudsec.set`. Missing detector proof is unknown, not a passing control. An
export returns its artifact object; the tool does not fetch returned URLs with
the organization token. Azure containment does not establish an access grant.

IaC extraction is STDIO-only and requires the operator to explicitly set
`LC_IAC_MAP_EXTRACTOR` to an installed extractor's path. It does not implicitly
choose an executable from PATH. Supply the local show-JSON `input`, `repository`,
full `commit` and `source_kind` (`state_identity` or `plan_desired`). Review its
sanitized document before explicitly pushing it; never upload raw state, plan,
source or credentials. The extractor runs without the process's authentication
environment. Push and exact receipt status both need `cloudsec.set`, so status
is excluded from the read-only profile despite its read-only annotation.
`processing` is staging, `published` is visible, `retryable` permits resubmitting
the same document and `superseded` means newer evidence replaced it. None proves
deployment or remediation. Availability depends on backend provenance rollout.

## When something is missing

- **No tool in the client:** check the profile and MCP server version, then reconnect.
- **Missing privilege:** check `ai_agent.operate` and the permission for that exact
  operation; selecting a larger profile does not fix an API permission error.
- **Product not enabled:** confirm the organization subscription and beta access.
- **Empty results:** confirm provider credentials, pilot scope, scan/ingest status
  and completion. Missing evidence is not proof of a clean environment.
- **Unknown route or feature disabled:** the backend capability is unavailable in
  this deployment. A new MCP binary or tenant policy cannot enable it.
- **Local scan fails:** see the CodeSec guide for CLI installation and authorized
  scanner image requirements; hosted MCP cannot read your local working copy.

## Entity Pivot

Both Cloud Security profiles include two read-only tools:

- `cloudsec_entity_pivot`: pass `identifier` and optionally `type` and `at`
  (Unix seconds). It resolves User/Host identities, returns the complete candidate
  results, and fetches cards for confirmed, unambiguous matches. `cards` contains
  card responses, preserving `redirect_to` and `index_ready`. `candidates` retains
  detected types, evidence, ambiguity and possible matches. Possible matches are
  unconfirmed and are never followed automatically.
- `cloudsec_entity_activity`: pass `entity_id`, optionally `since`, `until`
  (Unix seconds, at most 30 days), and a `sources` array containing any of `email`,
  `detections`, `sensor`, `cloud`. Omit sources for all four.

For example, ask the assistant to resolve a hostname with
`{"identifier":"host.example","type":"hostname"}`, then inspect activity with
`{"entity_id":"eh_aaaaaaaaaaaaaaaaaaaaaaaaaa","sources":["sensor","cloud"]}`.
Entity IDs come from resolution or search; treat them as opaque.

Entity reads require `cloudsec.get` and Cloud Security enabled. Email activity
also requires `mailsec.get` plus Email Security enabled, detections need
`insight.det.get`, and sensor state needs `sensor.get`. Missing access is reported
per source. `unavailable`, `timeout`, `index_ready:false`, or `truncated:true`
means the answer is incomplete; none establishes absence. Disabled readers
report `feature_disabled`. Use the returned product links with the caller's own
permissions to inspect the full view.

Sighting data needs `insight.evt.get`. Without it, pivot reports
`sightings:"forbidden"` and omits sighting-derived matches and recent activity.
User activity uses confirmed owned hosts; other recently observed hosts need
event-read permission too.

The activity window filters email/detections and the host sightings used to
select sensors; sensor status and open cloud findings describe current state.
Pivot limits card reads to ten with a 30-second overall deadline. A card failure
preserves candidates and adds `card_errors` plus `truncated:true`.
