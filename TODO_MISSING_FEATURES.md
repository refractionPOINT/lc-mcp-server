# Missing Features from Python Implementation

This document tracks features present in the Python implementation that are not yet implemented in the Go version.

**Current Status**: 17/97 tools implemented (~17% feature parity)

---

## 🔴 Priority 1: Core Missing Tools

### Organization Management (13 tools)
- [ ] `create_org` - Create new organization
- [ ] `list_user_orgs` - List organizations accessible to user
- [ ] `get_org_info` - Get organization details
- [ ] `get_org_errors` - Get organization error logs
- [ ] `dismiss_org_error` - Dismiss specific org error
- [ ] `get_billing_details` - Get billing information
- [ ] `get_org_invoice_url` - Get URL for organization invoice
- [ ] `get_usage_stats` - Get organization usage statistics
- [ ] `get_sku_definitions` - Get SKU pricing definitions
- [ ] `get_mitre_report` - Get MITRE ATT&CK coverage report
- [ ] `list_api_keys` - List organization API keys
- [ ] `delete_api_key` - Delete an API key
- [ ] `get_time_when_sensor_has_data` - Get timeline of sensor data availability

### Detection & Response Rules (12 tools)
- [ ] `get_detection_rules` - Get all D&R rules
- [ ] `get_dr_general_rule` - Get specific general D&R rule
- [ ] `list_dr_general_rules` - List all general D&R rules
- [ ] `delete_dr_general_rule` - Delete general D&R rule
- [ ] `get_dr_managed_rule` - Get specific managed D&R rule
- [ ] `list_dr_managed_rules` - List all managed D&R rules
- [ ] `delete_dr_managed_rule` - Delete managed D&R rule
- [ ] `get_fp_rule` - Get specific false positive rule
- [ ] `get_fp_rules` - Get all false positive rules
- [ ] `delete_fp_rule` - Delete false positive rule
- [ ] `validate_dr_rule_components` - Validate D&R rule syntax
- [ ] `get_rule` / `list_rules` / `delete_rule` - Generic hive rule management

### Event Schema Tools (5 tools)
- [ ] `get_event_schema` - Get schema for specific event type
- [ ] `get_event_schemas_batch` - Get multiple event schemas in parallel
- [ ] `get_event_types_with_schemas` - List all event types with schemas
- [ ] `get_event_types_with_schemas_for_platform` - List event types by platform
- [ ] `get_platform_names` - Get list of platform names

---

## 🟡 Priority 2: Forensics & Investigation

### Forensics Tools (11 tools)
- [ ] `get_historic_events` - Get historic events for specific sensor
- [ ] `get_autoruns` - Get autorun registry entries
- [ ] `get_drivers` - Get installed drivers
- [ ] `get_users` - Get system users
- [ ] `get_services` - Get running services
- [ ] `get_packages` - Get installed packages
- [ ] `get_registry_keys` - Get Windows registry keys
- [ ] `get_process_modules` - Get modules loaded by process
- [ ] `get_process_strings` - Get strings from process memory
- [ ] `find_strings` - Find strings in memory
- [ ] `execute_sensor_command` - Execute arbitrary sensor command

### Artifact Management (1 tool)
- [ ] `get_artifact` - Download/get artifact (logs, memory dumps, etc.)

### YARA Scanning (7 tools)
- [ ] `get_yara_rule` - Get specific YARA rule
- [ ] `list_yara_rules` - List all YARA rules
- [ ] `delete_yara_rule` - Delete YARA rule
- [ ] `yara_scan_file` - Scan file with YARA
- [ ] `yara_scan_directory` - Scan directory with YARA
- [ ] `yara_scan_memory` - Scan process memory with YARA
- [ ] `yara_scan_process` - Scan specific process with YARA

---

## 🟢 Priority 3: Configuration Management

### Lookups & Secrets (6 tools)
- [ ] `get_lookup` - Get lookup table
- [ ] `list_lookups` - List all lookup tables
- [ ] `delete_lookup` - Delete lookup table
- [ ] `get_secret` - Get secret value
- [ ] `list_secrets` - List all secrets
- [ ] `delete_secret` - Delete secret

### Installation Keys (2 tools)
- [ ] `list_installation_keys` - List sensor installation keys
- [ ] `delete_installation_key` - Delete installation key

### Extensions (5 tools)
- [ ] `get_extension_config` - Get extension configuration
- [ ] `list_extension_configs` - List all extension configs
- [ ] `delete_extension_config` - Delete extension config
- [ ] `subscribe_to_extension` - Subscribe to extension
- [ ] `unsubscribe_from_extension` - Unsubscribe from extension

### Cloud Sensors (3 tools)
- [ ] `get_cloud_sensor` - Get cloud sensor configuration
- [ ] `list_cloud_sensors` - List all cloud sensors
- [ ] `delete_cloud_sensor` - Delete cloud sensor

### External Adapters (3 tools)
- [ ] `get_external_adapter` - Get adapter configuration
- [ ] `list_external_adapters` - List all external adapters
- [ ] `delete_external_adapter` - Delete external adapter

### Outputs (2 tools)
- [ ] `list_outputs` - List output configurations
- [ ] `delete_output` - Delete output configuration

### Playbooks (3 tools)
- [ ] `get_playbook` - Get specific playbook
- [ ] `list_playbooks` - List all playbooks
- [ ] `delete_playbook` - Delete playbook

### Saved Queries (3 tools)
- [ ] `get_saved_query` - Get specific saved query
- [ ] `list_saved_queries` - List all saved queries
- [ ] `delete_saved_query` - Delete saved query

### Sensor Management (2 tools)
- [ ] `delete_sensor` - Delete sensor from organization
- [ ] `list_with_platform` - List sensors filtered by platform

---

## 🤖 Priority 4: AI-Powered Features

These require integration with an LLM API (Python uses Google Gemini):

- [ ] `generate_lcql_query` - Generate LCQL query from natural language
- [ ] `generate_dr_rule_detection` - Generate D&R detection logic from description
- [ ] `generate_dr_rule_respond` - Generate D&R response actions from description
- [ ] `generate_sensor_selector` - Generate sensor selector expression
- [ ] `generate_python_playbook` - Generate Python playbook code
- [ ] `generate_detection_summary` - Generate human-readable detection summary

**Implementation Notes**:
- Requires LLM API integration (consider: OpenAI, Anthropic, Google Gemini)
- Python version uses prompt templates in `prompts/` directory
- Need to port/rewrite prompts for Go
- Consider using Claude API (Anthropic) for better security context

---

## 🏗️ Infrastructure Features

### Missing Infrastructure Components

#### 1. Advanced OAuth 2.1 Flow
Python version includes full OAuth flow with web UI:
- [ ] Multi-provider OAuth (Google, Microsoft, GitHub, Firebase)
- [ ] Interactive MFA challenges (TOTP, SMS)
- [ ] Token encryption at rest
- [ ] Rate limiting for OAuth endpoints
- [ ] CSRF/state management
- [ ] Web UI for provider selection
- [ ] Automatic token refresh

**Files in Python**:
- `oauth_endpoints.py` - HTTP endpoints for OAuth flow
- `oauth_state_manager.py` - State and CSRF management
- `oauth_token_manager.py` - Token lifecycle management
- `oauth_metadata.py` - Provider metadata
- `firebase_auth_bridge.py` - Firebase integration
- `token_encryption.py` - Token encryption utilities
- `rate_limiter.py` - Rate limiting
- `templates/*.html` - OAuth web UI

**Status**: Go version has JWT validation but no interactive OAuth flow

#### 2. Audit Logging
Comprehensive audit trail of all operations:
- [ ] Automatic audit logging with decorator pattern
- [ ] Severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- [ ] Action tracking (CREATE, READ, UPDATE, DELETE, EXECUTE)
- [ ] Request metadata tracking
- [ ] Structured log output

**Files in Python**:
- `audit_logger.py` - Core audit logging
- `audit_decorator.py` - Decorator for automatic audit

**Environment Variables**:
- `AUDIT_LOG_ENABLED` - Enable/disable audit logging
- `AUDIT_LOG_LEVEL` - Minimum severity to log

#### 3. Google Cloud Storage Integration
Automatic storage of large results:
- [ ] Auto-upload responses exceeding token threshold
- [ ] Signed URL generation with expiry
- [ ] Service account authentication
- [ ] Transparent to clients

**Environment Variables**:
- `GCS_BUCKET_NAME` - GCS bucket name
- `GCS_URL_EXPIRY_HOURS` - URL expiration (default: 24h)
- `GCS_TOKEN_THRESHOLD` - Upload threshold (default: 1000 tokens)
- `GCS_SIGNER_SERVICE_ACCOUNT` - Service account for signing

#### 4. HTTP/REST API Mode
Python supports both stdio and HTTP deployment:
- [ ] HTTP/REST endpoints
- [ ] Server-Sent Events (SSE) for streaming
- [ ] Header-based authentication
- [ ] CORS support
- [ ] Web UI integration

**Environment Variables**:
- `PUBLIC_MODE=true` - Enable HTTP mode
- `PORT` - HTTP server port

**Status**: Go version is stdio-only (MCP protocol via stdin/stdout)

---

## 📊 Implementation Roadmap

### Phase 1: Core Tools (Estimated: 2-3 weeks)
Focus on most commonly used features:
1. Organization management (13 tools)
2. D&R rule management (12 tools)
3. Event schema tools (5 tools)
4. Sensor management (2 tools)

**Total**: 32 tools

### Phase 2: Forensics (Estimated: 2-3 weeks)
Incident response and investigation:
1. Forensics tools (11 tools)
2. YARA scanning (7 tools)
3. Artifact management (1 tool)

**Total**: 19 tools

### Phase 3: Configuration (Estimated: 1-2 weeks)
Platform configuration management:
1. Lookups & secrets (6 tools)
2. Extensions (5 tools)
3. Installation keys (2 tools)
4. Cloud sensors (3 tools)
5. External adapters (3 tools)
6. Outputs (2 tools)
7. Playbooks (3 tools)
8. Saved queries (3 tools)

**Total**: 27 tools

### Phase 4: AI Features (Estimated: 1-2 weeks)
AI-powered code generation:
1. Integrate with LLM API
2. Port/rewrite prompts
3. Implement 6 AI generation tools

**Total**: 6 tools

### Phase 5: Infrastructure (Estimated: 2-3 weeks)
Advanced features:
1. Advanced OAuth flow (if needed)
2. Audit logging
3. GCS integration (if needed)
4. HTTP mode (if needed)

---

## 🎯 Tool Categories Progress

| Category | Total | Implemented | Remaining | Progress |
|----------|-------|-------------|-----------|----------|
| Core Operations | 6 | 6 | 0 | ✅ 100% |
| Process & System | 3 | 3 | 0 | ✅ 100% |
| Network Isolation | 3 | 3 | 0 | ✅ 100% |
| Tagging | 2 | 2 | 0 | ✅ 100% |
| Data Queries | 3 | 3 | 0 | ✅ 100% |
| **Organization Mgmt** | 13 | 0 | 13 | 🔴 0% |
| **D&R Rules** | 12 | 0 | 12 | 🔴 0% |
| **Event Schemas** | 5 | 0 | 5 | 🔴 0% |
| **Forensics** | 11 | 0 | 11 | 🔴 0% |
| **YARA Scanning** | 7 | 0 | 7 | 🔴 0% |
| **Lookups & Secrets** | 6 | 0 | 6 | 🔴 0% |
| **Installation Keys** | 2 | 0 | 2 | 🔴 0% |
| **Extensions** | 5 | 0 | 5 | 🔴 0% |
| **Cloud Sensors** | 3 | 0 | 3 | 🔴 0% |
| **External Adapters** | 3 | 0 | 3 | 🔴 0% |
| **Outputs** | 2 | 0 | 2 | 🔴 0% |
| **Playbooks** | 3 | 0 | 3 | 🔴 0% |
| **Saved Queries** | 3 | 0 | 3 | 🔴 0% |
| **Sensor Mgmt** | 2 | 0 | 2 | 🔴 0% |
| **AI Generation** | 6 | 0 | 6 | 🔴 0% |
| **TOTAL** | **97** | **17** | **80** | **17%** |

---

## 📝 Implementation Notes

### Code Organization
When implementing missing tools, follow the existing structure:

```
internal/tools/
├── core/           - Basic operations (already has 17 tools)
├── historical/     - Time-based queries (empty, needs get_historic_events)
├── investigation/  - Forensics tools (empty, needs 11 tools)
├── response/       - Response actions (empty, needs playbooks, etc.)
├── admin/          - NEW: Organization & billing management
├── rules/          - NEW: D&R rule management
├── config/         - NEW: Lookups, secrets, extensions
├── yara/           - NEW: YARA scanning
└── ai/             - NEW: AI-powered generation
```

### SDK Cache Reuse
The existing `internal/auth/sdk_cache.go` should be used for all tools to maintain:
- Credential isolation
- JWT expiration enforcement
- Cache TTL management
- Concurrent access safety

### Testing Requirements
Each new tool should have:
- Unit tests for core logic
- Integration tests with mock SDK (if feasible)
- Example usage in documentation
- Error handling tests

### LimaCharlie SDK Reference
The Go SDK exposes these manager types:
- `limacharlie.Manager` - Organization management
- `limacharlie.Sensor` - Sensor operations
- `limacharlie.Timeline` - Historical queries
- `limacharlie.Replay` - Replay operations
- `limacharlie.Billing` - Billing information

Explore the SDK at: https://github.com/refractionPOINT/go-limacharlie

---

## 🔗 References

- **Python Implementation**: `master` branch, `server.py` (6780 lines)
- **Go Implementation**: `go-port` branch, `internal/tools/` directory
- **LimaCharlie Go SDK**: https://github.com/refractionPOINT/go-limacharlie
- **LimaCharlie API Docs**: https://doc.limacharlie.io/
- **MCP Protocol**: https://modelcontextprotocol.io/

---

**Last Updated**: 2025-10-30
**Tracking PR**: #7
