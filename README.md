# LimaCharlie MCP Server

## Overview

The Model Context Protocol (MCP) is a standardized protocol used by AI Agents to access and leverage external tools and resources. Note that MCP itself is still experimental and cutting edge.

LimaCharlie offers an MCP server at https://mcp.limacharlie.io which enables AI agents to:

- **Query and analyze** historical telemetry from any sensor
- **Actively investigate** endpoints using the LimaCharlie Agent (EDR) in real-time
- **Take remediation actions** like isolating endpoints, killing processes, and managing tags
- **Generate content** using AI-powered tools for LCQL queries, D&R rules, playbooks, and detection summaries
- **Manage platform configuration** including rules, outputs, adapters, secrets, and more
- **Access threat intelligence** through IOC searches and MITRE ATT&CK mappings

This opens up the entire LimaCharlie platform to AI agents, regardless of their implementation or location.

## Transport Modes

The server supports two transport modes based on the `PUBLIC_MODE` environment variable:

### STDIO Mode (PUBLIC_MODE=false, default)
Used for local MCP clients like Claude Desktop or Claude Code:
- Communication through stdin/stdout using JSON-RPC
- Perfect for local development and single-user scenarios
- Uses LimaCharlie SDK's default authentication
- Reads credentials from environment variables or config files
- Run directly with: `python3 server.py`

### HTTP Mode (PUBLIC_MODE=true)
Used when deploying as a public service (e.g., at mcp.limacharlie.io):
- Server runs as a stateless HTTP API with JSON responses
- Authentication via HTTP headers
- Supports multiple organizations concurrently
- Run with: `uvicorn server:app`

## Profile System

The MCP server supports **profiles** to reduce cognitive load on AI agents by providing focused tool subsets. With over 100 tools available, profiles allow you to expose only relevant capabilities for specific workflows.

### Available Profiles

#### **all** (Default)
All 100+ tools available. Best for general-purpose usage.
- **STDIO**: No `MCP_PROFILE` variable needed (default behavior)
- **HTTP**: `https://mcp.limacharlie.io/mcp`

#### **historical_data**
Historical telemetry analysis and LCQL queries (18 tools).
Perfect for threat hunting and historical investigations.
- LCQL queries, historic events, historic detections
- Artifact management, IOC searches
- Event schemas and platform information
- **STDIO**: `MCP_PROFILE=historical_data`
- **HTTP**: `https://mcp.limacharlie.io/historical_data`

#### **live_investigation**
Real-time endpoint investigation (24 tools).
For active IR and live forensics.
- Process inspection (modules, strings, memory)
- System information (packages, services, users, network)
- YARA scanning (process, file, directory, memory)
- Reliable tasking for investigations
- **STDIO**: `MCP_PROFILE=live_investigation`
- **HTTP**: `https://mcp.limacharlie.io/live_investigation`

#### **threat_response**
Incident response actions (8 tools).
For taking remediation actions on endpoints.
- Network isolation (isolate, rejoin, check status)
- Sensor tagging and deletion
- Reliable tasking for response actions
- **STDIO**: `MCP_PROFILE=threat_response`
- **HTTP**: `https://mcp.limacharlie.io/threat_response`

#### **fleet_management**
Sensor and deployment management (13 tools).
For managing your sensor fleet.
- Sensor management (list, info, tags, deletion)
- Installation keys (create, list, delete)
- Cloud sensors (CSPM integration)
- Platform information
- **STDIO**: `MCP_PROFILE=fleet_management`
- **HTTP**: `https://mcp.limacharlie.io/fleet_management`

#### **detection_engineering**
D&R rules and detection development (21 tools).
For building and managing detections.
- D&R rules (general and managed)
- False positive rules
- YARA rules and validation
- MITRE ATT&CK coverage reports
- Event schemas for rule development
- **STDIO**: `MCP_PROFILE=detection_engineering`
- **HTTP**: `https://mcp.limacharlie.io/detection_engineering`

#### **ai_powered**
AI-powered content generation (6 tools).
For generating LCQL, rules, and playbooks with AI assistance.
- Generate LCQL queries
- Generate D&R rules (detection and response)
- Generate sensor selectors
- Generate Python playbooks
- Generate detection summaries
- **STDIO**: `MCP_PROFILE=ai_powered`
- **HTTP**: `https://mcp.limacharlie.io/ai_powered`

#### **platform_admin**
Platform configuration and administration (31 tools).
For configuring outputs, lookups, secrets, and more.
- Outputs, lookups, secrets management
- Playbooks, external adapters, extensions
- Hive rules, saved queries
- API keys and organization info
- **STDIO**: `MCP_PROFILE=platform_admin`
- **HTTP**: `https://mcp.limacharlie.io/platform_admin`

### Core Tools

All profiles include these 6 core tools:
- `test_tool` - Verify MCP connectivity
- `get_sensor_info` - Get detailed sensor information
- `list_sensors` - List sensors in organization
- `get_online_sensors` - List currently online sensors
- `is_online` - Check if sensor is online
- `search_hosts` - Search sensors by hostname

### Profile Selection

**STDIO Mode (Claude Desktop/Code):**
Set the `MCP_PROFILE` environment variable in your configuration:
```json
{
  "mcpServers": {
    "limacharlie-historical": {
      "command": "python3",
      "args": ["/path/to/server.py"],
      "env": {
        "MCP_PROFILE": "historical_data",
        "LC_OID": "your-org-id",
        "LC_API_KEY": "your-api-key"
      }
    }
  }
}
```

**HTTP Mode:**
Use profile-specific URLs:
```bash
# Historical data profile
claude mcp add limacharlie-historical https://mcp.limacharlie.io/historical_data \
  --header "Authorization: Bearer API_KEY:OID"

# Live investigation profile
claude mcp add limacharlie-live https://mcp.limacharlie.io/live_investigation \
  --header "Authorization: Bearer API_KEY:OID"
```

### Benefits

- **Reduced Context**: Fewer tools mean less cognitive load for AI agents
- **Focused Workflows**: Each profile is optimized for specific use cases
- **Better Performance**: Smaller tool sets lead to faster tool selection
- **Backward Compatible**: No profile specified = all tools (existing configs work unchanged)

## Requirements & Authentication

### For HTTP Mode

The server requires authentication headers:

1. **Authorization header** in one of these formats:
   - `Authorization: Bearer <jwt>` (OID must be in x-lc-oid header)
   - `Authorization: Bearer <jwt>:<oid>` (combined format)
   - `Authorization: Bearer <api_key>:<oid>` (API key with OID)

2. **x-lc-oid header** (if not included in Authorization):
   - `x-lc-oid: <organization_id>`

### For STDIO Mode

Set environment variables:
- `LC_OID`: Your LimaCharlie Organization ID
- `LC_API_KEY`: Your LimaCharlie API key
- `MCP_PROFILE`: Profile to load (default: `all`). Options: `historical_data`, `live_investigation`, `threat_response`, `fleet_management`, `detection_engineering`, `ai_powered`, `platform_admin`
- `GOOGLE_API_KEY`: For AI-powered generation features (optional)

## Quick Start

### For Claude Desktop/Code (STDIO Mode)
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Set environment variables:
   ```bash
   export PUBLIC_MODE=false
   export MCP_PROFILE=all  # Or choose a specific profile
   export GOOGLE_API_KEY=your-api-key
   export LC_OID=your-org-id
   export LC_API_KEY=your-lc-api-key
   ```

3. Run the server:
   ```bash
   python3 server.py
   ```

4. Configure Claude Desktop (see `claude-desktop-config.json` for example)

### For HTTP Deployment
1. Set `PUBLIC_MODE=true`
2. Run with uvicorn:
   ```bash
   uvicorn server:app --host 0.0.0.0 --port 8000
   ```

### HTTP Service Usage
```bash
# Default (all tools)
claude mcp add --transport http limacharlie https://mcp.limacharlie.io/mcp \
  --header "Authorization: Bearer API_KEY:OID" \
  --header "x-lc-oid: OID"

# Using a specific profile (e.g., historical_data)
claude mcp add --transport http limacharlie-historical https://mcp.limacharlie.io/historical_data \
  --header "Authorization: Bearer API_KEY:OID"
```

## Capabilities

The LimaCharlie MCP server exposes over 100 tools organized by category:

### Investigation & Telemetry
- **Process inspection**: `get_processes`, `get_process_modules`, `get_process_strings`, `yara_scan_process`
- **System information**: `get_os_version`, `get_users`, `get_services`, `get_drivers`, `get_autoruns`, `get_packages`
- **Network analysis**: `get_network_connections`, `is_online`, `get_online_sensors`
- **File operations**: `find_strings`, `yara_scan_file`, `yara_scan_directory`, `yara_scan_memory`
- **Registry access**: `get_registry_keys`
- **Historical data**: `get_historic_events`, `get_historic_detections`, `get_time_when_sensor_has_data`

### Threat Response & Remediation
- **Network isolation**: `isolate_network`, `rejoin_network`, `is_isolated`
- **Sensor management**: `add_tag`, `remove_tag`, `delete_sensor`
- **Reliable tasking**: `reliable_tasking`, `list_reliable_tasks`

### AI-Powered Generation (requires GOOGLE_API_KEY)
- **Query generation**: `generate_lcql_query` - Create LCQL queries from natural language
- **Rule creation**: `generate_dr_rule_detection`, `generate_dr_rule_respond` - Generate D&R rules
- **Automation**: `generate_python_playbook` - Create Python playbooks
- **Analysis**: `generate_detection_summary` - Summarize detection data
- **Sensor selection**: `generate_sensor_selector` - Generate sensor selectors

### Platform Configuration
- **Detection & Response**: `get_detection_rules`, `set_dr_general_rule`, `set_dr_managed_rule`, `delete_dr_general_rule`, `delete_dr_managed_rule`, `list_dr_general_rules`, `list_dr_managed_rules`, `get_dr_general_rule`, `get_dr_managed_rule`
- **False Positive Management**: `get_fp_rules`, `get_fp_rule`, `set_fp_rule`, `delete_fp_rule`
- **YARA Rules**: `list_yara_rules`, `get_yara_rule`, `set_yara_rule`, `validate_yara_rule`, `delete_yara_rule`
- **Outputs & Adapters**: `list_outputs`, `add_output`, `delete_output`, `list_external_adapters`, `get_external_adapter`, `set_external_adapter`, `delete_external_adapter`
- **Extensions**: `list_extension_configs`, `get_extension_config`, `set_extension_config`, `delete_extension_config`
- **Playbooks**: `list_playbooks`, `get_playbook`, `set_playbook`, `delete_playbook`
- **Secrets Management**: `list_secrets`, `get_secret`, `set_secret`, `delete_secret`
- **Saved Queries**: `list_saved_queries`, `get_saved_query`, `set_saved_query`, `delete_saved_query`, `run_saved_query`
- **Lookups**: `list_lookups`, `get_lookup`, `set_lookup`, `query_lookup`, `delete_lookup`
- **Rules**: `list_rules`, `get_rule`, `set_rule`, `delete_rule`

### Threat Intelligence
- **IOC Search**: `search_iocs`, `batch_search_iocs`
- **Host Search**: `search_hosts`
- **MITRE ATT&CK**: `get_mitre_report`

### Administrative
- **API Keys**: `list_api_keys`, `create_api_key`, `delete_api_key`
- **Installation Keys**: `list_installation_keys`, `create_installation_key`, `delete_installation_key`
- **Cloud Sensors**: `list_cloud_sensors`, `get_cloud_sensor`, `set_cloud_sensor`, `delete_cloud_sensor`
- **Organization Info**: `get_org_info`, `get_usage_stats`
- **Artifacts**: `list_artifacts`, `get_artifact`
- **Sensor Info**: `get_sensor_info`, `list_sensors`

### Schema & Documentation
- **Event Schemas**: `get_event_schema`, `get_event_schemas_batch`, `get_event_types_with_schemas`, `get_event_types_with_schemas_for_platform`
- **Platform Support**: `get_platform_names`, `list_with_platform`

## Advanced Features

### Large Result Handling
The server automatically handles large responses by uploading them to Google Cloud Storage (if configured):
- Set `GCS_BUCKET_NAME` for the storage bucket
- Configure `GCS_TOKEN_THRESHOLD` (default: 1000 tokens)
- Results are returned as signed URLs valid for 24 hours

### LCQL Query Execution
The `run_lcql_query` tool supports:
- Streaming results for real-time monitoring
- Flexible time windows and limits
- Output formatting options

## Environment Variables

- `PUBLIC_MODE` - Set to `true` for HTTP mode, `false` for STDIO (default: `false`)
- `MCP_PROFILE` - Profile to load (default: `all`). Options: `all`, `historical_data`, `live_investigation`, `threat_response`, `fleet_management`, `detection_engineering`, `ai_powered`, `platform_admin`
- `GOOGLE_API_KEY` - API key for AI-powered features
- `GCS_BUCKET_NAME` - Google Cloud Storage bucket for large results (optional)
- `GCS_SIGNER_SERVICE_ACCOUNT` - Service account for GCS URL signing (optional)
- `GCS_TOKEN_THRESHOLD` - Token count threshold for GCS upload (default: 1000)
- `GCS_URL_EXPIRY_HOURS` - Hours until GCS URLs expire (default: 24)
- `LC_OID` - Organization ID (STDIO mode only)
- `LC_API_KEY` - API key (STDIO mode only)

### Audit Logging

- `AUDIT_LOG_ENABLED` - Enable/disable audit logging (default: `true`)
- `AUDIT_LOG_LEVEL` - Minimum severity to log: CRITICAL, HIGH, MEDIUM, LOW (default: `MEDIUM`)
- `AUDIT_LOG_INCLUDE_LOW` - Include LOW severity events (default: `false`)

## Audit Logging

The MCP server includes comprehensive audit logging for security and compliance. All security-relevant operations are automatically logged to stdout as structured JSON events.

### What is Logged

**CRITICAL Severity:**
- Authentication and authorization events
- Destructive operations (all delete operations)
- Credential management (API keys, secrets)
- Network isolation actions (isolate/rejoin endpoints)

**HIGH Severity:**
- Configuration changes (D&R rules, YARA rules, false positive rules)
- Policy modifications (outputs, adapters, extensions)
- Sensor management (tagging, installation keys)
- Detection rule updates

**MEDIUM Severity:**
- Data access operations (LCQL queries, historical data retrieval)
- IOC searches and threat intelligence queries
- Detection retrieval
- List and read operations

**LOW Severity:**
- Metadata operations
- Health checks
- Platform information queries

### What is Never Logged

For security, the following data is **never** logged:
- Function parameters (may contain API keys, secrets, passwords)
- Function responses (may contain sensitive data)
- OAuth tokens or JWT contents
- API keys or secrets values
- Query contents or rule bodies

Only metadata is logged:
- Event type (function name)
- User ID and organization ID
- Timestamp and duration
- Status (success/failure)
- Source IP and user agent
- Generic error types (without details)

### Audit Event Format

```json
{
  "timestamp": "2025-10-26T18:00:00.000Z",
  "event_type": "delete_sensor",
  "severity": "CRITICAL",
  "action": "delete",
  "status": "success",
  "user_id": "uid-xxx",
  "organization_id": "oid-yyy",
  "status_code": 200,
  "request_id": "uuid",
  "source_ip": "1.2.3.4",
  "user_agent": "client/1.0",
  "duration_ms": 123
}
```

### Configuration Examples

**Development (verbose logging):**
```bash
export AUDIT_LOG_ENABLED=true
export AUDIT_LOG_LEVEL=LOW
export AUDIT_LOG_INCLUDE_LOW=true
```

**Production (default - balanced):**
```bash
export AUDIT_LOG_ENABLED=true
export AUDIT_LOG_LEVEL=MEDIUM
```

**High security (only critical events):**
```bash
export AUDIT_LOG_ENABLED=true
export AUDIT_LOG_LEVEL=CRITICAL
```

**Disable audit logging:**
```bash
export AUDIT_LOG_ENABLED=false
```

### Parsing Audit Logs

Audit logs are written to stdout with the prefix `AUDIT:`. To extract and parse:

```bash
# Extract audit logs from server output
grep "AUDIT:" server.log | sed 's/AUDIT: //' > audit.jsonl

# Parse with jq
cat audit.jsonl | jq 'select(.severity == "CRITICAL")'

# Count events by type
cat audit.jsonl | jq -r '.event_type' | sort | uniq -c

# Find failed operations
cat audit.jsonl | jq 'select(.status == "failure")'
```

### Performance

Audit logging is designed for minimal overhead:
- Non-blocking writes to stdout
- Lazy JSON serialization
- No parameter/response serialization
- Average overhead: < 2ms per operation

## Notes

- The server is stateless when running in HTTP mode
- HTTP mode uses JSON responses (not Server-Sent Events)
- No OAuth flow is used - authentication is via bearer tokens only
- If you encounter missing capabilities, contact https://community.limacharlie.com for quick additions

## Resource Profile
This should be mostly network and memory bound. No other external resources.

## Testing Procedure
See `test_deployment.py` for basic deployment testing.

## License
Apache License 2.0 - See LICENSE file for details.
