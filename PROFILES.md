# LimaCharlie MCP Server - Tool Profiles

This document describes the available tool profiles and their contents.

## What are Profiles?

Profiles are curated sets of tools designed for specific use cases. Using profiles allows you to:
- Reduce cognitive load on AI agents by exposing only relevant tools
- Create security boundaries by restricting access to specific functionality
- Optimize performance by loading smaller tool sets

## Available Profiles

### `all` (Default)
Includes all available tools from all profiles. Use this when you need full functionality.

**Tool Count**: 115+ tools

### `core` - Basic Sensor Operations
Essential sensor management and information retrieval tools.

**Tools** (6):
- `test_tool` - Server connectivity check
- `get_sensor_info` - Detailed sensor information
- `list_sensors` - List all sensors
- `get_online_sensors` - Filter online sensors only
- `is_online` - Check single sensor status
- `search_hosts` - Search by hostname/IP

**Use Cases**:
- Basic sensor management
- Sensor discovery and monitoring
- Health checks

### `historical_data` - Telemetry & Analysis
Query and analyze historical security data and events.

**Tools** (12):
- `run_lcql_query` - LimaCharlie Query Language
- `get_historic_events` - Historical event retrieval
- `get_historic_detections` - Detection history
- `search_iocs` - Search IOCs/artifacts
- `batch_search_iocs` - Batch IOC searches
- `get_time_when_sensor_has_data` - Sensor timeline
- `get_event_schema` - Event schema definitions
- `get_event_schemas_batch` - Multiple schemas
- `get_event_types_with_schemas` - All event types
- `get_event_types_with_schemas_for_platform` - Platform-specific events
- `get_platform_names` - Platform ontology
- `list_with_platform` - List sensors by platform

**Use Cases**:
- Threat hunting
- Historical analysis
- IOC investigation
- Schema exploration

### `historical_data_readonly` - Read-Only Historical Data
Same as `historical_data` but conceptually read-only (no mutations).

**Tools**: Same as `historical_data` (12 tools)

**Use Cases**:
- Audit and compliance reporting
- Read-only analyst access
- External integrations

### `live_investigation` - Real-Time Endpoint Analysis
Live forensics and investigation capabilities on running endpoints.

**Tools** (18):
- `get_processes` - Running processes
- `get_process_modules` - Process memory modules
- `get_process_strings` - Memory string extraction
- `find_strings` - String search in memory
- `get_network_connections` - Network connections
- `get_os_version` - OS information
- `get_users` - System users
- `get_services` - Running services
- `get_drivers` - System drivers
- `get_autoruns` - Autorun entries
- `get_packages` - Installed packages
- `get_registry_keys` - Windows registry queries
- `yara_scan_process` - YARA process scanning
- `yara_scan_file` - YARA file scanning
- `yara_scan_directory` - YARA directory scanning
- `yara_scan_memory` - YARA memory scanning
- `list_artifacts` - List collected artifacts
- `get_artifact` - Download artifacts

**Use Cases**:
- Incident response
- Live forensics
- Malware analysis
- Endpoint investigation

### `threat_response` - Incident Response
Active threat mitigation and response actions.

**Tools** (8):
- `isolate_network` - Network isolation
- `rejoin_network` - Restore network access
- `is_isolated` - Check isolation status
- `add_tag` - Tag sensors
- `remove_tag` - Remove tags
- `delete_sensor` - Delete sensor permanently
- `reliable_tasking` - Persistent task sending
- `list_reliable_tasks` - List pending tasks

**Use Cases**:
- Incident containment
- Threat mitigation
- Emergency response
- Sensor management

### `fleet_management` - Sensor Deployment & Management
Large-scale sensor deployment and configuration.

**Tools** (9):
- `list_installation_keys` - List installation keys
- `create_installation_key` - Create new installation key
- `delete_installation_key` - Delete installation key
- `list_cloud_sensors` - Cloud sensors (hive-based)
- `get_cloud_sensor` - Get cloud sensor config
- `set_cloud_sensor` - Configure cloud sensor
- `delete_cloud_sensor` - Delete cloud sensor
- `get_platform_names` - Platform ontology
- `list_with_platform` - List sensors by platform

**Use Cases**:
- Sensor deployment
- Fleet-wide configuration
- Cloud workload protection
- Platform management

### `detection_engineering` - Rules & Detection Logic
Create and manage detection and response rules.

**Tools** (19):
- `get_detection_rules` - List detection rules
- **D&R General Rules**: `list`, `get`, `set`, `delete`
- **D&R Managed Rules**: `list`, `get`, `set`, `delete`
- **YARA Rules**: `list`, `get`, `set`, `delete`, `validate`
- **False Positive Rules**: `get`, `get_fp_rule`, `set`, `delete`
- `get_mitre_report` - MITRE ATT&CK coverage
- **Event Schemas**: `get_event_schema`, `get_event_schemas_batch`, `get_event_types_with_schemas`, `get_event_types_with_schemas_for_platform`

**Use Cases**:
- Detection rule creation
- Rule tuning and testing
- False positive management
- MITRE ATT&CK coverage analysis

### `platform_admin` - Complete Platform Control
Full administrative access to all organization features.

**Tools** (44):
- **Organization**: 9 tools (info, usage, billing, errors, invoices, SKU, create, list user orgs)
- **Outputs**: 3 tools (list, add, delete)
- **Secrets**: 4 tools (list, get, set, delete)
- **Lookups**: 5 tools (list, get, set, delete, query)
- **Playbooks**: 4 tools (list, get, set, delete)
- **External Adapters**: 4 tools (list, get, set, delete)
- **Extensions**: 6 tools (list, get, set, delete, subscribe, unsubscribe)
- **Hive Rules**: 4 tools (list, get, set, delete)
- **Saved Queries**: 4 tools (list, get, set, delete)
- **API Keys**: 3 tools (list, create, delete)

**Use Cases**:
- Platform administration
- Integration management
- Billing and usage monitoring
- Multi-organization management

### `ai_powered` - AI-Assisted Generation (Coming Soon)
AI-powered tools for automated content generation using Google Gemini.

**Planned Tools** (6):
- `generate_lcql_query` - AI-generated queries
- `generate_dr_rule_detection` - AI-generated detection rules
- `generate_dr_rule_respond` - AI-generated response rules
- `generate_sensor_selector` - AI-generated selectors
- `generate_python_playbook` - AI-generated playbooks
- `generate_detection_summary` - AI-generated summaries

**Status**: Deferred for future release

**Use Cases**:
- Automated rule creation
- Query assistance
- Playbook generation
- Detection summarization

## Profile Selection

### STDIO Mode (Claude Desktop/Code)
Set the `MCP_PROFILE` environment variable:

```bash
export MCP_PROFILE=core              # Core tools only
export MCP_PROFILE=historical_data   # Historical analysis
export MCP_PROFILE=all               # All tools (default)
```

### HTTP Mode
Profile is selected via URL path:

```
/mcp/                          # Default "all" profile
/core/                         # Core profile
/historical_data/              # Historical data profile
/live_investigation/           # Live investigation profile
/threat_response/              # Threat response profile
/fleet_management/             # Fleet management profile
/detection_engineering/        # Detection engineering profile
/platform_admin/               # Platform admin profile
```

## Tool Coverage by Profile

| Feature Area | Core | Historical | Live Inv | Threat Resp | Fleet Mgmt | Detection Eng | Platform Admin |
|--------------|------|------------|----------|-------------|------------|---------------|----------------|
| Sensor Info | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| Event Schemas | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| LCQL Queries | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Live Forensics | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Network Isolation | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| D&R Rules | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| Secrets/Lookups | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| API Keys | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

## Choosing the Right Profile

**For Security Analysts**:
- Start with `historical_data` for threat hunting
- Add `live_investigation` for active incidents
- Add `threat_response` for containment actions

**For Detection Engineers**:
- Use `detection_engineering` for rule creation
- Add `historical_data` for testing queries

**For Platform Administrators**:
- Use `platform_admin` for full control
- Add specific profiles as needed for operators

**For SOC Operations**:
- Use `all` profile for maximum flexibility
- Or combine `historical_data` + `threat_response`

**For Automation/CI/CD**:
- Use minimal profiles (e.g., `historical_data_readonly`)
- Avoid `platform_admin` in automated contexts

## Security Considerations

1. **Principle of Least Privilege**: Use the most restrictive profile that meets your needs
2. **Read-Only Access**: Use `historical_data_readonly` for analysis-only use cases
3. **Isolation**: `threat_response` profile includes network isolation - use carefully
4. **Deletion**: `threat_response` and `platform_admin` include deletion capabilities
5. **Multi-Org**: In UID mode, tools require `oid` parameter for each call

## Profile Implementation

Profiles are defined in `/internal/tools/registry.go`:

```go
var ProfileDefinitions = map[string][]string{
    "core": {"test_tool", "get_sensor_info", ...},
    "historical_data": {"run_lcql_query", ...},
    // ... other profiles
}
```

Each tool is registered with a `Profile` field:

```go
tools.RegisterTool(&tools.ToolRegistration{
    Name: "get_sensor_info",
    Profile: "core",
    RequiresOID: true,
    // ... other fields
})
```
