# Go MCP Server Implementation Status

## Completed Work

### ✅ Hive-Based Tools (30 tools) - COMPLETE
All hive-based configuration tools have been implemented in `internal/tools/hive/`:

**Playbooks (4 tools):**
- `list_playbooks` - ✅ playbooks.go
- `get_playbook` - ✅ playbooks.go
- `set_playbook` - ✅ playbooks.go
- `delete_playbook` - ✅ playbooks.go

**Saved Queries (5 tools):**
- `list_saved_queries` - ✅ saved_queries.go
- `get_saved_query` - ✅ saved_queries.go
- `set_saved_query` - ✅ saved_queries.go
- `delete_saved_query` - ✅ saved_queries.go
- `run_saved_query` - ✅ saved_queries.go

**Cloud Sensors (4 tools):**
- `list_cloud_sensors` - ✅ cloud_sensors.go
- `get_cloud_sensor` - ✅ cloud_sensors.go
- `set_cloud_sensor` - ✅ cloud_sensors.go
- `delete_cloud_sensor` - ✅ cloud_sensors.go

**External Adapters (4 tools):**
- `list_external_adapters` - ✅ external_adapters.go
- `get_external_adapter` - ✅ external_adapters.go
- `set_external_adapter` - ✅ external_adapters.go
- `delete_external_adapter` - ✅ external_adapters.go

**Extension Configs (4 tools):**
- `list_extension_configs` - ✅ extension_configs.go
- `get_extension_config` - ✅ extension_configs.go
- `set_extension_config` - ✅ extension_configs.go
- `delete_extension_config` - ✅ extension_configs.go

**Generic Hive Operations (4 tools):**
- `list_rules` - ✅ generic_hive.go
- `get_rule` - ✅ generic_hive.go
- `set_rule` - ✅ generic_hive.go
- `delete_rule` - ✅ generic_hive.go

**Common:**
- ✅ common.go - Helper functions

## Remaining Work

### 🚧 Forensics Tools (14 tools) - STARTED
Need to complete `internal/tools/forensics/forensics.go` with:

**Process Investigation (3 tools):**
- `get_process_modules` - Command: `os_processes --pid {pid}`
- `get_process_strings` - Command: `mem_strings --pid {pid}`
- `find_strings` - Command: `mem_find_string` with string list

**System Information (5 tools):**
- `get_packages` - Command: `os_packages`
- `get_services` - Command: `os_services`
- `get_autoruns` - Command: `os_autoruns`
- `get_drivers` - Command: `os_drivers`
- `get_users` - Command: `os_users`

**Registry (1 tool):**
- `get_registry_keys` - Command: `reg_list {path}`

**Historical Events (1 tool):**
- `get_historic_events` - Use: `org.GetHistoricEvents()`

**YARA Scanning (4 tools):**
- `yara_scan_process` - Command: `yara_scan {rule} --pid {pid}`
- `yara_scan_file` - Command: `yara_scan {rule} --filePath {path}`
- `yara_scan_directory` - Command: `yara_scan {rule} --root-dir {dir} --file-exp {exp} --depth {d}`
- `yara_scan_memory` - Command: `yara_scan {rule} --processExpr {expr}`

### ⏳ Artifacts Tools (2 tools)
Create `internal/tools/artifacts/artifacts.go`:
- `get_artifact` - Use: `org.ExportArtifact()`
- `list_artifacts` - Use: API call to `/insight/{oid}/artifacts`

### ⏳ Investigation Tools (2 tools)
Add to `internal/tools/investigation/`:
- `batch_search_iocs` - Use: `org.InsightObjectsBatch()`
- `delete_sensor` - Use: `sensor.Delete()`

### ⏳ Admin Tools (3 tools)
Add to `internal/tools/admin/`:
- `get_sku_definitions` - API call to `/billing/sku`
- `reliable_tasking` - API call to reliable tasking endpoint
- `list_reliable_tasks` - API call to reliable tasking endpoint

### ⏳ AI Tools (6 tools) with Gemini
Create `internal/tools/ai/`:
- `generate_dr_rule_detection` - Gemini API
- `generate_dr_rule_respond` - Gemini API
- `generate_lcql_query` - Gemini API
- `generate_detection_summary` - Gemini API
- `generate_python_playbook` - Gemini API
- `generate_sensor_selector` - Gemini API

**Gemini Configuration (from Python):**
- Model: `gemini-2.0-flash-exp` (or `gemini-1.5-flash-002` fallback)
- API Key: `GEMINI_API_KEY` environment variable
- Retry count: `LLM_YAML_RETRY_COUNT` (default: 10)
- Features: JSON mode, schema validation, retry logic

### ⏳ Infrastructure
1. **Import new packages** in `cmd/server/main.go`:
   ```go
   _ "github.com/refractionpoint/lc-mcp-go/internal/tools/hive"
   _ "github.com/refractionpoint/lc-mcp-go/internal/tools/forensics"
   _ "github.com/refractionpoint/lc-mcp-go/internal/tools/artifacts"
   _ "github.com/refractionpoint/lc-mcp-go/internal/tools/ai"
   ```

2. **Add dependencies** to `go.mod`:
   ```
   github.com/google/generative-ai-go
   ```

3. **Configuration** in `internal/config/config.go`:
   - Add `GeminiAPIKey` field
   - Add `GeminiModel` field (default: "gemini-2.0-flash-exp")
   - Add `LLMRetryCount` field (default: 10)

### ⏳ Testing
Create comprehensive tests:
- `internal/tools/hive/*_test.go` - Hive tool tests
- `internal/tools/forensics/forensics_test.go` - Forensics tests
- `internal/tools/ai/ai_test.go` - AI tool tests

## Implementation Notes

### SDK Compatibility
All tools use the Go SDK (`feature/mcp-missing-methods` branch) which provides:
- ✅ `org.Hive()` for hive operations
- ✅ `sensor.SimpleRequest()` for sensor commands
- ✅ `org.Query()` for LCQL queries
- ✅ `org.InsightObjects()` / `InsightObjectsBatch()` for IOC search
- ✅ `org.HistoricalDetections()` for detection history
- ✅ `org.GetHistoricEvents()` for event history

### Tool Patterns
1. **Hive Tools**: All use same pattern with different `HiveName`:
   - Playbooks: `"playbook"`
   - Queries: `"query"`
   - Cloud sensors: `"cloud_sensor"`
   - Adapters: `"external_adapter"`
   - Extensions: `"extension_config"`
   - Lookups: `"lookup"`

2. **Forensics Tools**: All use `sensor.SimpleRequest(command)` pattern

3. **AI Tools**: Use Gemini API with retry logic and JSON schema validation

### File Structure
```
internal/tools/
├── hive/
│   ├── common.go ✅
│   ├── playbooks.go ✅
│   ├── saved_queries.go ✅
│   ├── cloud_sensors.go ✅
│   ├── external_adapters.go ✅
│   ├── extension_configs.go ✅
│   └── generic_hive.go ✅
├── forensics/
│   ├── common.go ✅
│   └── forensics.go (needs completion)
├── artifacts/
│   └── artifacts.go (to create)
├── ai/
│   ├── common.go (to create)
│   ├── gemini.go (to create)
│   ├── rules.go (to create)
│   └── queries.go (to create)
├── investigation/ (existing, add tools)
├── admin/ (existing, add tools)
└── ...
```

## Command Reference for Forensics Tools

| Tool | SDK Call | Command/Method |
|------|----------|----------------|
| get_process_modules | `sensor.SimpleRequest()` | `os_processes --pid {pid}` |
| get_process_strings | `sensor.SimpleRequest()` | `mem_strings --pid {pid}` |
| find_strings | `sensor.SimpleRequest()` | `mem_find_string` + params |
| get_packages | `sensor.SimpleRequest()` | `os_packages` |
| get_services | `sensor.SimpleRequest()` | `os_services` |
| get_autoruns | `sensor.SimpleRequest()` | `os_autoruns` |
| get_drivers | `sensor.SimpleRequest()` | `os_drivers` |
| get_users | `sensor.SimpleRequest()` | `os_users` |
| get_registry_keys | `sensor.SimpleRequest()` | `reg_list {path}` |
| get_historic_events | `org.GetHistoricEvents()` | Direct SDK method |
| yara_scan_process | `sensor.SimpleRequest()` | `yara_scan {rule} --pid {pid}` |
| yara_scan_file | `sensor.SimpleRequest()` | `yara_scan {rule} --filePath {path}` |
| yara_scan_directory | `sensor.SimpleRequest()` | `yara_scan {rule} --root-dir {dir} --file-exp {exp} --depth {d}` |
| yara_scan_memory | `sensor.SimpleRequest()` | `yara_scan {rule} --processExpr {expr}` |

## Next Steps

1. ✅ Complete 30 hive-based tools
2. 🚧 Complete 14 forensics tools in `forensics/forensics.go`
3. ⏳ Create 2 artifact tools in `artifacts/artifacts.go`
4. ⏳ Add 2 investigation tools to existing package
5. ⏳ Add 3 admin tools to existing package
6. ⏳ Create 6 AI tools with Gemini integration in `ai/` package
7. ⏳ Update `cmd/server/main.go` with new imports
8. ⏳ Add Gemini dependency and configuration
9. ⏳ Create comprehensive tests
10. ⏳ Test end-to-end with Python comparison

## Deployment Checklist

Before deployment:
- [ ] All 53 tools implemented
- [ ] All tools registered in init()
- [ ] All packages imported in main.go
- [ ] Gemini API key configuration added
- [ ] Tests created (even if can't run locally)
- [ ] Documentation updated
- [ ] Compare with Python tool list for completeness

## Current Status

**Implemented**: 30/53 tools (57%)
**In Progress**: Forensics tools (14 tools)
**Remaining**: 23 tools (AI + artifacts + misc)

All hive-based configuration management is complete and ready for testing.
