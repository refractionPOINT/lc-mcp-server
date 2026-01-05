// Package resources provides MCP resources for the LimaCharlie MCP server.
package resources

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// WrapstackContextURI is the URI for the wrapstack context resource.
const WrapstackContextURI = "wrapstack://context"

// ToolRelationship describes a relationship between two tools.
type ToolRelationship struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Type  string `json:"type"`
	Field string `json:"field,omitempty"`
}

// WrapstackContext contains the tool relationships and entry points
// for LLM orchestration.
type WrapstackContext struct {
	Version       string             `json:"version"`
	Relationships []ToolRelationship `json:"relationships"`
	EntryPoints   []string           `json:"entryPoints"`
}

// wrapstackContextData contains the predefined relationships between tools
// that help LLMs understand how to chain tool calls.
var wrapstackContextData = WrapstackContext{
	Version: "1.0",
	Relationships: []ToolRelationship{
		// list_user_orgs provides oid to many tools
		{From: "list_user_orgs", To: "get_sensor_info", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_sensors", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_online_sensors", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "is_online", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "search_hosts", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "run_lcql_query", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_historic_events", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_historic_detections", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "search_iocs", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "batch_search_iocs", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_time_when_sensor_has_data", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_saved_queries", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_saved_query", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "run_saved_query", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "set_saved_query", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_saved_query", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_event_schema", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_event_schemas_batch", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_event_types_with_schemas", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_event_types_with_schemas_for_platform", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_with_platform", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_processes", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_process_modules", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_process_strings", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "yara_scan_process", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "yara_scan_file", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "yara_scan_directory", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "yara_scan_memory", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_network_connections", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_os_version", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_users", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_services", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_drivers", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_autoruns", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_packages", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_registry_keys", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "find_strings", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "dir_list", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "dir_find_hash", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_artifacts", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_artifact", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "isolate_network", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "rejoin_network", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "is_isolated", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "add_tag", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "remove_tag", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_sensor", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "reliable_tasking", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_reliable_tasks", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_installation_keys", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "create_installation_key", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_installation_key", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_cloud_sensors", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_cloud_sensor", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "set_cloud_sensor", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_cloud_sensor", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_detection_rules", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_dr_general_rules", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_dr_general_rule", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "set_dr_general_rule", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_dr_general_rule", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_dr_managed_rules", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_dr_managed_rule", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "set_dr_managed_rule", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_dr_managed_rule", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "validate_dr_rule_components", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_yara_rule", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "set_yara_rule", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_yara_rule", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "validate_yara_rule", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_fp_rules", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_fp_rule", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "set_fp_rule", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_fp_rule", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_mitre_report", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_org_info", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_usage_stats", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_billing_details", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_org_errors", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "dismiss_org_error", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_org_invoice_url", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_outputs", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "add_output", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_output", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_secrets", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_secret", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "set_secret", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_secret", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_lookups", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_lookup", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "set_lookup", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_lookup", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "query_lookup", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_playbooks", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_playbook", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "set_playbook", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_playbook", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_external_adapter", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "set_external_adapter", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_external_adapter", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_extension_configs", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_extension_config", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "set_extension_config", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_extension_config", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "subscribe_to_extension", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "unsubscribe_from_extension", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_rules", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_rule", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "set_rule", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_rule", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_api_keys", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "create_api_key", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_api_key", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "generate_lcql_query", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "generate_dr_rule_detection", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "generate_dr_rule_respond", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "generate_sensor_selector", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "generate_python_playbook", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "generate_detection_summary", Type: "provides", Field: "oid"},
		// list_sensors provides sid to many tools
		{From: "list_sensors", To: "get_sensor_info", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "get_processes", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "get_process_modules", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "get_process_strings", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "yara_scan_process", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "yara_scan_file", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "yara_scan_directory", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "yara_scan_memory", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "get_network_connections", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "get_os_version", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "get_users", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "get_services", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "get_drivers", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "get_autoruns", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "get_packages", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "get_registry_keys", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "find_strings", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "dir_list", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "dir_find_hash", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "list_artifacts", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "get_artifact", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "isolate_network", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "rejoin_network", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "is_isolated", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "add_tag", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "remove_tag", Type: "provides", Field: "sid"},
		{From: "list_sensors", To: "delete_sensor", Type: "provides", Field: "sid"},
		// list_saved_queries provides name
		{From: "list_saved_queries", To: "get_saved_query", Type: "provides", Field: "name"},
		{From: "list_saved_queries", To: "run_saved_query", Type: "provides", Field: "name"},
		{From: "list_saved_queries", To: "delete_saved_query", Type: "provides", Field: "name"},
		// list_installation_keys provides iid
		{From: "list_installation_keys", To: "delete_installation_key", Type: "provides", Field: "iid"},
		// list_cloud_sensors provides name
		{From: "list_cloud_sensors", To: "get_cloud_sensor", Type: "provides", Field: "name"},
		{From: "list_cloud_sensors", To: "delete_cloud_sensor", Type: "provides", Field: "name"},
		// list_dr_general_rules provides name
		{From: "list_dr_general_rules", To: "get_dr_general_rule", Type: "provides", Field: "name"},
		{From: "list_dr_general_rules", To: "delete_dr_general_rule", Type: "provides", Field: "name"},
		// list_dr_managed_rules provides name
		{From: "list_dr_managed_rules", To: "get_dr_managed_rule", Type: "provides", Field: "name"},
		{From: "list_dr_managed_rules", To: "delete_dr_managed_rule", Type: "provides", Field: "name"},
		// get_fp_rules provides name
		{From: "get_fp_rules", To: "get_fp_rule", Type: "provides", Field: "name"},
		{From: "get_fp_rules", To: "delete_fp_rule", Type: "provides", Field: "name"},
		// list_outputs provides name
		{From: "list_outputs", To: "delete_output", Type: "provides", Field: "name"},
		// list_secrets provides name
		{From: "list_secrets", To: "get_secret", Type: "provides", Field: "name"},
		{From: "list_secrets", To: "delete_secret", Type: "provides", Field: "name"},
		// list_lookups provides name
		{From: "list_lookups", To: "get_lookup", Type: "provides", Field: "name"},
		{From: "list_lookups", To: "delete_lookup", Type: "provides", Field: "name"},
		{From: "list_lookups", To: "query_lookup", Type: "provides", Field: "name"},
		// list_playbooks provides name
		{From: "list_playbooks", To: "get_playbook", Type: "provides", Field: "name"},
		{From: "list_playbooks", To: "delete_playbook", Type: "provides", Field: "name"},
		// list_extension_configs provides name
		{From: "list_extension_configs", To: "get_extension_config", Type: "provides", Field: "name"},
		{From: "list_extension_configs", To: "delete_extension_config", Type: "provides", Field: "name"},
		// list_rules provides name
		{From: "list_rules", To: "get_rule", Type: "provides", Field: "name"},
		{From: "list_rules", To: "delete_rule", Type: "provides", Field: "name"},
		// list_api_keys provides name
		{From: "list_api_keys", To: "delete_api_key", Type: "provides", Field: "name"},
		// list_artifacts provides artifact_id
		{From: "list_artifacts", To: "get_artifact", Type: "provides", Field: "artifact_id"},
		// get_org_errors provides error_id
		{From: "get_org_errors", To: "dismiss_org_error", Type: "provides", Field: "error_id"},
		// generate_lcql_query provides query
		{From: "generate_lcql_query", To: "run_lcql_query", Type: "provides", Field: "query"},
		// get_platform_names provides platform
		{From: "get_platform_names", To: "get_event_types_with_schemas_for_platform", Type: "provides", Field: "platform"},
		// Chain relationships
		{From: "generate_dr_rule_detection", To: "validate_dr_rule_components", Type: "chains"},
		{From: "generate_dr_rule_respond", To: "validate_dr_rule_components", Type: "chains"},
		{From: "validate_dr_rule_components", To: "set_dr_general_rule", Type: "chains"},
		{From: "validate_yara_rule", To: "set_yara_rule", Type: "chains"},
		{From: "create_installation_key", To: "list_installation_keys", Type: "chains"},
		{From: "set_saved_query", To: "list_saved_queries", Type: "chains"},
		{From: "add_output", To: "list_outputs", Type: "chains"},
		{From: "set_secret", To: "list_secrets", Type: "chains"},
		{From: "set_lookup", To: "list_lookups", Type: "chains"},
		{From: "set_playbook", To: "list_playbooks", Type: "chains"},
		{From: "set_cloud_sensor", To: "list_cloud_sensors", Type: "chains"},
		{From: "set_dr_general_rule", To: "list_dr_general_rules", Type: "chains"},
		{From: "set_dr_managed_rule", To: "list_dr_managed_rules", Type: "chains"},
		{From: "set_fp_rule", To: "get_fp_rules", Type: "chains"},
		{From: "set_extension_config", To: "list_extension_configs", Type: "chains"},
		{From: "set_rule", To: "list_rules", Type: "chains"},
		{From: "create_api_key", To: "list_api_keys", Type: "chains"},
		{From: "reliable_tasking", To: "list_reliable_tasks", Type: "chains"},
		// Trigger relationships
		{From: "isolate_network", To: "is_isolated", Type: "triggers"},
		{From: "rejoin_network", To: "is_isolated", Type: "triggers"},
		// get_processes provides pid
		{From: "get_processes", To: "get_process_modules", Type: "provides", Field: "pid"},
		{From: "get_processes", To: "get_process_strings", Type: "provides", Field: "pid"},
		{From: "get_processes", To: "yara_scan_process", Type: "provides", Field: "pid"},
		// generate_* chains
		{From: "generate_dr_rule_detection", To: "set_dr_general_rule", Type: "chains"},
		{From: "generate_dr_rule_respond", To: "set_dr_general_rule", Type: "chains"},
		{From: "generate_sensor_selector", To: "list_sensors", Type: "chains"},
		{From: "generate_python_playbook", To: "set_playbook", Type: "chains"},
		// get_online_sensors provides sid
		{From: "get_online_sensors", To: "get_processes", Type: "provides", Field: "sid"},
		{From: "get_online_sensors", To: "get_network_connections", Type: "provides", Field: "sid"},
		{From: "get_online_sensors", To: "get_os_version", Type: "provides", Field: "sid"},
		{From: "get_online_sensors", To: "yara_scan_process", Type: "provides", Field: "sid"},
		{From: "get_online_sensors", To: "yara_scan_file", Type: "provides", Field: "sid"},
		// search_hosts provides sid
		{From: "search_hosts", To: "get_sensor_info", Type: "provides", Field: "sid"},
		{From: "search_hosts", To: "get_processes", Type: "provides", Field: "sid"},
		{From: "search_hosts", To: "isolate_network", Type: "provides", Field: "sid"},
		// get_* provides data for set_*
		{From: "get_cloud_sensor", To: "set_cloud_sensor", Type: "provides", Field: "config"},
		{From: "get_dr_general_rule", To: "set_dr_general_rule", Type: "provides", Field: "rule_data"},
		{From: "get_dr_managed_rule", To: "set_dr_managed_rule", Type: "provides", Field: "rule_data"},
		{From: "get_yara_rule", To: "set_yara_rule", Type: "provides", Field: "rule_content"},
		{From: "get_fp_rule", To: "set_fp_rule", Type: "provides", Field: "rule_data"},
		{From: "get_external_adapter", To: "set_external_adapter", Type: "provides", Field: "config"},
		{From: "get_extension_config", To: "set_extension_config", Type: "provides", Field: "config"},
		{From: "get_playbook", To: "set_playbook", Type: "provides", Field: "playbook_code"},
		{From: "get_lookup", To: "set_lookup", Type: "provides", Field: "lookup_data"},
		{From: "get_secret", To: "set_secret", Type: "provides", Field: "secret_value"},
		{From: "get_saved_query", To: "run_saved_query", Type: "provides", Field: "query"},
		// Schema generation relationships
		{From: "get_event_schema", To: "generate_lcql_query", Type: "provides", Field: "schema"},
		{From: "get_event_types_with_schemas", To: "generate_lcql_query", Type: "provides", Field: "event_types"},
		// list_sensors provides sid for reliable_tasking
		{From: "list_sensors", To: "reliable_tasking", Type: "provides", Field: "sid"},
		// Detection summary generation
		{From: "get_historic_detections", To: "generate_detection_summary", Type: "provides", Field: "detections"},
		{From: "get_detection_rules", To: "generate_detection_summary", Type: "provides", Field: "rules"},
		// Investigation relationships
		{From: "list_investigations", To: "get_investigation", Type: "provides", Field: "investigation_id"},
		{From: "list_investigations", To: "delete_investigation", Type: "provides", Field: "investigation_id"},
		{From: "get_investigation", To: "expand_investigation", Type: "provides", Field: "investigation_id"},
		{From: "get_investigation", To: "set_investigation", Type: "provides", Field: "investigation_data"},
		{From: "set_investigation", To: "list_investigations", Type: "chains"},
		// SOP relationships
		{From: "list_sops", To: "get_sop", Type: "provides", Field: "name"},
		{From: "list_sops", To: "delete_sop", Type: "provides", Field: "name"},
		{From: "get_sop", To: "set_sop", Type: "provides", Field: "content"},
		{From: "set_sop", To: "list_sops", Type: "chains"},
		// Payload relationships
		{From: "get_payload", To: "delete_payload", Type: "provides", Field: "payload_id"},
		{From: "create_payload", To: "get_payload", Type: "chains"},
		// Org notes relationships
		{From: "list_org_notes", To: "get_org_note", Type: "provides", Field: "note_id"},
		{From: "list_org_notes", To: "delete_org_note", Type: "provides", Field: "note_id"},
		{From: "get_org_note", To: "set_org_note", Type: "provides", Field: "note_content"},
		{From: "set_org_note", To: "list_org_notes", Type: "chains"},
		// Sensor tags relationships
		{From: "list_sensor_tags", To: "add_tag", Type: "provides", Field: "tag"},
		{From: "list_sensor_tags", To: "remove_tag", Type: "provides", Field: "tag"},
		// Detection relationships
		{From: "get_detection", To: "generate_detection_summary", Type: "provides", Field: "detection_data"},
		// list_user_orgs provides oid for investigation, SOP, payload, notes, tags, detection, sku
		{From: "list_user_orgs", To: "list_investigations", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_investigation", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "set_investigation", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_investigation", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "expand_investigation", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_sops", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_sop", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "set_sop", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_sop", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "create_payload", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_payload", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_payload", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_org_notes", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_org_note", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "set_org_note", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "delete_org_note", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "list_sensor_tags", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_detection", Type: "provides", Field: "oid"},
		{From: "list_user_orgs", To: "get_sku_definitions", Type: "provides", Field: "oid"},
		// set_external_adapter chains
		{From: "set_external_adapter", To: "get_external_adapter", Type: "chains"},
		// IOC search provides findings for investigation
		{From: "search_iocs", To: "set_investigation", Type: "provides", Field: "ioc_findings"},
		{From: "batch_search_iocs", To: "set_investigation", Type: "provides", Field: "ioc_findings"},
		// Historic data provides data for investigation
		{From: "get_historic_events", To: "expand_investigation", Type: "provides", Field: "event_data"},
		{From: "get_historic_detections", To: "expand_investigation", Type: "provides", Field: "detection_data"},
		// MITRE report provides data for rule generation
		{From: "get_mitre_report", To: "generate_dr_rule_detection", Type: "provides", Field: "mitre_data"},
		// Timestamp range relationships
		{From: "get_time_when_sensor_has_data", To: "get_historic_events", Type: "provides", Field: "timestamp_range"},
		{From: "get_time_when_sensor_has_data", To: "run_lcql_query", Type: "provides", Field: "timestamp_range"},
		// Sensor info provides metadata for investigation
		{From: "get_sensor_info", To: "expand_investigation", Type: "provides", Field: "sensor_metadata"},
		// YARA scan results for investigation
		{From: "yara_scan_process", To: "set_investigation", Type: "provides", Field: "scan_results"},
		{From: "yara_scan_file", To: "set_investigation", Type: "provides", Field: "scan_results"},
		{From: "yara_scan_directory", To: "set_investigation", Type: "provides", Field: "scan_results"},
		{From: "yara_scan_memory", To: "set_investigation", Type: "provides", Field: "scan_results"},
		// Directory and file findings for investigation
		{From: "dir_find_hash", To: "set_investigation", Type: "provides", Field: "file_findings"},
		{From: "dir_list", To: "yara_scan_directory", Type: "provides", Field: "directory_path"},
		// Network and system data for investigation
		{From: "get_network_connections", To: "set_investigation", Type: "provides", Field: "network_data"},
		{From: "get_network_connections", To: "expand_investigation", Type: "provides", Field: "network_data"},
		{From: "get_os_version", To: "set_investigation", Type: "provides", Field: "os_info"},
		{From: "get_users", To: "set_investigation", Type: "provides", Field: "user_data"},
		{From: "get_services", To: "set_investigation", Type: "provides", Field: "service_data"},
		{From: "get_drivers", To: "set_investigation", Type: "provides", Field: "driver_data"},
		{From: "get_autoruns", To: "set_investigation", Type: "provides", Field: "autorun_data"},
		{From: "get_packages", To: "set_investigation", Type: "provides", Field: "package_data"},
		{From: "get_registry_keys", To: "set_investigation", Type: "provides", Field: "registry_data"},
		{From: "get_artifact", To: "set_investigation", Type: "provides", Field: "artifact_data"},
		// Platform relationships
		{From: "list_with_platform", To: "get_event_types_with_schemas_for_platform", Type: "provides", Field: "platform"},
		// Detection data for investigation
		{From: "get_detection", To: "set_investigation", Type: "provides", Field: "detection_data"},
		{From: "get_detection", To: "expand_investigation", Type: "provides", Field: "detection_data"},
		// Selector generation provides selector for tasking
		{From: "generate_sensor_selector", To: "reliable_tasking", Type: "provides", Field: "selector"},
		// String findings for investigation
		{From: "find_strings", To: "set_investigation", Type: "provides", Field: "string_findings"},
		{From: "get_process_strings", To: "set_investigation", Type: "provides", Field: "string_data"},
		{From: "get_process_modules", To: "set_investigation", Type: "provides", Field: "module_data"},
	},
	EntryPoints: []string{
		"list_user_orgs",
		"get_platform_names",
	},
}

// NewWrapstackContextResource creates the wrapstack context resource definition.
func NewWrapstackContextResource() mcp.Resource {
	return mcp.NewResource(
		WrapstackContextURI,
		"Tool Relationships Context",
		mcp.WithResourceDescription("Describes relationships between LimaCharlie MCP tools to help LLMs understand how to chain tool calls effectively."),
		mcp.WithMIMEType("application/json"),
	)
}

// WrapstackContextHandler handles requests for the wrapstack context resource.
func WrapstackContextHandler(_ context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	jsonData, err := json.Marshal(wrapstackContextData)
	if err != nil {
		return nil, err
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      WrapstackContextURI,
			MIMEType: "application/json",
			Text:     string(jsonData),
		},
	}, nil
}

// AddResourcesToServer adds all resources to the MCP server.
func AddResourcesToServer(s *server.MCPServer) {
	s.AddResource(NewWrapstackContextResource(), WrapstackContextHandler)
}
