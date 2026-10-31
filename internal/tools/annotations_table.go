package tools

// toolAnnotations is the classification of every tool the server ships. See
// Annotation for the meaning of each hint. Entries are grouped by tool package;
// the trailing comment gives the reason for the classification.
//
// A new tool MUST add an entry here (TestEveryRegisteredToolIsClassified).
var toolAnnotations = map[string]Annotation{
	// --- admin ---
	"add_group_member":       write().Open(),   // group.AddMember adds an email to members; invite_missing emails an LC invite to an arbitrary external address on every call (no dedupe), so not idempotent and open-world; an existing member is left unchanged by the backend (no role overwrite)
	"add_group_owner":        write().Open(),   // group.AddOwner adds an owner; invite_missing emails an LC invite to an arbitrary external address on every call (no dedupe), so not idempotent and open-world; an existing member is left unchanged by the backend (no role overwrite)
	"add_org_to_group":       write().Idem(),   // group.AddOrg links an org to a group (additive; repeat is no-op)
	"add_org_user":           write().Open(),   // org.AddUser POST orgs/{oid}/users with role; invite_missing emails an LC invite to an arbitrary external address on every call (no dedupe), so not idempotent and open-world; an existing member is left unchanged by the backend (no role overwrite)
	"add_user_permission":    write().Idem(),   // org.AddUserPermission appends one permission (additive, repeat is no-op)
	"create_api_key":         write(),          // org.CreateAPIKeyWithOptions mints a new key each call (new key_hash); additive
	"create_group":           write(),          // client.CreateGroup mints a new gid each call; additive
	"create_org":             write(),          // POST orgs/new creates a new org each call (description says NOT idempotent); platform-internal
	"delete_api_key":         destroy().Idem(), // org.DeleteAPIKey revokes the key by hash; irreversible, repeat is no-op
	"delete_group":           destroy().Idem(), // group.Delete removes the group by gid; irreversible
	"dismiss_org_error":      destroy().Idem(), // org.DismissOrgError issues HTTP DELETE errors/{oid}/{component}; removes the error entry
	"get_billing_details":    read(),           // org.GetBillingOrgDetails GET only
	"get_group_info":         read(),           // group.GetInfo GET only
	"get_mitre_report":       read(),           // org.GetMITREReport GET mitre/{oid}
	"get_org_errors":         read(),           // org.GetOrgErrors GET errors/{oid}
	"get_org_info":           read(),           // org.GetInfo GET only
	"get_org_invoice_url":    read(),           // org.GetBillingInvoiceURL GET returns a signed URL; nothing changes
	"get_org_oid_by_name":    read(),           // Lists user orgs via ListUserOrgs; only fills an in-process lookup cache (no LC state change)
	"get_sku_definitions":    read(),           // org.GetBillingSkuDefinitions GET only
	"get_usage_stats":        read(),           // org.GetUsageStats GET usage/{oid}
	"get_users_permissions":  read(),           // org.GetUsersPermissions GET only
	"list_api_keys":          read(),           // org.GetAPIKeys GET only; key values not returned
	"list_groups":            read(),           // client.GetGroups GET only
	"list_groups_detailed":   read(),           // client.GetGroupsConcurrent GET only
	"list_org_users":         read(),           // org.GetUsers GET only
	"list_user_orgs":         read(),           // org.ListUserOrgsWithOptions paged GET only
	"remove_group_member":    destroy().Idem(), // group.RemoveMember revokes membership/access; repeat leaves same state
	"remove_group_owner":     destroy().Idem(), // group.RemoveOwner revokes ownership; repeat leaves same state
	"remove_org_from_group":  destroy().Idem(), // group.RemoveOrg unlinks org from group, revoking group access to it
	"remove_org_user":        destroy().Idem(), // org.RemoveUser revokes the user's access to the org
	"remove_user_permission": destroy().Idem(), // org.RemoveUserPermission revokes a permission
	"set_group_permissions":  destroy().Idem(), // group.SetPermissions REPLACES all existing group permissions (overwrite); same args repeat is no-op
	"set_user_role":          destroy().Idem(), // org.SetUserRole overwrites the user's role (can demote/escalate); same args repeat is no-op
	"upgrade_sensors":        destroy().Idem(), // POST modules/{oid} sets org-wide sensor version (specific/latest/fallback downgrade/is_sleep dormant); endpoints update later
	// --- ai ---
	"delete_ai_memory":           destroy().Idem(), // org.DeleteAIMemory sends null to drop one named memory entry in ai_memory hive record; irreversible
	"generate_detection_summary": read().Open(),    // Sends caller/org-supplied data to api.anthropic.com (claudeResponse), a third-party model API; returns text and persists nothing. Returns text from Anthropic via claudeResponse (in-process memo cache only); persists nothing
	"generate_dr_rule_detection": read().Open(),    // Sends caller/org-supplied data to api.anthropic.com (claudeResponse), a third-party model API; returns text and persists nothing. Claude text gen + org.ValidateDRRule (validate only); persists nothing
	"generate_dr_rule_respond":   read().Open(),    // Sends caller/org-supplied data to api.anthropic.com (claudeResponse), a third-party model API; returns text and persists nothing. Claude text gen + org.ValidateDRRule (validate only); persists nothing
	"generate_lcql_query":        read().Open(),    // Sends caller/org-supplied data to api.anthropic.com (claudeResponse), a third-party model API; returns text and persists nothing. Claude text gen + org.ValidateLCQLQuery and schema reads; persists nothing; does not run the query
	"generate_python_playbook":   read().Open(),    // Sends caller/org-supplied data to api.anthropic.com (claudeResponse), a third-party model API; returns text and persists nothing. Claude text gen only; returns playbook source, nothing saved
	"generate_sensor_selector":   read().Open(),    // Sends caller/org-supplied data to api.anthropic.com (claudeResponse), a third-party model API; returns text and persists nothing. Claude text gen only; returns a selector expression, nothing saved
	"get_ai_chat":                read(),           // org.AI().GetUserSession GET only
	"get_ai_chat_history":        read(),           // org.AI().GetUserSessionHistory GET only
	"get_ai_session":             read(),           // org.AI().GetSession GET only
	"get_ai_session_history":     read(),           // org.AI().GetSessionHistory GET only
	"get_ai_usage":               read(),           // org.AI().GetUsage GET only
	"list_ai_chats":              read(),           // org.AI().ListUserSessions GET only
	"list_ai_sessions":           read(),           // org.AI().ListSessions GET only
	"list_ai_usage":              read(),           // org.AI().ListUsageIdentities GET only
	"set_ai_memory":              destroy().Idem(), // org.SetAIMemory creates/replaces one named memory entry on an agent record (overwrite); same args repeat is no-op
	"start_ai_session":           destroy(),        // org.AI().StartSession launches an agent (spends budget; permission_mode/allowed_tools overrides let it act on org); new session each call
	"terminate_ai_session":       destroy().Idem(), // org.AI().TerminateSession cancels a running session; repeat is no-op
	// --- api ---
	"lc_call_tool": destroy().Open(), // Dispatcher via tools.CallTool to any registered tool; per-target scope check but worst case mutating+open world
	// --- artifacts ---
	"get_artifact":   read(), // GET of artifact metadata/signed URL, or ExportArtifact download; no state change
	"list_artifacts": read(), // GenericGETRequest insight/{oid}/artifacts listing only
	// --- cases ---
	"add_case_artifact":    write(),          // AddArtifact appends an artifact reference to a case; additive, new row each call (org-internal ext-cases)
	"add_case_detection":   write(),          // AddDetection links a detection to a case; additive, org-internal; current des=T was overstated
	"add_case_entity":      write().Idem(),   // AddEntity appends an IOC; ext-cases rejects dup type+value (DUPLICATE_ENTITY) so repeat is a no-op; additive
	"add_case_note":        write(),          // AddNote appends a note each call; additive, org-internal
	"add_case_telemetry":   write(),          // AddTelemetry links a telemetry event ref to a case; additive, org-internal; current des=T was overstated
	"bulk_update_cases":    destroy().Idem(), // BulkUpdate overwrites status/severity/etc. on up to 200 cases; same fields reapplied = same state
	"create_case":          write(),          // CreateCase mints a new case with a new number each call; pure create, org-internal
	"get_case":             read(),           // GetCase reads one case + timeline; no mutation
	"get_case_dashboard":   read(),           // DashboardCounts read-only counts
	"get_case_report":      read(),           // ReportSummary computes metrics over a time range; read-only
	"list_case_entities":   read(),           // ListEntities read-only
	"list_cases":           read(),           // ListCases read-only with filters/pagination
	"merge_cases":          destroy().Idem(), // ext-cases MergeCases folds sources into target and puts sources in terminal state; repeat fails on terminal sources, no extra effect
	"search_case_entities": read(),           // SearchEntities read-only
	"update_case":          destroy().Idem(), // UpdateCase overwrites case fields (status, assignees, summary, tags...); same args converge on same state
	// --- cloudsec ---
	"cloudsec_bulk_set_finding_status":       destroy().Idem(),        // POST findings/bulk/status overwrites resolution on up to N findings; same args repeat harmlessly
	"cloudsec_check_finding_runtime":         read(),                  // POST runtime-check starts a telemetry measurement (publishes the finding's packages as relevant to its agents) but changes no finding, config or resource; kept read-only as designed (existing contract test), strictness caveat
	"cloudsec_code_autofix":                  write().Open(),          // POST code/autofix queues governed remediation run that opens a PR in customer source control; additive, one run per call
	"cloudsec_code_capabilities":             read(),                  // readProductGET/readGET; reports code-lane capabilities only
	"cloudsec_code_findings":                 read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_code_fixes":                    read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_code_iac_map_extract":          read(),                  // Local exec of operator-installed iac-map-extract on a local file; offline, no LC calls, no state change
	"cloudsec_code_iac_map_push":             destroy().Idem(),        // POST code/iac-map publishes a new mapping generation superseding earlier; exact replay writes nothing
	"cloudsec_code_iac_map_status":           read(),                  // GET code/iac-map/status receipt read (backend wants cloudsec.set but writes nothing)
	"cloudsec_code_image":                    read(),                  // readProductGET code/images/{digest}; read-only
	"cloudsec_code_image_repo_facets":        read(),                  // handleImageRead GET code/image-repos/facets; read-only
	"cloudsec_code_image_repos":              read(),                  // handleImageRead GET code/image-repos; read-only
	"cloudsec_code_images":                   read(),                  // handleImageRead GET code/images; read-only
	"cloudsec_code_ingest":                   destroy().Idem(),        // POST code/ingest upserts producer findings; complete report retires prior findings of that producer; replay writes nothing
	"cloudsec_code_pr_check":                 write().Open(),          // POST code/pr_check queues check run/status/comment published to GitHub/GitLab/Bitbucket; additive
	"cloudsec_code_provenance":               read(),                  // GET code/provenance; read-only
	"cloudsec_code_provenance_push":          write(),                 // POST code/provenance appends a metadata attestation; additive, replay-safety not documented
	"cloudsec_code_repos":                    read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_code_rescan":                   write().Open(),          // POST code/scan queues a hosted scan each call; LC then fetches repo from the SCM provider
	"cloudsec_code_sbom":                     read(),                  // GET code/sbom returns metadata + signed URL; tool never follows URL; no state change
	"cloudsec_code_scan_local":               destroy().Idem().Open(), // Runs local docker scan (image pull/vuln lookups); ingest=true pushes via code/ingest which can retire findings; output_path writes a file
	"cloudsec_code_status":                   read(),                  // readProductGET code/status; read-only
	"cloudsec_code_webhook":                  destroy().Idem().Open(), // POST code/webhook overwrites the GitHub App GLOBAL webhook URL/secret (shared by installations)
	"cloudsec_create_compliance_attestation": write(),                 // POST compliance/attestations appends an immutable revision; revocation is a later revision, never overwrite
	"cloudsec_create_compliance_run":         write(),                 // POST compliance/v2 persists a new immutable run each call (run_id optional, server mints)
	"cloudsec_create_remediation":            write(),                 // POST findings/{id}/remediations creates a run that does nothing until approved; random idempotency_key per call
	"cloudsec_decide_remediation":            destroy().Idem().Open(), // Without confirmation reads only; with token POSTs approve/reject/cancel (approve triggers PR/changes in SCM); generation-fenced
	"cloudsec_dismiss_chokepoint":            destroy().Idem(),        // POST chokepoints/dismiss hides an estate-wide risk from the overview (reversible via restore)
	"cloudsec_entity_activity":               read(),                  // GET entity activity preview; first-party LC sources only
	"cloudsec_entity_get":                    read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_entity_pivot":                  read(),                  // POST entities/resolve is a lookup (POST only for body size); returns cards, persists nothing
	"cloudsec_entity_resolve":                read(),                  // POST entities/resolve is a batch lookup; persists nothing
	"cloudsec_entity_search":                 read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_entity_sightings":              read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_export_compliance_run":         read(),                  // GET compliance/export renders immutable run; legion_graph handleComplianceExportV2 persists nothing
	"cloudsec_export_csv":                    read(),                  // GET/POST read of dataset as CSV; POST only used to carry query DSL body; no persistence
	"cloudsec_get_azure_scope_hierarchy":     read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_caasm_policy":              read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_code_coverage":             read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_code_impact":               read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_compliance_report":         read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_data_security_facets":      read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_finding":                   read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_finding_evidence_chain":    read(),                  // GET evidence chain; runtime=true reads existing evidence only (gateway doc)
	"cloudsec_get_finding_facets":            read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_fleet_overview":            read(),                  // GET cloudsec/fleet/overview across orgs the token sees; read-only
	"cloudsec_get_free_tier_status":          read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_graph_neighbors":           read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_identity":                  read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_identity_facets":           read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_inventory_facets":          read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_overview":                  read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_policy_vocabulary":         read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_provider_manifests":        read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_public_access":             read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_remediation":               read(),                  // rawJSON GET remediations/{id}; read-only
	"cloudsec_get_resource":                  read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_risk_trend":                read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_scan_status":               read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_get_topology":                  read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_ingest_caasm_records":          write().Idem(),          // POST caasm/ingest merges third-party asset rows by identity; identical re-ingest is a no-op; no deletes
	"cloudsec_list_attack_paths":             read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_list_caasm_assets":             read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_list_caasm_coverage":           read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_list_changes":                  read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_list_chokepoints":              read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_list_compliance_assignments":   read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_list_compliance_attestations":  read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_list_compliance_events":        read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_list_compliance_frameworks":    read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_list_compliance_runs":          read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_list_compliance_schedules":     read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_list_data_stores":              read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_list_finding_causes":           read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_list_finding_classes":          read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_list_findings":                 read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_list_identities":               read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_list_inventory":                read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_list_queries":                  read(),                  // GET to cloudsec gateway (cloudsec.get); returns data only
	"cloudsec_list_remediations":             read(),                  // rawJSON GET remediations; read-only
	"cloudsec_mint_m365_certificate":         destroy(),               // POST providers/m365/certificate stores key in org secret; replace=true rotates and can break the connection; idem unless replace
	"cloudsec_resolve_assets":                read(),                  // readGET sensor/asset resolver; read-only
	"cloudsec_resolve_sensors":               read(),                  // readGET sensor/asset resolver; read-only
	"cloudsec_restore_chokepoint":            write().Idem(),          // POST chokepoints/restore un-dismisses; re-enable toggle, repeat is no-op
	"cloudsec_run_query":                     read(),                  // POST /query carries DSL body; gateway documents it read-only (endpoint_cloudsec.go)
	"cloudsec_set_caasm_policy":              destroy().Idem(),        // POST caasm/policy UPSERT replaces the whole coverage policy
	"cloudsec_set_compliance_schedule":       destroy().Idem(),        // POST compliance/schedules upsert replaces schedule config; delivery refs stored, delivery happens later in LC
	"cloudsec_set_finding_owner":             destroy().Idem(),        // POST findings/{id}/owner overwrites or clears existing owner; low impact but is a set_* overwrite
	"cloudsec_set_finding_status":            destroy().Idem(),        // POST findings/{id}/status overwrites resolution (accepted/false_positive/mitigated/reopen)
	"cloudsec_set_finding_ticket":            destroy().Idem(),        // POST findings/{id}/ticket overwrites or clears existing ticket link; low impact but is a set_* overwrite
	"cloudsec_simulate_finding_match":        read(),                  // POST simulate/findings is a preview; gateway documents read-only
	"cloudsec_simulate_resource_match":       read(),                  // POST simulate/resources is a preview; gateway documents read-only
	"cloudsec_suggest_policy_values":         read(),                  // POST policy/suggest is a preview; gateway documents read-only
	"cloudsec_test_provider":                 write().Idem().Open(),   // Connects to the live cloud/SCM provider with caller-supplied credentials (providers/test); persists nothing but gated on cloudsec.set (as sensitive as saving a credential), so kept non-read-only
	// --- config ---
	"add_output":                   destroy().Idem().Open(), // org.OutputAdd; backend addOutput Datastore Put keyed oid+name, no exists check, so same name is overwritten; sends to 3rd party
	"create_installation_key":      write(),                 // POST installationkeys/{oid}; mints a new iid each call, additive, in-org only
	"delete_installation_key":      destroy().Idem(),        // org.DelInstallationKey by iid; irreversible removal, in-org
	"delete_lookup":                destroy().Idem(),        // hive client.Remove on lookup record; deletion, in-org
	"delete_org":                   destroy().Idem(),        // org.DeleteOrganization(token) DELETE orgs/{oid}/delete; irreversible org deletion
	"delete_output":                destroy().Idem(),        // org.OutputDel by name; removes output (deleting an output is not openWorld)
	"delete_secret":                destroy().Idem(),        // hive client.Remove on secret record; deletion, in-org
	"disable_secret":               destroy().Idem(),        // hive.SetRecordMetadata sets Enabled=false; disrupts consumers of the secret; idempotent
	"enable_secret":                write().Idem(),          // hive.SetRecordMetadata sets Enabled=true; re-enable toggle, idempotent
	"extension_request":            destroy().Open(),        // org.ExtensionRequest arbitrary extension/action/data escape hatch; worst case mutating, may reach 3rd parties
	"get_billing_status":           read(),                  // org.GetBillingOrgStatus read-only GET against LC billing
	"get_extension_schema":         read(),                  // org.GetExtensionSchema GET extension/schema; read-only
	"get_group_logs":               read(),                  // org.GetGroupLogs GET groups/{id}/logs; read-only
	"get_installation_key":         read(),                  // GenericGETRequest installationkeys/{oid}/{iid}; read-only
	"get_lookup":                   read(),                  // hive client.Get lookup record; read-only
	"get_org_delete_confirmation":  read(),                  // org.GetDeleteConfirmationToken GET orgs/{oid}/delete only mints a 60s token; deletes nothing
	"get_org_urls":                 read(),                  // org.GetURLs read-only
	"get_org_value":                read(),                  // org.OrgValueGet read-only
	"get_quota_usage":              read(),                  // org.GetQuotaUsage read-only
	"get_secret":                   read(),                  // hive client.Get secret value; read-only (sensitive data but no mutation)
	"list_audit_logs":              read(),                  // org.GetAuditLogs read-only
	"list_available_extensions":    read(),                  // org.ListAvailableExtensions read-only
	"list_billing_plans":           read(),                  // org.GetBillingAvailablePlans read-only
	"list_extension_subscriptions": read(),                  // org.Extensions read-only
	"list_installation_keys":       read(),                  // GenericGETRequest installationkeys/{oid}; read-only
	"list_lookups":                 read(),                  // hive.ListRecords on lookup hive; read-only
	"list_outputs":                 read(),                  // org.Outputs read-only
	"list_secrets":                 read(),                  // hive.ListNames on secret hive, metadata only; read-only
	"query_lookup":                 read(),                  // hive client.Get then in-memory lookupValue; read-only
	"rekey_extension":              destroy(),               // org.ReKeyExtension PATCH subscription/extension/{name}; invalidates old key, new key each call
	"rename_org":                   destroy().Idem(),        // POST orgs/{oid}/name overwrites org name (and description); same args idempotent
	"resolve_arl":                  read().Open(),           // org.ResolveARL GET arl/{oid}: read-only but backend fetches the ARL source (GitHub/URL) from the internet
	"set_lookup":                   destroy().Idem(),        // hive.SetRecord upserts lookup record, overwrites existing data (inv des=F wrong per overwrite rule)
	"set_org_description":          destroy().Idem(),        // renameOrg re-POSTs name+description via orgs/{oid}/name; overwrites existing description
	"set_org_quota":                destroy().Idem(),        // org.SetQuota overwrites sensor quota; lowering can cut capacity
	"set_org_value":                destroy().Idem(),        // org.OrgValueSet overwrites existing org config value
	"set_secret":                   destroy().Idem(),        // hive.SetRecord upserts secret, overwrites existing value (inv des=F wrong per overwrite rule)
	"subscribe_to_extension":       write().Idem(),          // org.SubscribeToExtension additive; re-subscribe leaves no extra effect; first-party
	"unsubscribe_from_extension":   destroy().Idem(),        // org.UnsubscribeFromExtension removes subscription; may drop extension state
	"who_am_i":                     read(),                  // org.WhoAmI read-only
	// --- core ---
	"export_sensors":      read(), // Pure read via org.ExportSensors manifest read; LC-internal
	"find_sensors_by_tag": read(), // Pure read via org.GetSensorsWithTag; LC-internal
	"get_online_sensors":  read(), // Pure read via org.ListSensors OnlineOnly; LC-internal
	"get_sensor_info":     read(), // Pure read via sensor record + GetTags + isolation status GET; LC-internal
	"is_online":           read(), // Pure read via sensor.IsOnline (ActiveSensors lookup); LC-internal
	"list_sensor_tags":    read(), // Pure read via org.GetAllTags; LC-internal
	"list_sensors":        read(), // Pure read via org.ListSensors; LC-internal
	"search_hosts":        read(), // Pure read via org.ListSensors + client-side glob; LC-internal
	"test_tool":           read(), // Returns static OK payload; no API call
	"wait_sensor_online":  read(), // Pure read via polls sensor.IsOnline (read only) up to 300s; LC-internal
	// --- feedback ---
	"add_feedback_channel":      write(),          // Feedback().AddChannel appends to ext-feedback hive config; errors if name exists; only stores config
	"list_feedback_channels":    read(),           // Feedback().ListChannels reads hive config only
	"remove_feedback_channel":   destroy().Idem(), // Feedback().RemoveChannel deletes the channel from ext-feedback config (errors if missing); output untouched
	"request_feedback_ack":      destroy().Open(), // ext-feedback request_acknowledgement sends an irreversible Slack/email/Teams message; reply triggers case/playbook/AI agent
	"request_feedback_approval": destroy().Open(), // ext-feedback request_simple_approval sends an irreversible Slack/email/Teams message; reply triggers case/playbook/AI agent
	"request_feedback_question": destroy().Open(), // ext-feedback request_question sends an irreversible Slack/email/Teams message; reply triggers case/playbook/AI agent
	// --- forensics ---
	"dir_find_hash":       read().Open(), // sendSensorCommand -> sensor.SimpleRequest('dir_find_hash') live introspection on endpoint; no state change; tasks real sensor
	"dir_list":            read().Open(), // sendSensorCommand -> sensor.SimpleRequest('dir_list') live introspection on endpoint; no state change; tasks real sensor
	"find_strings":        read().Open(), // sendSensorCommand -> sensor.SimpleRequest('mem_find_string') live introspection on endpoint; no state change; tasks real sensor
	"get_autoruns":        read().Open(), // sendSensorCommand -> sensor.SimpleRequest('os_autoruns') live introspection on endpoint; no state change; tasks real sensor
	"get_drivers":         read().Open(), // sendSensorCommand -> sensor.SimpleRequest('os_drivers') live introspection on endpoint; no state change; tasks real sensor
	"get_historic_events": read(),        // org.GetHistoricEvents paginated GET of insight/{oid}/{sid} (retention store); does not task sensor
	"get_packages":        read().Open(), // sendSensorCommand -> sensor.SimpleRequest('os_packages') live introspection on endpoint; no state change; tasks real sensor
	"get_process_modules": read().Open(), // sendSensorCommand -> sensor.SimpleRequest('os_processes --pid') live introspection on endpoint; no state change; tasks real sensor
	"get_process_strings": read().Open(), // sendSensorCommand -> sensor.SimpleRequest('mem_strings') live introspection on endpoint; no state change; tasks real sensor
	"get_registry_keys":   read().Open(), // sendSensorCommand -> sensor.SimpleRequest('reg_list') live introspection on endpoint; no state change; tasks real sensor
	"get_services":        read().Open(), // sendSensorCommand -> sensor.SimpleRequest('os_services') live introspection on endpoint; no state change; tasks real sensor
	"get_users":           read().Open(), // sendSensorCommand -> sensor.SimpleRequest('os_users') live introspection on endpoint; no state change; tasks real sensor
	"yara_scan_directory": read().Open(), // sendSensorCommand -> sensor.SimpleRequest('yara_scan --root-dir') live introspection on endpoint; no state change; tasks real sensor
	"yara_scan_file":      read().Open(), // sendSensorCommand -> sensor.SimpleRequest('yara_scan (file path)') live introspection on endpoint; no state change; tasks real sensor
	"yara_scan_memory":    read().Open(), // sendSensorCommand -> sensor.SimpleRequest('yara_scan --processExpr') live introspection on endpoint; no state change; tasks real sensor
	"yara_scan_process":   read().Open(), // sendSensorCommand -> sensor.SimpleRequest('yara_scan --pid') live introspection on endpoint; no state change; tasks real sensor
	// --- historical ---
	"analyze_lcql_query":            read(), // Read of LC historical data via ValidateAndEstimateLCQLQuery (no execution)
	"batch_search_iocs":             read(), // Read of LC historical data via insight/{oid}/objects POST used as batch search
	"estimate_lcql_query":           read(), // Read of LC historical data via ValidateAndEstimateLCQLQuery (no execution)
	"expand_investigation":          read(), // Read of LC historical data via POST orgs/{oid}/investigation/expand fetches events/detections, response only
	"get_atom_children":             read(), // Read of LC historical data via GET insight/.../children
	"get_detection":                 read(), // Read of LC historical data via GET insight/{oid}/detections/{id}
	"get_event_by_atom":             read(), // Read of LC historical data via GET insight/{oid}/{sid}/{atom}
	"get_historic_detections":       read(), // Read of LC historical data via org.HistoricalDetections
	"get_time_when_sensor_has_data": read(), // Read of LC historical data via org.GetTimeWhenSensorHasData
	"run_lcql_query":                read(), // Read of LC historical data via org.QueryAll over event/detect/audit stream; billable read, no persistence
	"run_lcql_query_free":           read(), // Read of LC historical data via org.QueryAll free-tier query; read only
	"search_iocs":                   read(), // Read of LC historical data via insight objects GET / SearchHostname
	"validate_lcql_query":           read(), // Read of LC historical data via ValidateLCQLQuery (no execution)
	// --- hive ---
	"delete_ai_skill":         destroy().Idem(), // ai_skills.go: hive.Remove deletes the record permanently; delete by key is idempotent; first-party hive.
	"delete_cloud_sensor":     destroy().Idem(), // cloud_sensors.go: hive.Remove deletes the record permanently; delete by key is idempotent; first-party hive.
	"delete_extension_config": destroy().Idem(), // extension_configs.go: hive.Remove deletes the record permanently; delete by key is idempotent; first-party hive.
	"delete_external_adapter": destroy().Idem(), // external_adapters.go: hive.Remove deletes the record permanently; delete by key is idempotent; first-party hive.
	"delete_investigation":    destroy().Idem(), // investigations.go: hive.Remove deletes the record permanently; delete by key is idempotent; first-party hive.
	"delete_org_note":         destroy().Idem(), // org_notes.go: hive.Remove deletes the record permanently; delete by key is idempotent; first-party hive.
	"delete_playbook":         destroy().Idem(), // playbooks.go: hive.Remove deletes the record permanently; delete by key is idempotent; first-party hive.
	"delete_rule":             destroy().Idem(), // generic_hive.go: hive.Remove deletes the record permanently; delete by key is idempotent; first-party hive.
	"delete_saved_query":      destroy().Idem(), // saved_queries.go: hive.Remove deletes the record permanently; delete by key is idempotent; first-party hive.
	"delete_sop":              destroy().Idem(), // sop.go: hive.Remove deletes the record permanently; delete by key is idempotent; first-party hive.
	"disable_adapter":         destroy().Idem(), // adapters_mgmt.go: setAdapterEnabled(false) -> usr_mtd.enabled=false halts the adapter's ingestion; idempotent.
	"enable_adapter":          write().Idem(),   // adapters_mgmt.go: setAdapterEnabled(true) -> SetRecordMetadata sets usr_mtd.enabled; additive toggle, idempotent.
	"get_adapter_schema":      read(),           // adapters_mgmt.go: org.GetHiveSchema GET hive/<name>/schema; pure read.
	"get_adapter_sensors":     read(),           // adapters_mgmt.go: hive.Get adapter + org.ListSensorsFromSelector (iid match); reads only, no endpoint tasking.
	"get_ai_skill":            read(),           // ai_skills.go: hive.Get of one record in own-org partition; pure read.
	"get_cloud_sensor":        read(),           // cloud_sensors.go: hive.Get of one record in own-org partition; pure read.
	"get_extension_config":    read(),           // extension_configs.go: hive.Get of one record in own-org partition; pure read.
	"get_external_adapter":    read(),           // external_adapters.go: hive.Get of one record in own-org partition; pure read.
	"get_hive_schema":         read(),           // hive_schema.go: org.GetHiveSchema GET hive/<name>/schema; pure read.
	"get_investigation":       read(),           // investigations.go: hive.Get of one record in own-org partition; pure read.
	"get_org_note":            read(),           // org_notes.go: hive.Get of one record in own-org partition; pure read.
	"get_playbook":            read(),           // playbooks.go: hive.Get of one record in own-org partition; pure read.
	"get_rule":                read(),           // generic_hive.go: hive.Get of one record in own-org partition; pure read.
	"get_saved_query":         read(),           // saved_queries.go: hive.Get of one record in own-org partition; pure read.
	"get_sop":                 read(),           // sop.go: hive.Get of one record in own-org partition; pure read.
	"list_ai_skills":          read(),           // ai_skills.go: ListRecords -> HiveClient.ListPage, paged read.
	"list_cloud_sensors":      read(),           // cloud_sensors.go: ListRecords -> HiveClient.ListPage, paged read.
	"list_extension_configs":  read(),           // extension_configs.go: ListRecords -> HiveClient.ListPage, paged read.
	"list_external_adapters":  read(),           // external_adapters.go: ListRecords -> HiveClient.ListPage, paged read.
	"list_investigations":     read(),           // investigations.go: ListRecords -> HiveClient.ListPage, paged read.
	"list_org_notes":          read(),           // org_notes.go: ListRecords -> HiveClient.ListPage, paged read.
	"list_playbooks":          read(),           // playbooks.go: ListRecords -> HiveClient.ListPage, paged read.
	"list_rules":              read(),           // generic_hive.go: ListRecords -> HiveClient.ListPage, paged read. Secret hive forced metadata-only.
	"list_saved_queries":      read(),           // saved_queries.go: ListRecords -> HiveClient.ListPage, paged read.
	"list_sops":               read(),           // sop.go: ListRecords -> HiveClient.ListPage, paged read.
	"rename_hive_record":      destroy(),        // hive_metadata.go: HiveClient.Rename POST .../rename; backend deletes source and recreates under new name; repeat fails.
	"run_saved_query":         read(),           // saved_queries.go: hive.Get then org.Query (LCQL on replay service, query.go); only reads events, nothing persisted.
	"set_adapter_tags":        destroy().Idem(), // adapters_mgmt.go: updateRecordMTD tags action set(default, replaces)/add/remove; set/remove drop tags; idempotent.
	"set_ai_skill":            destroy().Idem(), // ai_skills.go: SetRecord (record_write.go) POSTs hive data, overwriting an existing record's content; same input => same state.
	"set_cloud_sensor":        destroy().Idem(), // cloud_sensors.go: SetRecord (record_write.go) POSTs hive data, overwriting an existing record's content; same input => same state.
	"set_extension_config":    destroy().Idem(), // extension_configs.go: SetRecord (record_write.go) POSTs hive data, overwriting an existing record's content; same input => same state.
	"set_external_adapter":    destroy().Idem(), // external_adapters.go: SetRecord (record_write.go) POSTs hive data, overwriting an existing record's content; same input => same state.
	"set_hive_record_comment": destroy().Idem(), // hive_metadata.go: overwrites usr_mtd.comment of any record via SetRecordMetadata; idempotent; overwrite => des=T.
	"set_hive_record_enabled": destroy().Idem(), // hive_metadata.go: SetRecordMetadata flips usr_mtd.enabled on ANY hive record (enabled=false disables rules etc.); idempotent.
	"set_hive_record_tags":    destroy().Idem(), // hive_metadata.go: applyTagAction set(default, replaces)/add/remove on any record's tags; set/remove drop tags; idempotent.
	"set_investigation":       destroy().Idem(), // investigations.go: SetRecord (record_write.go) POSTs hive data, overwriting an existing record's content; same input => same state.
	"set_org_note":            destroy().Idem(), // org_notes.go: SetRecord (record_write.go) POSTs hive data, overwriting an existing record's content; same input => same state.
	"set_playbook":            destroy().Idem(), // playbooks.go: SetRecord (record_write.go) POSTs hive data, overwriting an existing record's content; same input => same state.
	"set_rule":                destroy().Idem(), // generic_hive.go: SetRecord (record_write.go) POSTs hive data, overwriting an existing record's content; same input => same state.
	"set_saved_query":         destroy().Idem(), // saved_queries.go: SetRecord overwrites record data (same key => replace; metadata preserved); first-party hive.
	"set_sop":                 destroy().Idem(), // sop.go: SetRecord (record_write.go) POSTs hive data, overwriting an existing record's content; same input => same state.
	"validate_hive_record":    read(),           // hive_schema.go: POST hive/.../validate, description says 'without persisting'; dry-run only.
	// --- investigation ---
	"get_network_connections": read().Open(), // sensor.SimpleRequest(netstat) tasks the live endpoint for introspection only; no endpoint state change
	"get_os_version":          read().Open(), // sensor.SimpleRequest(os_version) tasks the live endpoint for introspection only; no endpoint state change
	"get_processes":           read().Open(), // sensor.SimpleRequest(os_processes) tasks the live endpoint for introspection only; no endpoint state change
	// --- mailsec ---
	"mailsec_act_on_campaign":         destroy().Idem().Open(), // POST campaigns/{id}/actions with confirm runs quarantine/trash/etc. on member mail at M365/Google; idempotent per member+attempt
	"mailsec_act_on_message":          destroy().Idem().Open(), // POST messages/{id}/actions executes provider action (quarantine/trash/move_to_spam/banner/crawl_link); same attempt token is deduped
	"mailsec_analyze":                 read(),                  // POST analyze parses/judges submitted EML; description says persists nothing, touches no mailbox (POST only carries body)
	"mailsec_backtest_rule":           read(),                  // POST rules/backtest replays candidate over retained mail; expensive read, persists nothing
	"mailsec_execute_bulk_action":     destroy().Idem().Open(), // POST actions/bulk/execute starts async job applying quarantine/trash/etc. at provider; same request+attempt adopts the same job
	"mailsec_get_action":              read(),                  // GET actions/{id} reads audit record
	"mailsec_get_bulk_action":         read(),                  // GET actions/bulk/{id} reads job progress
	"mailsec_get_campaign":            read(),                  // GET campaigns/{id} read
	"mailsec_get_coverage":            read(),                  // GET coverage read (volume cached server-side only)
	"mailsec_get_message":             read(),                  // GET messages/{uuid} read
	"mailsec_get_message_eml":         read(),                  // GET .../eml downloads original bytes; read of own-org data, server writes an access-audit row (emlaccess.go) as side effect
	"mailsec_get_onboarding":          read(),                  // GET onboarding returns setup steps; creates no resources
	"mailsec_get_report":              read(),                  // GET reports/{id} read
	"mailsec_get_sender_profile":      read(),                  // GET senders/{key} read
	"mailsec_list_campaigns":          read(),                  // GET campaigns read
	"mailsec_list_messages":           read(),                  // GET messages read
	"mailsec_list_reports":            read(),                  // GET reports read
	"mailsec_list_similar_messages":   read(),                  // GET messages/{uuid}/similar read
	"mailsec_list_verdict_revisions":  read(),                  // GET messages/{uuid}/revisions read
	"mailsec_prepare_tenant_purge":    read(),                  // GET tenant is a preview that deletes nothing; it mints a short-lived single-use confirmation token (ephemeral Redis state); kept read-only as designed (gateway contract test), strictness caveat
	"mailsec_preview_bulk_action":     read(),                  // POST actions/bulk/preview is pure tenant read of index rows (service/bulk.go: mints no job); confirm token is derived, not stored
	"mailsec_preview_campaign_action": read(),                  // POST campaigns/{id}/actions without confirm/force only previews (sweeper.Preview); schema cannot pass confirm, so it cannot execute
	"mailsec_purge_tenant":            destroy().Idem().Open(), // DELETE tenant irreversibly wipes all mailsec data and stops provider push subscriptions at M365/Google (handlePurgeTenant); repeat no-op
	"mailsec_reopen_report":           write().Idem(),          // POST reports/{id}/reopen toggles report back to open; already-open succeeds, no extra effect; org-internal
	"mailsec_resolve_report":          destroy().Idem(),        // POST reports/{id}/resolve sets disposition on report; already_resolved is a no-op on repeat; does not remediate mail
	"mailsec_revise_verdict":          destroy().Idem(),        // POST messages/{uuid}/verdict overwrites the message verdict and appends audited revision; applied:false when unchanged
	"mailsec_test_connection":         destroy().Idem().Open(), // POST connections/{record}/test probes provider (Google/M365); include_watch=true replaces a real push watch at the provider (overwrite of third-party state)
	"mailsec_validate_rule":           read(),                  // POST rules/validate checks candidate rule without saving
	// --- payloads ---
	"create_payload": destroy().Idem(), // org.CreatePayloadFromReader POSTs payload/{oid}/{name} then PUTs; no exists check so it overwrites a same-named payload
	"delete_payload": destroy().Idem(), // org.DeletePayload permanently deletes the named payload
	"get_payload":    write().Idem(),   // Returns payload inline; optional file_path (local stdio only, refused over HTTP) writes the MCP host filesystem, so not read-only; kept non-destructive as before
	"list_payloads":  read(),           // org.Payloads GET listing only
	// --- replay ---
	"replay_dr_rule":      read(), // org.ReplayDRRule evaluates rule on historical data and returns results; respond actions not executed (billable only)
	"test_dr_rule_events": read(), // org.ReplayDRRule against inline events; returns match results only
	// --- response ---
	"add_tag":                       write().Idem(),          // sensor.AddTag POST {sid}/tags; additive, re-adding same tag leaves no extra effect (TTL refresh); LC-internal metadata
	"collect_velociraptor_artifact": destroy().Open(),        // ext-velociraptor 'collect' tasks endpoints to run artifacts; custom_artifact accepts arbitrary VQL, each call queues new collection
	"delete_reliable_task":          destroy().Idem(),        // ext-reliable-tasking 'untask' aborts pending tasks; without task_id deletes ALL for target (incl selector '*'); idempotent
	"delete_sensor":                 destroy().Idem(),        // sensor.Delete DELETE /{sid}: permanently removes sensor from org; irreversible
	"isolate_network":               destroy().Idem().Open(), // sensor.IsolateFromNetwork POST {sid}/isolation: cuts endpoint network access; state-set so idempotent; acts on real endpoint
	"list_reliable_tasks":           read(),                  // ext-reliable-tasking 'list' read of pending tasks; LC-internal
	"list_velociraptor_artifacts":   read().Open(),           // ext-velociraptor list may fetch https://triage.velocidex.com/sitemap.xml live (external artifact discovery); changes nothing
	"mass_add_tag":                  write().Idem(),          // org.MassTag adds tag to all sensors matching selector; additive but fleet-wide, can drive tag-based D&R; re-add idempotent
	"mass_remove_tag":               destroy().Idem(),        // org.MassUntag removes tag from all sensors matching selector; fleet-wide, idempotent
	"memory_dump_sensor":            write().Open(),          // org.ServiceRequest 'dumper' triggers full memory dump on endpoint and uploads artifact; additive collection, new dump per call
	"rejoin_network":                write().Idem().Open(),   // sensor.RejoinNetwork DELETE {sid}/isolation restores connectivity (inverse of isolate); acts on real endpoint
	"reliable_tasking":              destroy().Open(),        // ext-reliable-tasking 'task' queues arbitrary sensor command (sid/tag/selector '*') with retries; each call queues new tasks
	"remove_tag":                    destroy().Idem(),        // sensor.RemoveTag DELETE {sid}/tags; removes tag (can change D&R/selector targeting); idempotent
	"seal_sensor":                   write().Idem().Open(),   // sensor.Seal POST {sid}/seal: tamper-protection, blocks uninstall/config change; state-set; reversible via unseal
	"show_velociraptor_artifact":    read().Open(),           // ext-velociraptor show downloads an external artifact ZIP from the internet; changes nothing
	"task_sensor":                   destroy().Open(),        // sensor.Task / SimpleRequest sends arbitrary command (e.g. run --shell-command) to endpoint; each call sends a new task
	"unseal_sensor":                 destroy().Idem().Open(), // sensor.Unseal DELETE {sid}/seal removes tamper protection (access/safeguard revocation); state-set idempotent
	// --- rules ---
	"delete_dr_general_rule":      destroy().Idem(), // Deletes a named org config record via org.DRRuleDelete(general ns); delete-by-name is idempotent, LC-internal only
	"delete_dr_managed_rule":      destroy().Idem(), // Deletes a named org config record via org.DRRuleDelete(managed ns); delete-by-name is idempotent, LC-internal only
	"delete_dr_service_rule":      destroy().Idem(), // Deletes a named org config record via org.DRRuleDelete(service ns); delete-by-name is idempotent, LC-internal only
	"delete_exfil_rule":           destroy().Idem(), // Deletes a named org config record via ExfilRuleEvent/WatchDelete by name; delete-by-name is idempotent, LC-internal only
	"delete_fp_rule":              destroy().Idem(), // Deletes a named org config record via org.FPRuleDelete; delete-by-name is idempotent, LC-internal only
	"delete_yara_rule":            destroy().Idem(), // Deletes a named org config record via org.YaraSourceDelete; delete-by-name is idempotent, LC-internal only
	"delete_yara_ruleset":         destroy().Idem(), // Deletes a named org config record via org.YaraRuleDelete; delete-by-name is idempotent, LC-internal only
	"disable_dr_rule":             destroy().Idem(), // setHiveRecordEnabled flips usr_mtd.enabled=false on dr-general/managed record; stops detection, reversible toggle
	"disable_fp_rule":             destroy().Idem(), // setHiveRecordEnabled flips usr_mtd.enabled=false on fp record; FP suppression off, reversible toggle
	"enable_dr_rule":              write().Idem(),   // setHiveRecordEnabled sets usr_mtd.enabled=true on dr hive record; re-enable toggle
	"enable_fp_rule":              write().Idem(),   // setHiveRecordEnabled sets usr_mtd.enabled=true on fp hive record; re-enable toggle
	"get_detection_rules":         read(),           // Pure read of org config via org.DRRules for general/managed/service
	"get_dr_general_rule":         read(),           // Pure read of org config via org.DRRules(general) lookup
	"get_dr_managed_rule":         read(),           // Pure read of org config via org.DRRules(managed) lookup
	"get_fp_rule":                 read(),           // Pure read of org config via org.FPRules lookup
	"get_fp_rules":                read(),           // Pure read of org config via org.FPRules
	"get_yara_rule":               read(),           // Pure read of org config via org.YaraGetSource
	"import_dr_rules":             destroy().Idem(), // Default mode batch SetRecord upsert of dr-general/managed rules (overwrites); dry_run only validates but writing is the default
	"list_dr_general_rules":       read(),           // Pure read of org config via org.DRRules(general)
	"list_dr_managed_rules":       read(),           // Pure read of org config via org.DRRules(managed)
	"list_dr_service_rules":       read(),           // Pure read of org config via org.DRRules(service)
	"list_exfil_rules":            read(),           // Pure read of org config via org.ExfilRules
	"list_yara_rules":             read(),           // Pure read of org config via org.YaraListSources + YaraListRules
	"list_yara_sources":           read(),           // Pure read of org config via org.YaraListSources
	"set_dr_general_rule":         destroy().Idem(), // Upserts dr-general via hive.SetRecord, overwrites existing rule content
	"set_dr_managed_rule":         destroy().Idem(), // Upserts dr-managed via hive.SetRecord, overwrites existing rule content
	"set_dr_service_rule":         destroy().Idem(), // org.DRRuleAdd IsReplace=true, IsEnabled=true: overwrites existing service rule and forces enabled (drops disabled state)
	"set_exfil_event_rule":        destroy().Idem(), // org.ExfilRuleEventAdd upserts by name, overwrites existing exfil rule; data stays within LC
	"set_exfil_watch_rule":        destroy().Idem(), // org.ExfilRuleWatchAdd upserts by name, overwrites existing exfil rule; data stays within LC
	"set_fp_rule":                 destroy().Idem(), // Upserts fp hive via hive.SetRecord, overwrites existing rule content
	"set_yara_rule":               destroy().Idem(), // org.YaraSourceAdd upserts YARA source by name, overwrites existing
	"set_yara_ruleset":            destroy().Idem(), // org.YaraRuleAdd upserts deployed rule-set by name (sensor mapping), overwrites; LC stores config only
	"validate_dr_rule_components": read(),           // org.ValidateDRRule against LC Replay service (rule_name path only reads DRRules); no writes
	"validate_usp_mapping":        read(),           // org.ValidateUSPMappingWithContext tests mapping against sample input via LC API; no persistence
	"validate_yara_rule":          read(),           // Client-side heuristic regex check only; no API call
	// --- schemas ---
	"get_event_schema":                          read(),           // Pure read via org.GetSchema
	"get_event_schemas_batch":                   read(),           // Pure read via org.GetSchema per event
	"get_event_types_with_schemas":              read(),           // Pure read via org.GetSchemas
	"get_event_types_with_schemas_for_platform": read(),           // Pure read via org.GetSchemasForPlatform
	"get_platform_names":                        read(),           // Pure read via org.GetPlatformNames
	"list_with_platform":                        read(),           // Pure read via org.ListSensors with plat selector
	"reset_event_schemas":                       destroy().Idem(), // org.ResetSchemas DELETE orgs/{oid}/schema wipes learned event schemas (recomputed later); idempotent, LC-internal
	// --- tools ---
	"is_isolated": read(), // tools.GetSensorIsolation GET {sid}/isolation on LC API; reads state, does not task the sensor
	// --- vulnerability ---
	"vulnerability_bulk_set_finding_resolution": destroy().Idem(), // BulkSetFindingResolution overwrites resolution overlay on up to 100 findings; empty resolution deletes overlay rows
	"vulnerability_cve_hosts":                   read(),           // CVEHosts read-only query
	"vulnerability_cve_packages":                read(),           // CVEPackages read-only query
	"vulnerability_dashboard":                   read(),           // Dashboard read-only
	"vulnerability_epss_history":                read(),           // EPSSHistory read-only
	"vulnerability_get_cve":                     read(),           // GetCVE read-only
	"vulnerability_host_packages":               read(),           // HostPackages read-only query
	"vulnerability_list_finding_resolutions":    read(),           // ListFindingResolutions read-only
	"vulnerability_query_cves":                  read(),           // QueryCVEs read-only query
	"vulnerability_query_endpoints":             read(),           // QueryEndpoints read-only query
	"vulnerability_reset_asset_findings":        destroy().Idem(), // ResetAssetFindings wipes all stored findings for a sensor; irreversible until next scan; repeat is a no-op
	"vulnerability_scan":                        write().Open(),   // ext scan_packages schedules an os_packages task on the sensor; results processed into persisted findings. Additive, but tasks an endpoint
	"vulnerability_set_finding_resolution":      destroy().Idem(), // SetFindingResolution upserts/overwrites resolution overlay row; empty resolution deletes it
	"vulnerability_snapshot_list":               read(),           // SnapshotList read-only burndown counts
}
