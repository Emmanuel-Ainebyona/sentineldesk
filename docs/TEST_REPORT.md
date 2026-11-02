# Test report (authoring environment)

Command: `python -m unittest discover -s tests -t . -v`  
Environment: Python 3.12.3, Flask 3.1.3, SQLite 3.45.1

Overall: Ran 34 tests in 9.771s OK

| Test | Result |
|---|---|
| `test_core.AuthTests.test_bad_credentials_are_indistinguishable` | PASS |
| `test_core.AuthTests.test_duplicate_email_case_insensitive` | PASS |
| `test_core.AuthTests.test_health` | PASS |
| `test_core.AuthTests.test_logout_revokes_token` | PASS |
| `test_core.AuthTests.test_protected_requires_valid_token` | PASS |
| `test_core.AuthTests.test_rate_limit_on_login` | PASS |
| `test_core.AuthTests.test_register_login_me` | PASS |
| `test_core.AuthTests.test_register_validation` | PASS |
| `test_core.HardeningTests.test_cors_allowlist` | PASS |
| `test_core.HardeningTests.test_errors_are_json_and_do_not_leak` | PASS |
| `test_core.HardeningTests.test_pagination_and_bad_params` | PASS |
| `test_core.HardeningTests.test_passwords_stored_hashed` | PASS |
| `test_core.HardeningTests.test_production_requires_strong_secret` | PASS |
| `test_core.HardeningTests.test_security_headers` | PASS |
| `test_core.HardeningTests.test_sql_injection_attempts_are_inert` | PASS |
| `test_core.HardeningTests.test_static_frontend_and_path_traversal` | PASS |
| `test_core.UserAdminTests.test_admin_cannot_demote_or_disable_self` | PASS |
| `test_core.UserAdminTests.test_audit_log_records_events_and_hides_secrets` | PASS |
| `test_core.UserAdminTests.test_deactivated_user_loses_access_and_login` | PASS |
| `test_core.UserAdminTests.test_non_admin_forbidden` | PASS |
| `test_core.UserAdminTests.test_reset_password` | PASS |
| `test_core.UserAdminTests.test_role_change_applies_immediately_and_validates` | PASS |
| `test_domain.AssetVulnTests.test_asset_with_vulnerabilities_cannot_be_deleted` | PASS |
| `test_domain.AssetVulnTests.test_crud_and_validation` | PASS |
| `test_domain.AssetVulnTests.test_rbac` | PASS |
| `test_domain.AssetVulnTests.test_search_filter_sort_overdue` | PASS |
| `test_domain.AssetVulnTests.test_severity_and_sla_computed_server_side` | PASS |
| `test_domain.AssetVulnTests.test_vulnerability_validation` | PASS |
| `test_domain.IncidentTests.test_audit_trail_for_changes` | PASS |
| `test_domain.IncidentTests.test_auditor_cannot_change_incidents` | PASS |
| `test_domain.IncidentTests.test_create_sets_reporter_and_status_ignores_client_values` | PASS |
| `test_domain.IncidentTests.test_invalid_transitions_rejected` | PASS |
| `test_domain.IncidentTests.test_workflow_and_events` | PASS |
| `test_domain.StatsTests.test_stats_match_database` | PASS |

Failures found and fixed during development are listed in the delivery notes; nothing here is marked PASS without having been executed.
