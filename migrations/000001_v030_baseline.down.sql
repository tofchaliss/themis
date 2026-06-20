-- Greenfield baseline down migration: drop the entire v0.3.0 schema.
-- There is no in-place downgrade; this exists so `migrate down` returns to a
-- clean database for local/CI re-initialisation.

DROP TABLE IF EXISTS epss_kev_signals CASCADE;
DROP TABLE IF EXISTS exploit_records CASCADE;
DROP TABLE IF EXISTS asset_graph_edges CASCADE;
DROP TABLE IF EXISTS asset_graph_nodes CASCADE;
DROP TABLE IF EXISTS deployments CASCADE;
DROP TABLE IF EXISTS customers CASCADE;
DROP TABLE IF EXISTS microservices CASCADE;
DROP TABLE IF EXISTS system_state CASCADE;
DROP TABLE IF EXISTS ingestion_jobs CASCADE;
DROP TABLE IF EXISTS audit_log CASCADE;
DROP TABLE IF EXISTS cve_watch_findings CASCADE;
DROP TABLE IF EXISTS notification_rules CASCADE;
DROP TABLE IF EXISTS api_keys CASCADE;
DROP TABLE IF EXISTS triage_history CASCADE;
DROP TABLE IF EXISTS risk_context CASCADE;
DROP TABLE IF EXISTS remediation_actions CASCADE;
DROP TABLE IF EXISTS runtime_exposures CASCADE;
DROP TABLE IF EXISTS intelligence_signals CASCADE;
DROP TABLE IF EXISTS vex_assertions CASCADE;
DROP TABLE IF EXISTS vex_documents CASCADE;
DROP TABLE IF EXISTS component_vulnerabilities CASCADE;
DROP TABLE IF EXISTS vulnerabilities CASCADE;
DROP TABLE IF EXISTS dependency_relationships CASCADE;
DROP TABLE IF EXISTS component_versions CASCADE;
DROP TABLE IF EXISTS components CASCADE;
DROP TABLE IF EXISTS scan_reports CASCADE;
DROP TABLE IF EXISTS sboms CASCADE;
DROP TABLE IF EXISTS artifacts CASCADE;
DROP TABLE IF EXISTS versions CASCADE;
DROP TABLE IF EXISTS projects CASCADE;
DROP TABLE IF EXISTS products CASCADE;
