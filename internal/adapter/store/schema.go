package store

import (
	"fmt"
	"slices"
	"strings"
)

var expectedTables = []string{
	"products",
	"projects",
	"versions",
	"artifacts",
	"sboms",
	"scan_reports",
	"components",
	"component_versions",
	"dependency_relationships",
	"vulnerabilities",
	"component_vulnerabilities",
	"vex_documents",
	"vex_assertions",
	"intelligence_signals",
	"runtime_exposures",
	"remediation_actions",
	"risk_context",
	"api_keys",
	"notification_rules",
	"cve_watch_findings",
	"audit_log",
	"ingestion_jobs",
	"triage_history",
	"system_state",
	"microservices",
	"customers",
	"deployments",
	"asset_graph_nodes",
	"asset_graph_edges",
	"exploit_records",
	"epss_kev_signals",
}

// legacyTables are pre-v0.3.0 tables. Their presence means the database was not
// re-initialised for the core-model restructure and the binary would run against
// an incompatible schema.
var legacyTables = []string{
	"sbom_documents",
	"images",
	"product_versions",
}

var expectedIndexes = []string{
	"components_purl_key",
	"artifacts_image_digest_key",
	"sboms_artifact_id_sbom_checksum_key",
	"idx_component_vulnerabilities_pair",
	"idx_component_vulnerabilities_scan_report_id",
	"idx_risk_context_effective_state",
	"idx_vulnerabilities_cve_id",
	"idx_scan_reports_active",
	"idx_epss_kev_signals_kev_listed",
	"idx_asset_graph_edges_from_type",
}

// ExpectedTables returns the Layer 1–3 and operational tables created by migrations.
func ExpectedTables() []string {
	return slices.Clone(expectedTables)
}

// LegacyTables returns pre-v0.3.0 tables whose presence indicates an un-migrated schema.
func LegacyTables() []string {
	return slices.Clone(legacyTables)
}

// ExpectedIndexes returns indexes required by the schema contract.
func ExpectedIndexes() []string {
	return slices.Clone(expectedIndexes)
}

// MissingTables returns expected tables absent from existing.
func MissingTables(existing []string) []string {
	present := make(map[string]struct{}, len(existing))
	for _, name := range existing {
		present[name] = struct{}{}
	}

	var missing []string
	for _, table := range expectedTables {
		if _, ok := present[table]; !ok {
			missing = append(missing, table)
		}
	}
	slices.Sort(missing)
	return missing
}

// MissingIndexes returns expected indexes absent from existing.
func MissingIndexes(existing []string) []string {
	present := make(map[string]struct{}, len(existing))
	for _, name := range existing {
		present[name] = struct{}{}
	}

	var missing []string
	for _, index := range expectedIndexes {
		if _, ok := present[index]; !ok {
			missing = append(missing, index)
		}
	}
	slices.Sort(missing)
	return missing
}

// PresentLegacyTables returns the pre-v0.3.0 tables found among existing.
func PresentLegacyTables(existing []string) []string {
	present := make(map[string]struct{}, len(existing))
	for _, name := range existing {
		present[name] = struct{}{}
	}

	var found []string
	for _, table := range legacyTables {
		if _, ok := present[table]; ok {
			found = append(found, table)
		}
	}
	slices.Sort(found)
	return found
}

// reinitialiseHint is the actionable message returned when a schema-skew is detected.
const reinitialiseHint = "this binary requires the v0.3.0 core-model schema; " +
	"in-place upgrade from the pre-v0.3.0 sbom_documents model is not supported. " +
	"Re-initialise your database: drop and recreate it, then run migrations " +
	"(see README § Full database reset)"

// VerifySchemaShape asserts that the connected database matches the v0.3.0 schema
// shape: all expected core-model tables present and no legacy tables remaining.
// It fails loudly with an actionable message when an un-reinitialised pre-v0.3.0
// database is detected (D13 schema-skew guard).
func VerifySchemaShape(existing []string) error {
	if legacy := PresentLegacyTables(existing); len(legacy) > 0 {
		return fmt.Errorf(
			"incompatible database schema: legacy pre-v0.3.0 tables present (%s); %s",
			strings.Join(legacy, ", "), reinitialiseHint,
		)
	}
	if missing := MissingTables(existing); len(missing) > 0 {
		return fmt.Errorf(
			"incompatible database schema: missing core-model tables (%s); %s",
			strings.Join(missing, ", "), reinitialiseHint,
		)
	}
	return nil
}
