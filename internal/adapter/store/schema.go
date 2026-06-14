package store

import "slices"

var expectedTables = []string{
	"products",
	"projects",
	"product_versions",
	"artifacts",
	"images",
	"sbom_documents",
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

var expectedIndexes = []string{
	"components_purl_key",
	"idx_component_vulnerabilities_pair",
	"idx_risk_context_component_vuln_id",
	"idx_risk_context_effective_state",
	"idx_vulnerabilities_cve_id",
	"sbom_documents_image_digest_checksum_sha256_key",
	"vex_documents_sbom_checksum_checksum_sha256_key",
	"idx_epss_kev_signals_kev_listed",
	"idx_asset_graph_edges_from_type",
	"idx_sbom_documents_active",
}

// ExpectedTables returns the Layer 1–3 and operational tables created by migrations.
func ExpectedTables() []string {
	return slices.Clone(expectedTables)
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
