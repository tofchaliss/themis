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
}

var expectedIndexes = []string{
	"components_purl_key",
	"component_vulnerabilities_component_version_id_vulnerability_id_key",
	"risk_context_component_vulnerability_id_key",
	"idx_risk_context_effective_state",
	"vulnerabilities_cve_id_key",
	"sbom_documents_image_digest_checksum_sha256_key",
	"vex_documents_sbom_checksum_checksum_sha256_key",
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
