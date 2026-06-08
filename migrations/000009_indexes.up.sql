-- Additional indexes required by task 3.9 (constraints may already exist from earlier migrations).

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities (cve_id);
CREATE INDEX IF NOT EXISTS idx_component_vulnerabilities_pair
    ON component_vulnerabilities (component_version_id, vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_risk_context_component_vuln_id
    ON risk_context (component_vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_sbom_documents_digest_checksum
    ON sbom_documents (image_digest, checksum_sha256);
CREATE INDEX IF NOT EXISTS idx_vex_documents_checksum_pair
    ON vex_documents (sbom_checksum, checksum_sha256);
