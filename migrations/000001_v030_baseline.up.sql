-- Themis v0.3.0 core-model baseline (themis-core-model).
--
-- This is a squashed greenfield baseline that replaces the prior 000001–000019
-- chain (D13). It is NOT an in-place upgrade: a database created under the
-- pre-v0.3.0 `sbom_documents` model must be dropped and recreated. A startup
-- schema-shape guard fails loudly if an old schema is detected.
--
-- Key structural changes vs the pre-v0.3.0 model:
--   * `sbom_documents` is split into `sboms` (composition) + `scan_reports` (temporal).
--   * `artifacts` and `images` are merged; `image_digest` is globally UNIQUE.
--   * `product_versions` becomes `versions` with `project_id NOT NULL`.
--   * Durable Layer-2/3 judgment tables (`risk_context`, `triage_history`,
--     `remediation_actions`, `intelligence_signals`, `runtime_exposures`) are
--     re-keyed on the stable identity `(artifact_id, component_purl, cve_id)`.
--   * `is_latest` / `supersedes_id` removed; "latest scan" = ORDER BY scanned_at DESC.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Organizational hierarchy: products -> projects -> versions -> artifacts
-- ---------------------------------------------------------------------------

CREATE TABLE products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id UUID NOT NULL REFERENCES products(id),
    name TEXT NOT NULL,
    description TEXT,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (product_id, name)
);

-- versions replaces product_versions; parented by a project (project_id NOT NULL).
CREATE TABLE versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id),
    version TEXT NOT NULL,
    release_status TEXT NOT NULL DEFAULT 'draft'
        CHECK (release_status IN ('draft', 'released', 'deprecated')),
    released_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, version)
);

-- artifacts merges the old artifacts + images tables. image_digest is the
-- global artifact identity (same digest = same content = same artifact).
CREATE TABLE artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version_id UUID NOT NULL REFERENCES versions(id),
    artifact_type TEXT NOT NULL DEFAULT 'image'
        CHECK (artifact_type IN ('image', 'jar', 'binary', 'firmware', 'other')),
    image_digest TEXT NOT NULL UNIQUE,
    registry TEXT,
    repository TEXT,
    tag TEXT,
    image_signature TEXT,
    image_signature_format TEXT,
    image_signer_identity TEXT,
    image_signature_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- Composition (sboms) vs temporal scans (scan_reports)
-- ---------------------------------------------------------------------------

-- sboms: an uploaded bill of materials. Keyed (artifact_id, sbom_checksum) so a
-- different tool/format or corrected re-upload yields a distinct composition (D9).
CREATE TABLE sboms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts(id),
    sbom_checksum TEXT NOT NULL,
    format TEXT NOT NULL CHECK (format IN ('cyclonedx', 'spdx', 'trivy')),
    spec_version TEXT,
    supplier_identity TEXT,
    upstream_origin TEXT,
    signature TEXT,
    signature_format TEXT,
    signer_identity TEXT,
    signature_verified BOOLEAN NOT NULL DEFAULT FALSE,
    trust_status TEXT NOT NULL DEFAULT 'unsigned'
        CHECK (trust_status IN ('verified', 'unverified', 'failed', 'unsigned')),
    raw_document JSONB NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (artifact_id, sbom_checksum)
);

-- scan_reports: one correlation run's findings at a point in time. N per artifact.
-- Carries sbom_id (composition correlated) + denormalized artifact_id (fast scoping).
-- No is_latest / supersedes_id: latest = ORDER BY scanned_at DESC. Soft-delete via deleted_at.
CREATE TABLE scan_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_id UUID NOT NULL REFERENCES sboms(id),
    artifact_id UUID NOT NULL REFERENCES artifacts(id),
    image_digest TEXT NOT NULL,
    scan_checksum TEXT NOT NULL,
    scanner TEXT,
    scanner_name TEXT,
    scanner_version TEXT,
    scanner_db_version TEXT,
    ci_job_id TEXT,
    ci_pipeline_url TEXT,
    build_timestamp TIMESTAMPTZ,
    trigger_source TEXT,
    trust_status TEXT NOT NULL DEFAULT 'unsigned'
        CHECK (trust_status IN ('verified', 'unverified', 'failed', 'unsigned')),
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ DEFAULT NULL,
    UNIQUE (sbom_id, scan_checksum)
);

-- ---------------------------------------------------------------------------
-- Component inventory (hangs off sboms)
-- ---------------------------------------------------------------------------

CREATE TABLE components (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    purl TEXT NOT NULL UNIQUE,
    component_type TEXT,
    ecosystem TEXT,
    name TEXT NOT NULL,
    namespace TEXT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE component_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_id UUID NOT NULL REFERENCES components(id),
    version TEXT NOT NULL,
    sbom_id UUID NOT NULL REFERENCES sboms(id),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    licenses TEXT[] NOT NULL DEFAULT '{}',
    direct_dependency BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (component_id, version, sbom_id)
);

CREATE TABLE dependency_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_id UUID NOT NULL REFERENCES sboms(id),
    from_component_version_id UUID NOT NULL REFERENCES component_versions(id),
    to_component_version_id UUID NOT NULL REFERENCES component_versions(id),
    relationship_type TEXT NOT NULL DEFAULT 'depends_on',
    scope TEXT NOT NULL DEFAULT 'runtime',
    depth INT NOT NULL DEFAULT 1 CHECK (depth >= 1)
);

-- ---------------------------------------------------------------------------
-- Vulnerabilities + findings (findings hang off scan_reports)
-- ---------------------------------------------------------------------------

CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL DEFAULT 'nvd',
    severity TEXT NOT NULL DEFAULT 'unknown',
    cvss_score NUMERIC(4, 1),
    cvss_vector TEXT,
    description TEXT,
    ecosystem TEXT,
    package_name TEXT,
    affected_versions TEXT[] NOT NULL DEFAULT '{}',
    fix_versions TEXT[] NOT NULL DEFAULT '{}',
    reference_urls TEXT[] NOT NULL DEFAULT '{}',
    published_at TIMESTAMPTZ,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- CR-5: when the NVD-by-CVE CVSS backfill last checked this row, so genuinely
    -- un-scored (very recent) CVEs are retried with a back-off rather than looped.
    cvss_checked_at TIMESTAMPTZ
);

-- component_vulnerabilities: the raw finding. The only per-scan judgment row.
-- Carries denormalized version-qualified component_purl + cve_id (D11) so the
-- stable identity (artifact_id, component_purl, cve_id) can be formed without
-- fragile multi-table joins and without collapsing distinct installed versions.
CREATE TABLE component_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_version_id UUID NOT NULL REFERENCES component_versions(id),
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id),
    scan_report_id UUID NOT NULL REFERENCES scan_reports(id),
    component_purl TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    -- CR-3 finding provenance: which source produced this finding and what it
    -- asserted, so multiple correlation sources can be merged by explicit
    -- precedence. 'legacy' marks pre-provenance / backfilled rows.
    source TEXT NOT NULL DEFAULT 'legacy',
    source_severity TEXT NOT NULL DEFAULT '',
    source_cvss_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    source_cvss_vector TEXT NOT NULL DEFAULT '',
    source_fixed_version TEXT NOT NULL DEFAULT '',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (component_version_id, vulnerability_id, scan_report_id)
);

-- ---------------------------------------------------------------------------
-- VEX (vex_documents references artifacts, not a scan-document row)
-- ---------------------------------------------------------------------------

CREATE TABLE vex_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID REFERENCES artifacts(id),
    sbom_checksum TEXT NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    format TEXT NOT NULL CHECK (format IN ('cyclonedx', 'csaf', 'openvex')),
    spec_version TEXT,
    supplier_identity TEXT,
    source TEXT NOT NULL DEFAULT 'vendor'
        CHECK (source IN ('vendor', 'upstream', 'upstream_vendor', 'manual', 'themis_generated')),
    issuer TEXT,
    signature TEXT,
    signature_format TEXT,
    signer_identity TEXT,
    signature_verified BOOLEAN NOT NULL DEFAULT FALSE,
    trust_status TEXT NOT NULL DEFAULT 'unsigned'
        CHECK (trust_status IN ('verified', 'unverified', 'failed', 'unsigned')),
    raw_document JSONB NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (sbom_checksum, checksum_sha256)
);

CREATE TABLE vex_assertions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vex_document_id UUID NOT NULL REFERENCES vex_documents(id),
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id),
    component_version_id UUID REFERENCES component_versions(id),
    component_purl TEXT,
    status TEXT NOT NULL
        CHECK (status IN ('not_affected', 'affected', 'fixed', 'under_investigation')),
    justification TEXT,
    impact_statement TEXT,
    action_statement TEXT,
    match_type TEXT
        CHECK (match_type IS NULL OR match_type IN (
            'exact', 'namespace_normalised', 'version_inherited', 'range_matched'
        )),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- Durable Layer-2/3 judgment tables — Durable-Enrichment Identity Contract (D15).
-- Keyed on the stable identity (artifact_id, component_purl, cve_id), so triage,
-- remediation status, and enrichment survive rescans and are never recomputed.
-- ---------------------------------------------------------------------------

CREATE TABLE intelligence_signals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts(id),
    component_purl TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    signal_type TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence NUMERIC(4, 3) CHECK (confidence >= 0 AND confidence <= 1),
    summary TEXT,
    details JSONB NOT NULL DEFAULT '{}',
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE runtime_exposures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts(id),
    component_purl TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT '',
    exposure_type TEXT NOT NULL,
    is_exposed BOOLEAN NOT NULL DEFAULT FALSE,
    evidence JSONB NOT NULL DEFAULT '{}',
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE remediation_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts(id),
    component_purl TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    description TEXT,
    target_version TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'in_progress', 'completed', 'blocked')),
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- risk_context: convergence/judgment table. PK is the stable identity (D3); all
-- mutable enrichment (effective_state, EPSS/KEV, triage) lives here, never on the
-- immutable scan_reports row.
CREATE TABLE risk_context (
    artifact_id UUID NOT NULL REFERENCES artifacts(id),
    component_purl TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    effective_state TEXT NOT NULL
        CHECK (effective_state IN (
            'detected', 'suppressed', 'confirmed', 'in_triage',
            'accepted_risk', 'false_positive', 'resolved', 'not_affected'
        )),
    priority TEXT NOT NULL DEFAULT 'medium'
        CHECK (priority IN ('critical', 'high', 'medium', 'low', 'informational')),
    risk_score NUMERIC(6, 2),
    raw_severity TEXT,
    vex_status TEXT,
    suppression_reason TEXT,
    assigned_to TEXT,
    accepted_until TIMESTAMPTZ,
    triage_notes TEXT,
    triaged_by TEXT,
    triaged_at TIMESTAMPTZ,
    vex_assertion_id UUID REFERENCES vex_assertions(id),
    epss_score NUMERIC(6, 5),
    kev_listed BOOLEAN NOT NULL DEFAULT FALSE,
    exploit_public BOOLEAN NOT NULL DEFAULT FALSE,
    deterministic_level TEXT,
    blast_radius_score NUMERIC(4, 2) NOT NULL DEFAULT 1.0,
    upstream_vex_coverage TEXT
        CHECK (upstream_vex_coverage IN ('covered', 'not_covered', 'purl_mismatch')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (artifact_id, component_purl, cve_id)
);

CREATE TABLE triage_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts(id),
    component_purl TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    decision TEXT NOT NULL
        CHECK (decision IN ('false_positive', 'accepted_risk', 'confirmed', 'resolved', 'escalate')),
    justification TEXT NOT NULL,
    actor TEXT NOT NULL,
    accepted_until TIMESTAMPTZ,
    assigned_to TEXT,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- Operational tables
-- ---------------------------------------------------------------------------

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE notification_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('email', 'slack', 'webhook')),
    destination TEXT NOT NULL,
    filter JSONB NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE cve_watch_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id TEXT NOT NULL,
    product_id UUID REFERENCES products(id),
    project_id UUID REFERENCES projects(id),
    status TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN ('new', 'acknowledged', 'resolved', 'ignored')),
    details JSONB NOT NULL DEFAULT '{}',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id UUID,
    details JSONB NOT NULL DEFAULT '{}',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ingestion_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    payload JSONB NOT NULL DEFAULT '{}',
    error_message TEXT,
    attempts INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE TABLE system_state (
    key TEXT PRIMARY KEY,
    value TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO system_state (key, value)
VALUES ('cve_watch_last_success', NOW());

-- feed_health (CR-8): operator-facing per-feed health, upserted on every sync
-- cycle. Drives degraded_feeds[] on GET /api/v1/status so every feed line's
-- status is visible, not just EPSS/KEV staleness.
CREATE TABLE feed_health (
    feed TEXT PRIMARY KEY,
    class TEXT NOT NULL DEFAULT '',
    tier INTEGER NOT NULL DEFAULT 0,
    last_success_at TIMESTAMPTZ,
    last_attempt_at TIMESTAMPTZ,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT ''
);

-- ---------------------------------------------------------------------------
-- Phase 2a: asset graph + threat-signal entities (unchanged logic)
-- ---------------------------------------------------------------------------

CREATE TABLE microservices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id UUID NOT NULL REFERENCES products(id),
    name TEXT NOT NULL,
    description TEXT,
    tech_stack JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (product_id, name)
);

CREATE TABLE customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    contact_email TEXT NOT NULL UNIQUE,
    notification_preferences JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    microservice_id UUID NOT NULL REFERENCES microservices(id),
    customer_id UUID NOT NULL REFERENCES customers(id),
    environment TEXT NOT NULL,
    region TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (microservice_id, environment, region, customer_id)
);

CREATE TABLE asset_graph_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_type TEXT NOT NULL CHECK (node_type IN (
        'CVE', 'CWE', 'Package', 'Product', 'Microservice', 'Deployment', 'Customer'
    )),
    entity_id UUID NOT NULL,
    properties JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (node_type, entity_id)
);

CREATE TABLE asset_graph_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_node_id UUID NOT NULL REFERENCES asset_graph_nodes(id),
    to_node_id UUID NOT NULL REFERENCES asset_graph_nodes(id),
    edge_type TEXT NOT NULL,
    weight NUMERIC(6, 2) NOT NULL DEFAULT 1.0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (from_node_id, to_node_id, edge_type)
);

CREATE TABLE exploit_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    edb_id TEXT NOT NULL UNIQUE,
    cve_id TEXT,
    exploit_type TEXT,
    published_date DATE,
    title TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE epss_kev_signals (
    cve_id TEXT PRIMARY KEY,
    epss_score NUMERIC(6, 5),
    kev_listed BOOLEAN NOT NULL DEFAULT FALSE,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    stale BOOLEAN NOT NULL DEFAULT FALSE
);

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------

CREATE INDEX idx_projects_product_id ON projects (product_id);
CREATE INDEX idx_versions_project_id ON versions (project_id);
CREATE INDEX idx_artifacts_version_id ON artifacts (version_id);

CREATE INDEX idx_sboms_artifact_id ON sboms (artifact_id);
CREATE INDEX idx_scan_reports_artifact_id ON scan_reports (artifact_id);
CREATE INDEX idx_scan_reports_sbom_id ON scan_reports (sbom_id);
CREATE INDEX idx_scan_reports_latest ON scan_reports (artifact_id, scanned_at DESC);
CREATE INDEX idx_scan_reports_active ON scan_reports (id) WHERE deleted_at IS NULL;

CREATE INDEX idx_component_versions_component_id ON component_versions (component_id);
CREATE INDEX idx_component_versions_sbom_id ON component_versions (sbom_id);
CREATE INDEX idx_dependency_relationships_sbom_id ON dependency_relationships (sbom_id);

CREATE INDEX idx_vulnerabilities_cve_id ON vulnerabilities (cve_id);
CREATE INDEX idx_vulnerabilities_ecosystem_package ON vulnerabilities (ecosystem, package_name);

CREATE INDEX idx_component_vulnerabilities_pair
    ON component_vulnerabilities (component_version_id, vulnerability_id);
CREATE INDEX idx_component_vulnerabilities_scan_report_id
    ON component_vulnerabilities (scan_report_id);
CREATE INDEX idx_component_vulnerabilities_identity
    ON component_vulnerabilities (component_purl, cve_id);

CREATE INDEX idx_vex_documents_artifact_id ON vex_documents (artifact_id);
CREATE INDEX idx_vex_documents_source ON vex_documents (source);
CREATE INDEX idx_vex_assertions_vex_document_id ON vex_assertions (vex_document_id);
CREATE INDEX idx_vex_assertions_vulnerability_id ON vex_assertions (vulnerability_id);
CREATE INDEX idx_vex_assertions_component_purl
    ON vex_assertions (component_purl) WHERE component_purl IS NOT NULL;

CREATE INDEX idx_intelligence_signals_identity
    ON intelligence_signals (artifact_id, component_purl, cve_id);
CREATE INDEX idx_runtime_exposures_identity
    ON runtime_exposures (artifact_id, component_purl, cve_id, environment);
CREATE INDEX idx_remediation_actions_identity
    ON remediation_actions (artifact_id, component_purl, cve_id);

CREATE INDEX idx_risk_context_effective_state ON risk_context (effective_state);
CREATE INDEX idx_risk_context_epss_kev ON risk_context (epss_score, kev_listed);

CREATE INDEX idx_triage_history_identity
    ON triage_history (artifact_id, component_purl, cve_id, recorded_at DESC);

CREATE INDEX idx_api_keys_key_hash ON api_keys (key_hash);
CREATE INDEX idx_notification_rules_event_type ON notification_rules (event_type);
CREATE INDEX idx_cve_watch_findings_cve_id ON cve_watch_findings (cve_id);
CREATE INDEX idx_cve_watch_findings_product_id ON cve_watch_findings (product_id);
CREATE INDEX idx_audit_log_occurred_at ON audit_log (occurred_at);
CREATE INDEX idx_ingestion_jobs_status ON ingestion_jobs (status);

CREATE INDEX idx_microservices_product_id ON microservices (product_id);
CREATE INDEX idx_deployments_microservice_id ON deployments (microservice_id);
CREATE INDEX idx_deployments_customer_id ON deployments (customer_id);
CREATE INDEX idx_asset_graph_nodes_entity ON asset_graph_nodes (entity_id);
CREATE INDEX idx_asset_graph_edges_from_type ON asset_graph_edges (from_node_id, edge_type);
CREATE INDEX idx_exploit_records_cve_id ON exploit_records (cve_id);
CREATE INDEX idx_epss_kev_signals_kev_listed ON epss_kev_signals (kev_listed);

-- ---------------------------------------------------------------------------
-- Shared latest-scan filter (D10): "current findings" = the component_vulnerabilities
-- of the latest non-deleted scan_report per artifact. Every findings-bearing read
-- path joins this view so prior scans' findings are never double-counted.
-- ---------------------------------------------------------------------------

CREATE VIEW v_latest_findings AS
SELECT cv.id,
       cv.component_version_id,
       cv.vulnerability_id,
       cv.scan_report_id,
       cv.component_purl,
       cv.cve_id,
       cv.detected_at,
       sr.artifact_id,
       sr.sbom_id,
       sr.scanned_at
FROM component_vulnerabilities cv
JOIN scan_reports sr ON sr.id = cv.scan_report_id
WHERE sr.deleted_at IS NULL
  AND sr.id = (
      SELECT sr2.id
      FROM scan_reports sr2
      WHERE sr2.artifact_id = sr.artifact_id
        AND sr2.deleted_at IS NULL
      ORDER BY sr2.scanned_at DESC, sr2.id DESC
      LIMIT 1
  );
