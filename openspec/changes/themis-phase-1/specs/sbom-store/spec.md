## ADDED Requirements

### Requirement: Three-layer PostgreSQL schema
The system SHALL implement the three-layer data model in PostgreSQL with Layer 1 (immutable inventory), Layer 2 (mutable vulnerability intelligence), and Layer 3 (temporal exploitability context) as distinct logical groups of tables. Schema migrations SHALL be managed with `golang-migrate`.

#### Scenario: Layer 1 entities are append-only
- **WHEN** the system attempts to update or delete a row in `sbom_documents`, `components`, `component_versions`, or `vulnerabilities`
- **THEN** the operation SHALL be prevented (enforced via application logic; no `UPDATE` or `DELETE` statements on Layer 1 tables)

#### Scenario: Migrations run on startup
- **WHEN** Themis starts and the database schema version is behind the binary version
- **THEN** the system SHALL apply pending migrations before accepting requests

#### Scenario: Startup fails on schema ahead of binary
- **WHEN** the database schema version is ahead of the binary version
- **THEN** the system SHALL refuse to start and log an actionable error message

---

### Requirement: Product and product version storage
The system SHALL store `products` and `product_versions` as the top-level organizational grouping. Products group multiple projects; product versions group artifacts into a named release.

#### Scenario: Product created via API
- **WHEN** a caller posts to `POST /api/v1/products`
- **THEN** the system SHALL create a product record and return its `id` and `name`

#### Scenario: Product version created under product
- **WHEN** a caller posts to `POST /api/v1/products/{id}/versions`
- **THEN** the system SHALL create a `product_versions` record linked to the product

#### Scenario: Products listed with pagination
- **WHEN** a caller queries `GET /api/v1/products`
- **THEN** the system SHALL return a paginated list with cursor-based pagination

---

### Requirement: Image and artifact storage
The system SHALL store container images identified by their SHA-256 digest as the immutable identity. Tags SHALL be stored as mutable aliases. Images SHALL be linked to a generic `artifacts` record enabling future non-container artifact types.

#### Scenario: Image identity is digest-based
- **WHEN** two image records are submitted with the same `digest` but different `tag`
- **THEN** the system SHALL store one image record and update the `tag` field (tags are mutable aliases, not identity keys)

#### Scenario: Image registered before SBOM ingestion
- **WHEN** an SBOM upload references an image digest not yet in the database
- **THEN** the system SHALL require image registration first (enforced by the integrity chain check)

---

### Requirement: Component catalog
The system SHALL maintain a cross-product component catalog indexed by PURL. The catalog SHALL record when each component version was first seen and last seen across all products.

#### Scenario: Component catalog updated on ingestion
- **WHEN** a new SBOM is ingested containing components
- **THEN** the system SHALL upsert each component's `last_seen` timestamp and record the specific `component_version` for this SBOM

#### Scenario: Component catalog queryable across products
- **WHEN** a caller queries `GET /api/v1/components?purl=pkg:npm/lodash@4.17.21`
- **THEN** the system SHALL return all products and projects containing that component version

---

### Requirement: Vulnerability storage with immutability
The system SHALL store raw vulnerability findings as immutable records in `vulnerabilities` and `component_vulnerabilities`. No API endpoint SHALL permit mutation or deletion of these records.

#### Scenario: Duplicate vulnerability finding is idempotent
- **WHEN** the same CVE is correlated against the same component version in the same SBOM ingestion
- **THEN** the system SHALL return the existing `component_vulnerabilities` record without creating a duplicate

#### Scenario: Vulnerability records have no delete endpoint
- **WHEN** any API consumer attempts to DELETE a vulnerability or component_vulnerability record
- **THEN** the system SHALL return HTTP 405 Method Not Allowed

---

### Requirement: SBOM and VEX raw document storage
The system SHALL store the complete raw SBOM and VEX documents as JSONB in `sbom_documents.raw_document` and `vex_documents.raw_document` respectively. These fields SHALL be immutable after first write.

#### Scenario: Raw document stored on ingestion
- **WHEN** an SBOM is ingested and normalized
- **THEN** `sbom_documents.raw_document` SHALL contain the exact bytes received, parseable as JSON

#### Scenario: Raw document not overwritten on duplicate
- **WHEN** a duplicate SBOM (same dedup key) is submitted
- **THEN** the existing `raw_document` SHALL remain unchanged

---

### Requirement: Dependency graph storage
The system SHALL store SBOM dependency relationships in `dependency_relationships` with `from_component_version_id`, `to_component_version_id`, `relationship_type`, `scope`, and `depth` (1 = direct, 2+ = transitive).

#### Scenario: Direct dependency marked with depth 1
- **WHEN** a CycloneDX document contains a component listed in the root `dependencies` array
- **THEN** the system SHALL store the edge with `depth=1` and `scope=runtime` (unless scope is specified)

#### Scenario: Transitive dependency stored with depth
- **WHEN** a CycloneDX document contains nested `dependsOn` entries
- **THEN** the system SHALL resolve the transitive depth and store each edge with the correct `depth` value

---

### Requirement: Vulnerability list endpoint with filtering
The system SHALL expose `GET /api/v1/scans/{id}/vulnerabilities` returning vulnerability findings for a scan, filterable by severity, effective state, and CVE ID, with cursor-based pagination.

#### Scenario: Vulnerability list filtered by severity
- **WHEN** a caller queries `GET /api/v1/scans/{id}/vulnerabilities?severity=critical`
- **THEN** the system SHALL return only vulnerabilities with `raw_severity=critical`

#### Scenario: Vulnerability list filtered by effective state
- **WHEN** a caller queries with `?effective_state=suppressed`
- **THEN** the system SHALL return only findings where `risk_context.effective_state=suppressed`

---

### Requirement: Multi-product data isolation
The system SHALL enforce that API keys scoped to a product can only query and modify data belonging to that product. Cross-product queries SHALL be permitted only for globally-scoped API keys.

#### Scenario: Product-scoped key cannot access other product data
- **WHEN** a caller with an API key scoped to Product A queries `/api/v1/products/{id}` for Product B
- **THEN** the system SHALL return HTTP 403

#### Scenario: Global admin key can query all products
- **WHEN** a caller with a global admin API key queries `/api/v1/products`
- **THEN** the system SHALL return all products
