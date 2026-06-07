## ADDED Requirements

### Requirement: Signature verification interface
The system SHALL define a `SignatureVerifier` interface that decouples trust gate logic from the cryptographic implementation. Phase 1 SHALL ship a `StubVerifier` that records trust status without performing real cryptographic operations. The interface SHALL be swappable in Phase 2 with a real cosign/sigstore verifier.

#### Scenario: Unsigned artifact accepted under standard policy
- **WHEN** an SBOM or VEX document is submitted with no signature and the product trust policy is `standard`
- **THEN** the system SHALL accept the artifact and record `trust_status=unsigned`

#### Scenario: Unsigned artifact rejected under strict policy
- **WHEN** an SBOM or VEX document is submitted with no signature and the product trust policy is `strict`
- **THEN** the system SHALL reject the artifact with HTTP 422 and `trust_status=failed`

#### Scenario: Artifact with invalid signature rejected
- **WHEN** an SBOM or VEX document is submitted with a signature that does not match (stub: detected via mismatched checksum)
- **THEN** the system SHALL reject the artifact, record `trust_status=failed`, and emit a security audit log entry

#### Scenario: Artifact with valid signature accepted
- **WHEN** an SBOM or VEX document is submitted with a verifiable signature (stub: any non-empty signature field)
- **THEN** the system SHALL accept the artifact and record `trust_status=verified`

---

### Requirement: Schema conformance validation
The system SHALL validate every ingested SBOM against its declared format schema (CycloneDX JSON schema or SPDX JSON schema) and every ingested VEX document against OpenVEX or CSAF schema before any further processing.

#### Scenario: Valid CycloneDX document accepted
- **WHEN** a document is submitted with `format=cyclonedx` and passes JSON schema validation
- **THEN** the system SHALL proceed to the next validation step

#### Scenario: Malformed document rejected
- **WHEN** a document fails JSON schema validation
- **THEN** the system SHALL reject the artifact with HTTP 400, `trust_status=failed`, and a structured error detailing the schema violations

#### Scenario: Unsupported spec version rejected
- **WHEN** a document declares a `specVersion` not supported by the installed adapter
- **THEN** the system SHALL reject with HTTP 422 and a message indicating the unsupported version

---

### Requirement: Hash verification and deduplication check
The system SHALL compute the SHA-256 hash of every incoming raw document and check it against the deduplication key before processing.

#### Scenario: Duplicate SBOM returns existing ingestion
- **WHEN** a SBOM is submitted where `UNIQUE(image_digest, checksum_sha256)` already exists
- **THEN** the system SHALL return HTTP 200 with a reference to the existing ingestion record and SHALL NOT re-process

#### Scenario: New SBOM for existing image stored as latest
- **WHEN** a SBOM is submitted with the same `image_digest` but a different `checksum_sha256`
- **THEN** the system SHALL store the new SBOM, set `is_latest=true` on the new record, set `is_latest=false` on the previous record, and link them via `supersedes_id`

#### Scenario: Checksum mismatch with provided hash rejected
- **WHEN** a caller provides an expected checksum in the request and it does not match the computed SHA-256 of the raw document
- **THEN** the system SHALL reject with HTTP 422 and record a security audit log entry

---

### Requirement: Provenance validation
The system SHALL validate that ingested artifacts carry expected provenance metadata and SHALL log warnings for missing fields without blocking ingestion (under standard/permissive policies).

#### Scenario: Missing provenance logged as warning under standard policy
- **WHEN** an SBOM is submitted without `ci_job_id` or `ci_pipeline_url` and trust policy is `standard`
- **THEN** the system SHALL accept the artifact and log a structured warning indicating missing provenance fields

#### Scenario: Missing provenance rejects under strict policy
- **WHEN** an SBOM is submitted without required provenance fields and trust policy is `strict`
- **THEN** the system SHALL reject the artifact with HTTP 422

---

### Requirement: Supplier identity check
The system SHALL validate that the supplier identity declared in an artifact matches the registered owner for the product (for CI-generated artifacts) or appears in the trusted supplier registry (for third-party artifacts).

#### Scenario: Known supplier accepted
- **WHEN** an artifact's `supplier_identity` matches the registered product owner
- **THEN** the system SHALL record `trust_status` as verified (or unverified if unsigned) and proceed

#### Scenario: Unknown supplier flagged
- **WHEN** an artifact's `supplier_identity` is not in the trusted supplier registry
- **THEN** the system SHALL accept the artifact under standard policy but record a warning and flag for elevated scrutiny

---

### Requirement: Integrity chain validation
The system SHALL enforce that every ingested SBOM references a known `image_digest` already registered in Themis, and every ingested VEX document references a known `sbom_checksum` already ingested in Themis.

#### Scenario: SBOM referencing unknown image rejected
- **WHEN** an SBOM is submitted referencing an `image_digest` not present in the `images` table
- **THEN** the system SHALL reject with HTTP 422 and the message "image not found — ingest parent first"

#### Scenario: VEX referencing unknown SBOM rejected
- **WHEN** a VEX document is submitted referencing a `sbom_checksum` not present in the `sbom_documents` table
- **THEN** the system SHALL reject with HTTP 422 and the message "SBOM not found — ingest parent first"

---

### Requirement: Configurable trust policies per product
The system SHALL support three trust policy levels configurable per product: `strict`, `standard` (default), and `permissive`. The policy SHALL govern signature requirements, provenance requirements, and supplier identity validation.

#### Scenario: Permissive policy accepts unsigned artifacts with valid schema
- **WHEN** a product trust policy is `permissive` and an unsigned artifact with a valid schema is submitted
- **THEN** the system SHALL accept and record `trust_status=unsigned`

#### Scenario: Trust status is queryable
- **WHEN** a caller queries a scan or SBOM document record
- **THEN** the response SHALL include `trust_status` (verified | unverified | unsigned | failed) and `signature_verified` boolean

---

### Requirement: Security audit logging for trust events
The system SHALL write an audit log entry for every trust gate decision — including acceptance, rejection, and warnings — with actor identity, artifact identifier, trust status, and timestamp.

#### Scenario: Rejected artifact logged
- **WHEN** an artifact is rejected at any trust gate step
- **THEN** the system SHALL write an `audit_log` record with `event_type=ARTIFACT_REJECTED`, the rejection reason, and the source IP

#### Scenario: Security event on signature failure
- **WHEN** a signature verification failure is detected (mismatched checksum or invalid signature)
- **THEN** the system SHALL write an `audit_log` record with `event_type=SIGNATURE_FAILURE` at WARN log level
