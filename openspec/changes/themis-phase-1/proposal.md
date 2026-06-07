# Themis Phase 1 Proposal

## Why

Organizations building containerized applications lack a unified platform to ingest SBOMs from CI pipelines, correlate vulnerabilities, contextualize findings with VEX intelligence, and continuously monitor for new threats against their component catalog. Existing tools are fragmented — scanners produce reports that rot in CI logs, triage decisions are lost, and there is no continuous monitoring against newly disclosed vulnerabilities.

## What Changes

- **New system**: Themis security intelligence platform built in Go
- REST API for manual upload of CycloneDX/SPDX SBOM documents and VEX documents; webhook endpoints defined (CI automation is Phase 2)
- Artifact validation gate — signature verification, provenance validation, schema conformance, hash verification, and supplier identity checks before ingestion
- Scanner-agnostic SBOM/VEX parser layer with pluggable format adapters (CycloneDX + SPDX normalization; Trivy output as first adapter)
- Multi-product, multi-project data model from inception (PostgreSQL)
- Asynchronous processing pipeline: uploaded SBOM/VEX triggers a goroutine that reads components, checks them against the catalog, and correlates vulnerabilities
- Vulnerability correlation engine matching ingested components against known CVEs (NVD/OSV)
- Intelligence enrichment via VEX overlay: CycloneDX components crossed with VEX assertions produce effective state in `risk_context` — raw findings are never deleted
- CVE triage engine: automated VEX-based contextualization (L3) and human triage with custom justification from product owners (L4)
- Background CVE watch jobs that monitor NVD/OSV feeds and match new CVEs against the existing component catalog
- Configurable notification service (email + Microsoft Teams) for ingestion results, triage events, and new CVE alerts
- API key-based authentication with product-scoped keys
- Phase 1 risk score = raw severity + VEX effective state only (EPSS, KEV, and AI enrichment are Phase 2)

## Capabilities

### New Capabilities

- `artifact-trust`: Validation gate for SBOM/VEX artifact integrity — signature verification (cosign, sigstore, in-toto, PGP), provenance validation, schema conformance (CycloneDX/SPDX/OpenVEX/CSAF), hash verification, and supplier identity checks with configurable trust policies per product
- `sbom-parser`: Scanner-agnostic parser layer with pluggable format adapters normalizing CycloneDX and SPDX documents into the internal canonical model; Trivy output adapter as first implementation
- `sbom-ingestion`: REST API for manual upload of pre-generated SBOM/VEX documents (webhook endpoints also defined for future CI use); triggers asynchronous goroutine processing pipeline through validation, correlation, and enrichment stages; returns 202 Accepted immediately
- `sbom-store`: Multi-product, multi-project PostgreSQL storage for SBOMs, VEX documents, component catalogs, vulnerability findings, scan history, and the three-layer data model (immutable inventory, mutable intelligence, temporal signals convergence)
- `intelligence-enrichment`: VEX overlay applied per component from ingested CycloneDX documents — each component's CVE findings are crossed with VEX assertions to compute effective state in `risk_context`; Phase 1 risk score derived from raw severity and VEX status only; raw findings are preserved (never deleted)
- `cve-triage`: Triage engine combining automated VEX-based contextualization (L3) with human triage workflow (L4) — product owners can mark findings as false positive or accepted risk with custom justification; L4 decisions generate VEX assertions that auto-apply in future ingestions
- `cve-watch`: Background scheduler polling NVD and OSV feeds, matching newly disclosed CVEs against the stored component catalog, creating new findings between builds and triggering notifications
- `notification-service`: Configurable notification delivery via email (SMTP) and Microsoft Teams (incoming webhook) with routing rules governing who is notified, at what severity threshold, and for which event types (ingestion results, triage decisions, new CVE discoveries)

### Modified Capabilities

*None — this is a greenfield project.*

## Impact

- **New Go backend**: REST API server, ingestion pipeline, correlation engine, enrichment layer, background jobs
- **PostgreSQL schema**: Three-layer data model with ~15 core entities; managed via `golang-migrate`
- **External dependencies**: NVD API and OSV API (CVE feeds), SMTP relay (email notifications), Microsoft Teams incoming webhook (Teams notifications)
- **No scanner dependency**: Themis does not invoke scanners — it parses CI-generated output; no Trivy/Docker installation required on the Themis host
- **Webhook endpoints defined**: `POST /api/v1/webhooks/scan` is specified and callable for manual testing in Phase 1; automated CI pipeline integration (Jenkins shared library) is Phase 2
- **API conventions**: Cursor-based pagination, RFC 7807 error format, `Idempotency-Key` support, `/api/v1/` URL versioning
- **Phase 2 scope** (not in this change): AI enrichment, EPSS/KEV sync, CI pipeline automation, React SPA frontend
