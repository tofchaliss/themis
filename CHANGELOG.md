# Changelog

All notable changes to Themis are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.6] - 2026-06-30
### Changed
- docs(backlog): record RPM module fan-out vs Red Hat per-subpackage VEX as known characteristic

### Fixed
- fix(vex): scope Red Hat verdicts to main enterprise_linux stream + read epoch qualifier

## [0.3.5] - 2026-06-29
### Added
- feat(vex): Red Hat VEX overlay via on-demand Security Data API (Option B) (@invalid-email-address)

### Changed
- release: v0.3.5 — Red Hat VEX overlay (on-demand Security Data API) (@invalid-email-address)

## [0.3.4] - 2026-06-29
### Changed
- release: v0.3.4 — preserve backfilled CVSS in catalog upsert (@invalid-email-address)

### Fixed
- fix(correlation): preserve backfilled CVSS in catalog upsert (no clobber with empty/zero) (@invalid-email-address)

## [0.3.3] - 2026-06-29
### Changed
- release: v0.3.3 — distro-authoritative correlation + NVD backfill robustness + remediation surfacing (@invalid-email-address)

### Fixed
- fix(correlation): distro-authoritative identity + NVD backfill robustness + remediation surfacing (@invalid-email-address)

## [0.3.2] - 2026-06-28
### Changed
- test(correlation): golden Trivy/Rocky SBOM fixture + rpm-shape regressions (@invalid-email-address)
- docs(backlog): record the empty Red Hat CSAF VEX overlay gap (@invalid-email-address)
- release: v0.3.2 — correlation correctness (canonical CVE + el8/el9 streams) + feeder resilience (@invalid-email-address)

### Fixed
- fix(feeds): post-v0.3.0 feed resilience and severity-bucket fixes (@invalid-email-address)
- fix(correlation): key findings by canonical CVE, not advisory id (GHSA/RLSA) (@invalid-email-address)
- fix(correlation): scope RPM findings to their release stream (el8 vs el9) (@invalid-email-address)
- fix(correlation): read RPM release stream from purl + fixed NEVRA (@invalid-email-address)

## [0.3.0] - 2026-06-24
### Changed
- themis-core-model: add D15 Durable-Enrichment Identity Contract. (@invalid-email-address)
- themis-core-model: implement v0.3.0 schema restructure (Groups 1-9) (@invalid-email-address)
- themis-core-model: fix Layer 0 vulnerability correlation and identity (v0.3.0) (@invalid-email-address)
- themis-core-model: fix composite risk score saturation (v0.3.0) (@invalid-email-address)
- docs(backlog): add Layer-0 feeder + observability defects for next cycle (@invalid-email-address)
- docs(backlog): consolidate Layer-0 refactor plan (CR-1..CR-10) into backlog (@invalid-email-address)
- docs(readme): canonical from-scratch getting-started runbook (@invalid-email-address)
- refactor(layer-0): unify version/correlation/observability core (CR-1..CR-10) (@invalid-email-address)
- docs: reconcile backlog/status/README to the finished Layer-0 refactor (@invalid-email-address)
- release: v0.3.0 — core-model + Layer-0 refactor (docs, changelog, version plan) (@invalid-email-address)

## [0.2.1] - 2026-06-18
### Changed
- Document Alpine SBOM bring-up gaps and Phase 2a follow-ons in backlog. (@invalid-email-address)
- Add intel-source-tiers reference and Phase 2a blocking feed-reliability tasks. (@invalid-email-address)
- Archive Phase 2a: update STATUS.md, backlog, and README for post-2a state. (@invalid-email-address)
- Archive themis-phase-2a and establish canonical openspec/specs/ tree. (@invalid-email-address)
- Reconcile release versioning: v0.1.0 retag + v0.2.1 maintenance line. (@invalid-email-address)
- Sync repo memory snapshot with current phase/release state. (@invalid-email-address)
- Tighten core-model gating: it gates schema-dependent items, not v0.2.1. (@invalid-email-address)
- Propose themis-v0-2-1: maintenance release (feed reliability + Phase 1 hardening). (@invalid-email-address)
- Backlog: add feed-observability and feed-registry candidate changes. (@invalid-email-address)
- v0.2.1: add component-mismatch correlation logging (D5, group 4b) (@invalid-email-address)
- Complete v0.2.1 Alpine signal reliability patch. (@invalid-email-address)
- Sync v0.2.1 status tracking with implemented scope. (@invalid-email-address)
- Archive themis-v0-2-1 and sync canonical specs. (@invalid-email-address)
- Propose themis-core-model: greenfield schema restructure (v0.3.0). (@invalid-email-address)
- v0.2.1: harden Alpine backfill and upload-sbom helper scripts. (@invalid-email-address)

## [0.2.0] - 2026-06-14
### Changed
- Add CHANGELOG.md and fix changelog workflow first-run detection. (@invalid-email-address)
- Fix CVE correlation by wiring OSV and structured package matching. (@invalid-email-address)
- Map PURL ecosystems to OSV names and skip unsupported feeds. (@invalid-email-address)
- Document SBOM correlation, OSV mapping, and Linux distro debugging in README. (@invalid-email-address)
- Add verification checklist and Phase 1 post-bring-up task tracking. (@invalid-email-address)
- Archive Phase 1 OpenSpec, establish Phase 2 planning baseline (@invalid-email-address)
- Document Phase 2 architecture: AI intelligence pipeline and threat intelligence design. (@invalid-email-address)
- Add Phase 2a Signal Foundation OpenSpec planning artifacts. (@invalid-email-address)
- Complete Phase 2a Signal Foundation for v0.2.0 release. (@invalid-email-address)

## [0.1.0] - 2026-06-08
### Added
- Initial commit (@tofchaliss)
- Initial setup of project files and directory structure. (@invalid-email-address)

### Changed
- Refactor project structure and update configuration files for improved organization. (@invalid-email-address)
- Refactor domain package documentation, streamline main application logic, and enhance Makefile for better build management and organization. (@invalid-email-address)
- Update task definition to include Clean Architecture gate, revise coverage targets, and enhance project structure with new directory layout and dependencies for improved organization and compliance with architectural standards. (@invalid-email-address)
- Refactor project structure to improve organization, update dependencies, and enhance documentation for better compliance with architectural standards. (@invalid-email-address)
- Implement Phase 1 backend with property-based testing and CI workflows. (@invalid-email-address)
- Fix config docs so ./bin/themis startup requirements are clear. (@invalid-email-address)
- Fix make migrate-up by building golang-migrate with postgres driver. (@invalid-email-address)
- Fix chi panic by mounting API middleware inside /api/v1 routes. (@invalid-email-address)
- Document end-to-end local setup in README Getting Started guide. (@invalid-email-address)
- Document testing Themis with a user-supplied CycloneDX SBOM. (@invalid-email-address)
- Fix upload response returning nil ingestion_id. (@invalid-email-address)
- Document local SQL steps to reset or delete ingested SBOM data. (@invalid-email-address)
- Fix duplicate scans when multiple ingestion jobs reference one SBOM. (@invalid-email-address)
- Defer configurable debug logging to Phase 2 runtime-observability. (@invalid-email-address)

<!-- generated by git-cliff / .github/workflows/changelog.yml -->
