# Changelog

All notable changes to Themis are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-08-02
### Added
- feat: Phase-3 greenfield rebuild — 4-context pipeline + Intelligence Gateway Δ1 (@invalid-email-address)
- feat(knowledge): implement phase3-knowledge-feeds (19/19, gated) (@invalid-email-address)
- feat(intelligence): Δ2 — typed dispatch + Rule Engine + admission + OpenAI-compatible provider auth (@invalid-email-address)
- feat(eventbus): M5 Groups 1-2 - platform bus scaffold + full Envelope threading (@invalid-email-address)
- feat(eventbus): M5 Groups 3-8 — contracts, transport, and pipeline composition (@invalid-email-address)
- feat(eventbus): M5 Groups 9-10 — pipeline e2e, focused tests, docs; M5 complete (@invalid-email-address)
- feat: post-M5 deployment hardening + shared-CVE correlation fix (@invalid-email-address)
- feat(knowledge): correlate distro (rpm) packages via OSV, format-agnostic (@invalid-email-address)
- feat(knowledge): NVD modified-since enrichment (relevance-bounded, opt-in) (@invalid-email-address)
- feat(knowledge): EPSS/KEV/ExploitDB exploit-signal enrichment (opt-in) (@invalid-email-address)
- feat(knowledge): deterministic priority level + composite score on the Faultline (@invalid-email-address)
- feat(auth): inbound API-key auth + HMAC webhook trust across all services (F1/F2/F3) (@invalid-email-address)
- feat(knowledge): wire feed-health tier policy end-to-end + GET /feeds (parity B1) (@invalid-email-address)
- feat(knowledge): apply the reconciled range gate in correlation (parity A1 / D3) (@invalid-email-address)
- feat(knowledge): NVD as a bounded, opt-in correlation discovery source (parity A2 / D5) (@invalid-email-address)
- feat(governance): thread Knowledge's base score to the Finding (parity C6) + EDR-ESTATE-01 (@invalid-email-address)
- feat(knowledge,evidence): ingest uploaded VEX as applicability Proposals (EDR-VEX-01 Phase 1) (@invalid-email-address)
- feat(registry): enterprise estate graph + blast-radius traversal (parity C1) (@invalid-email-address)
- feat(governance): apply the blast-radius multiplier to Finding priority (parity C2) (@invalid-email-address)
- feat(vex): Phase 2 suppression overlay + eventbus D7 fix + configurable blast-cap (@invalid-email-address)
- feat(knowledge): Red Hat relevance-bounded vendor feed (EDR-VEX-01 Phase 3, PR2) (@invalid-email-address)
- feat(knowledge): stream-scoped RPM fixed verdict (EDR-VEX-01 Phase 3, PR3) (@invalid-email-address)
- feat(knowledge): generic CSAF-VEX vendor feed (EDR-VEX-01 B4) (@invalid-email-address)

### Changed
- docs: add architecture book, ADRs, and engineering notes (markdownlint-clean) (@invalid-email-address)
- docs: split the README into INSTALLATION / TESTING / API guides (@invalid-email-address)
- docs: v0.3.x feed e2e verification + CVSS-4.0/source-tier gaps + vuln-listing helpers (@invalid-email-address)
- docs(openspec): propose phase3-knowledge-feeds — promote feed gaps to tasks (@invalid-email-address)
- test: add release smoke-test script + TESTING pointer (@invalid-email-address)
- chore: gitignore themis-smoke.log (release-smoke-test.sh runtime log) (@invalid-email-address)
- test(knowledge): executable Faultline lifecycle + cross-SBOM reuse demos (@invalid-email-address)
- chore: version the themis-release-test skill (force-tracked) (@invalid-email-address)
- chore(openspec): archive phase3-knowledge-feeds (19/19, complete) (@invalid-email-address)
- Merge phase3-evidence: Δ2 Intelligence (typed dispatch + Rule Engine + admission + OpenAI-compatible provider auth); untrack .claude/ (local tooling + agent memory, not versioned) (@invalid-email-address)
- chore(openspec): archive 7 implemented phase3-* changes (kernel/evidence/knowledge/governance/communication/intelligence + Δ2) — all on main (@invalid-email-address)
- ci: add PR + Main workflows running the make check gate; fold test into check (@invalid-email-address)
- ci: scope the gate to greenfield (make check-ci); fix Faultline concurrent-fold flake (@invalid-email-address)
- docs+openspec: consolidate backlogs into docs/BACKLOG.md; scaffold M5 event-infrastructure (@invalid-email-address)
- docs(m5): add task + backlog to wire make e2e-pipeline into CI after M5 (@invalid-email-address)
- docs(CLAUDE): document make check-ci as the CI gate (@invalid-email-address)
- chore(openspec): archive phase3-event-infrastructure (M5 complete, 43/43) (@invalid-email-address)
- docs(install): wire the post-M5 end-to-end deployment runbook (@invalid-email-address)
- docs: checkpoint 2026-07-30 — VM deployment + first parity cluster closed (@invalid-email-address)
- docs(parity): expand PARITY-GAP with the full two-tree audit (stable IDs A1–F8) (@invalid-email-address)
- test(pipeline): deployment-faithful no-AI SBOM→VEX gate on every PR (@invalid-email-address)
- docs: checkpoint 2026-07-31 — full parity audit + 9-PR advancement (@invalid-email-address)
- docs(deploy): document THEMIS_REGISTRY_URL for Governance (C2 blast multiplier) (@invalid-email-address)
- docs: end-to-end runbook for the vendor-VEX feeds + AI (from scratch to E2E) (@invalid-email-address)
- docs: feed-config reconcile, §5a suppression fix, VM-test backlog findings (@invalid-email-address)
- docs: §5a direct accept + mark proposal-id path-safe fix done (@invalid-email-address)
- docs(backlog): mark the Red Hat applicability-volume + LLM-timeout items fixed (@invalid-email-address)
- docs(edr): EDR-GOVERNANCE-01 D14 — posture residual_priority + disposition re-evaluation (@invalid-email-address)
- docs: v0.4.0 release notes (first greenfield release) + GOV-14 v0.4.x target (@invalid-email-address)

### Fixed
- fix(v0.3.x): read CVSS v4.0 in the NVD adapter (D-NVD-2) (@invalid-email-address)
- fix(evidence-e2e): follow evidence_outbox column rename in outboxCount (@invalid-email-address)
- fix(knowledge): correlate OSV distro advisories via the `upstream` field (@invalid-email-address)
- fix(governance): make vex suppression proposal ids path-safe (@invalid-email-address)
- fix(knowledge): scope Red Hat not_affected applicabilities to package-level names (@invalid-email-address)
- fix(intelligence): make provider HTTP timeout configurable (THEMIS_LLM_TIMEOUT) (@invalid-email-address)

## [0.3.11] - 2026-07-06
### Changed
- proposal(themis-ai-1): consolidate basic AI enrichment (CVE Summarizer) (@invalid-email-address)
- design(themis-ai-1): resolve open questions (grain, queue, footprint) + next-stage roadmap (@invalid-email-address)
- propose(themis-ai-1): task breakdown — 46 tasks, apply-ready (@invalid-email-address)
- docs: consolidate under docs/ with K8s/Istio-style layout + refresh stale context (@invalid-email-address)
- release: v0.3.11 — docs consolidation (K8s/Istio layout) + context refresh (@invalid-email-address)

## [0.3.10] - 2026-07-02
### Changed
- docs(openspec): archive themis-core-model + sync specs; docs current to v0.3.9 (@invalid-email-address)
- release: v0.3.10 — archive themis-core-model; docs current to v0.3.9 (@invalid-email-address)

## [0.3.9] - 2026-07-01
### Added
- feat(feeds): user-defined feed registry (vexfeed.feeds delta list) (@invalid-email-address)

### Changed
- release: v0.3.9 — feed registry (user-defined feeds) (@invalid-email-address)

## [0.3.8] - 2026-07-01
### Added
- feat(api): scoped vulnerability-listing endpoints (product/project/version) (@invalid-email-address)

### Changed
- ci: fix changelog workflow base branch on tag push (detached HEAD) (@invalid-email-address)
- release: v0.3.8 — scoped vulnerability-listing endpoints (@invalid-email-address)

## [0.3.7] - 2026-07-01
### Changed
- release: v0.3.7 — OSV GIT-range over-match fix (@invalid-email-address)

### Fixed
- fix(osv): skip GIT-type ranges so commit hashes never become version bounds (@invalid-email-address)

## [0.3.6] - 2026-07-01
### Changed
- docs(backlog): record RPM module fan-out vs Red Hat per-subpackage VEX as known characteristic (@invalid-email-address)
- release: v0.3.6 — Red Hat VEX minor-stream false-resolution fix (@invalid-email-address)
- docs: bring backlog + STATUS + PROJECT_CONTEXT current to the v0.3.x line (@invalid-email-address)

### Fixed
- fix(vex): scope Red Hat verdicts to main enterprise_linux stream + read epoch qualifier (@invalid-email-address)

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
