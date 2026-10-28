# Changelog

All notable changes to Themis are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-10-28

274 commits since 0.4.2 (2026-08-21 → 2026-10-27). The release the team's beta runs on from
2026-11-01. Grouped by theme; each item names its decision record or backlog id.

### Added
- **One intake door for everything** (EDR-INTAKE-01): `POST /intake` on Evidence takes an SBOM
  (CycloneDX/SPDX), a curated scanner report, raw Trivy/Cortex/Grype JSON, a Nessus `.nessus`
  export (read as the release's SBOM, SCAN-NESSUS-1/2) or a Nessus CSV (read as its scan report),
  detects the kind itself, converts, files, and answers a receipt. A CI bot can name the release
  by product/project/version with `create_release=true` and a `build_id`; a product-scoped key
  may file only under its own product (B1–B7). Hand-installed software a Nessus scan detected
  outside the package manager (Tomcat, Log4j, JARs, gems, eggs) is filed as components with
  `themis:install-path` and counted as `components_unmanaged` (H1–H6, P-G3).
- **Remediation workflow** (EDR-REMEDIATION-01 D1–D7): SLA policy and the remediation clock
  (7/30/90/180 days, KEV earlier; the severity bucket freezes at first sight; the clock pauses on
  accepted risk); risk acceptance with owner, treatment, proof and review warning; what each SBOM
  upload changed; a one-way outbound webhook with recorded health; KEV date added, due date and
  ransomware use; remediation metrics estate-wide and per product, a weekly report; tags on
  Product, Project and Release as filters.
- **Outward delivery** (EDR-DELIVERY-01, the remediation chain N-M0…N-M2i): Jira tickets and mail
  for a new release's findings, naming product, project and version; the CI rebuild callback;
  delivery attempts recorded (open → continuing → exhausted). Verified live against Jira Data
  Center and a mail relay 2026-10-19.
- **Occurrence verdicts** (EDR-VERDICT-01): every matched component carries a verdict (open,
  cleared by vendor fix, cleared by range…) judged through one seam for the discovery and the
  scanner roads, re-judged by a sweep when the card learns something, with a verdict-logic
  generation stamp; an open rpm verdict now states its premise (D10, KN-OPEN-REASON-1: "fix only
  in a newer module stream", "base repo build vs module fix", EUS-bound).
- **Vendor statements kept whole** (EDR-VEX-02): the full Red Hat record per RHEL major with
  scope and Themis's own applicability determination; `will_not_fix` / `fix_deferred` /
  `out_of_support` propose `accepted_risk` (VEX-WNF-1); a new release is judged against its
  cards when its correlation completes (VEX-RAISE-2); accept/reject scripts for the standing
  vendor proposals.
- **Component identity at intake** (EDR-IDENTITY-01): a purl-less scanner observation resolves
  onto its SBOM twin by name + version or abstains and is counted
  (`GET /scanner-reports/{id}/unresolved`); marked component retirement (KN-SCAN-4b).
- **Carrier attribution** (EDR-CORRELATION-01, EDR-ATTRIBUTION-01): a distro advisory's package
  list is scope, not N claims; each match carries `claim_class` (carrier / scope / unknown), the
  attribution gap is shown and gates the AI; a re-classification sweep with a rule generation.
- **Roll-forward proposes, never copies** (EDR-ROLLFORWARD-01); review-by timer and the Finding
  records its re-surfacing (RF-2); a range keeps the world it was published for (KN-RANGE-ECO-1).
- **Feeds**: Red Hat modified-since gate and the Rocky RXSA feed; RLSA per-CVE fix bounds and
  module-stream placement (KN-MODULE-2…5); apk fixed-verdict (EDR-VEX-01 D9); OSV keeps only the
  Red Hat records of the package's RHEL major (KN-RHEL-MAJOR-1); live "latest published" NVD
  read with Gather (GUI-16); the fan-out guard flags a long discovery answer for an unparseable
  version (KN-SANITY-1).
- **Intelligence**: `compare_releases@v1` narration; delta-aware precedent ranking; LLMOps store
  with redacted invocation capture and an eval replay command (Δ4a); the autonomous analyst with
  an un-erodable authority bar and a capped sweep (Δ4b, AUTO-VOL-1); on-demand CVE gather;
  deterministic decline reasons on `X-Themis-AI-Reason` + `X-Themis-AI-Detail`.
- **Communication**: release-scoped VEX rollup (COMM-VEX-1) and its Customer VEX card.
- **Dashboard**: password login and an Admin tab; find a CVE; What's new (paged, tag filter);
  Cleared tile; Scans view; SBOM manager uploads through `/intake`; "(N hand-installed)".
- **Platform/ops**: `/healthz` + `/readyz` on every node; every node sends `THEMIS_API_KEY`, so
  inbound auth can be ON everywhere (#156); the network edge — loopback nodes, Caddy TLS on 443,
  ufw (VM-NET-1); three VM runbooks at the top of INSTALLATION.md (R1 fresh install, R2 restart,
  R3 pull + restart); `scripts/vm-verify.sh`, `match-census.sh`, the attribution census and
  Red Hat probe; `release-posture.sh`.

### Fixed
- Knowledge: a card save writes only its new proposals (KN-SAVE-TAIL-1: one host SBOM took
  >13 min in a single transaction); each discovered feed record folds once per correlation run
  (KN-PROPOSAL-BLOAT-2: 6.4 copies per fact measured); an rpm install is compared with its epoch
  restored from the purl (KN-EPOCH-1); Go versions spelled `go1.27.1` (KN-GO-1), OSV range
  events paired and graded by their contributors (KN-GO-3/4); the re-verdict loop drains on one
  wake-up; scanner-only components get feed discovery (KN-SCAN-5/5b); a scanner report read
  before its SBOM's correlation completes resolves against the filed SBOM (KN-SCAN-RACE-1).
- Evidence: a converted document's identity names its source, so an empty report is no longer a
  duplicate of every other empty report (EV-DEDUP-EMPTY-1, D3b).
- Governance: the release's product scope comes from the release; the authenticated principal
  becomes the audit actor; a policy's decision and a system proposal are not AI precedent
  (AI-RF-4/4b); priority unclamped to 0–200 (GOV-15).
- Registry: a product key registers only under its own product (#158); name lookups abstain and
  say ambiguous.
- Intelligence: invocation capture survives a cancelled context and non-JSON redaction (Δ4a).

### Docs
- EDRs: INTAKE-01, REMEDIATION-01, DELIVERY-01, VERDICT-01, VEX-02, IDENTITY-01,
  CORRELATION-01, ATTRIBUTION-01, ROLLFORWARD-01, HARNESS-01; DefectDojo comparison; VM test
  logs 2026-10-12/14/17/19 and the Nessus round; the Confluence user guide and the architecture
  diagram (project files).

### Known limits for the beta
- Hand-installed software gets no CVE feed discovery of its own (KN-CPE-1); only what the scan
  report says about it is shown.
- EUS-bound packages (OSV `rhel_eus`) show open (KN-EUS-1, 45 rows measured).
- A scan report filed BEFORE its SBOM is not re-ingested when the SBOM arrives; re-upload it.
- Nessus findings whose version is a guess are skipped and counted, never filed.
- Duplicate proposal rows written before KN-PROPOSAL-BLOAT-2 stay until an owner cleanup.

## [0.4.2] - 2026-08-21
### Added
- Governance (EDR-GOVERNANCE-01 D16, IDEA-1): the **release-comparison read** —
  `GET /releases/{releaseId}/compare/{candidateId}` returns `{fixed, new, persisting}` buckets of
  `PostureEntry` rows (fixed carries the baseline's state, new/persisting the candidate's; sorted by
  residual then effective priority). The honesty guard is part of the contract and fails CLOSED:
  422 names the evidence-less release, 502 when Evidence cannot be asked — over a new
  `governance/adapters/evidence` presence seam (`THEMIS_EVIDENCE_URL`, default `:8081`).
- GUI multi-scanner (EDR-GUI-01 D14–D16): `provenance_source` labels evidence rows (Phase A); the
  per-scan **Scans** view — stored document ⋈ posture, joined in the browser (Phase B); raw Trivy
  JSON translated in the browser, the curated shape staying the only wire contract (Phase C).
- GUI: the **Compare** tab — fixed / new / persisting between two releases by CVE, rendered from the
  Governance comparison read (the client-side join it specified is retired). Live-verified
  2026-08-19 (MRF v20.1.0.0-109 vs -118).
- GUI (GUI-13): the SBOM manager can file a **new build** — "＋ New…" on each selector registers the
  Product→Project→Release chain on upload; typing an existing name is refused (reuse is a pick,
  never a duplicate registration).
### Fixed
- Dashboard write-gate (GUI-14): SBOMs over 1 MiB no longer die as a fake 502 "node unreachable" —
  document routes stream past the D13 identity buffer intact; any other over-cap mutation gets an
  honest 413 (which also closes the padding bypass a skipped check would have opened).
- Evidence (EV-DEDUP-1): byte-identical content aimed at a **different** release now refuses loudly
  with 409 naming the release and evidence id it already resolves to — never a silent
  `created=false` that leaves the new release empty. Same-release re-uploads still dedup benignly
  (D3 upheld; realization note in EDR-EVIDENCE-01).
### Docs
- EDR-GOVERNANCE-01 **D16** (comparison read, fail-closed guard, why Governance); IDEA-1 marked
  realized + live-verified; EV-DEDUP-2 (one observation ↔ many releases) filed as an open design
  question; GUI-11/GUI-12 filed from the 2026-08-17 live test; developer onboarding & architecture
  guide added (`docs/ONBOARDING-GUIDE.{html,pdf}`).

## [0.4.1] - 2026-08-14
### Added
- GUI (GUI-7a): scanner-report evidence kind in the dashboard's SBOM-manager upload — curated
  `{findings:[…]}` documents auto-detected with a finding count; `format` sent only for SBOMs.
- Knowledge/Governance (KN-SCAN-2): per-component **detection origin** (`discovery` vs
  `scanner/<name>`) threaded match → `ComponentMatched` (additive) → `finding_components`
  (governance migration 000011) → read API `detection_origin` → a "found by scanner/…" chip in
  the finding drawer. Display provenance only — never authority.
### Fixed
- The `component_matched` v1 contract schema now declares the additive fields that already
  shipped (`Source`, `ClaimClass`, `Priority`, `Fixes`); the contract test sample sets them so
  the guard actually validates them.
### Docs
- TESTING.md Trivy recipe maps Trivy's ecosystem vocabulary to purl types (measured live);
  KN-SCAN-3 filed for in-code canonicalization; `docs/backlog-ideas/ideas.md` seeded with
  IDEA-1 (release-comparison read API / fix-verification view).

## [0.3.11] - 2026-07-06
### Changed
- docs: consolidate under docs/ (Kubernetes/Istio-style layout) + refresh stale context

## [0.3.10] - 2026-07-02
### Changed
- docs(openspec): archive themis-core-model + sync specs; docs current to v0.3.9

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
