# Themis — Project Status

_Maintained automatically by openspec skills (`propose`, `apply`, `archive`).
Last updated: 2026-07-03 (themis-ai-1 planning complete — tasks.md authored, 46 tasks; ready for `/opsx:apply`)._

---

## Active Changes

| Change | Status | Started | Progress | Blocked On |
| --- | --- | --- | --- | --- |
| Layer-0 refactor (CR-1…CR-10) | **Released (v0.3.0, 2026-06-24)** | 2026-06-23 | all 10 CRs merged and tagged `v0.3.0`; all gates green. Closes D-CVSS-1, D-FEED-1, D-NVD-1, D-LOG-1. See `project-backlog.md`. | — (user-defined feed registry shipped v0.3.9; only operational G1–G8 verification on real SBOMs remains) |
| themis-phase-2 | Architecture Reference | 2026-06-09 | proposal ✓  design ✓  scenario ✓ | — (reference doc, not implemented) |
| **themis-ai-1** | **Planning complete — ready to implement** | 2026-07-02 | proposal ✓  design ✓  spec ✓  **tasks ✓ (46 tasks, 9 groups)** | All open questions resolved (D-GRAIN-1 CVE-grain · D-QUEUE-1 reconcile-over-view, no queue table · D-FOOTPRINT-1 backend inverse query). Next: `/opsx:apply` — restructure → footprint endpoint → contract → migration `000002` → transparency API → `themis-ai` framework, tagged v0.4.0. Supersedes the `themis-phase-2b` slot below |
| themis-phase-2b | Superseded → `themis-ai-1` | — | — | folded into `themis-ai-1` (basic AI use case, v0.4.0) |
| themis-phase-2c | Planned | — | not started | themis-phase-2b complete + KB seeded |

## Prerequisite Work

- **`themis-core-model` restructure — ✅ DONE (released v0.3.0; archived 2026-07-02).** Split
  `sbom_documents` into `sboms` + `scan_reports`; `risk_context` identity PK; removed
  `is_latest`/`supersedes_id`; merged `artifacts`+`images`; `version.project_id` FK; Group 16
  registration endpoints. 58/58 tasks; delta specs synced to `openspec/specs/`. Archived at
  `openspec/changes/archive/2026-07-02-themis-core-model/`. No longer gates Phase 2b (unblocked).

> Group 31 and the Group 16 hardening remainder shipped in **`themis-v0-2-1`** (archived
> 2026-06-17, 36/37 tasks; only the manual merge-to-`main` + tag `v0.2.1` step, 7.7, remains).

- **Group 16 hardening remainder (targets v0.2.1)** — the original "gate before tagging `v0.1.0`"
  framing is retired: `v0.1.0` was tagged retroactively on the Phase 1 commit (2026-06-17,
  replacing `themis-phase-1`). The hardening tasks now ship in the `v0.2.1` maintenance release;
  the two registration endpoints moved under `themis-core-model`.
  Full detail: `openspec/changes/archive/2026-06-09-themis-phase-1/tasks.md` §16

  | # | Task | Status |
  | --- | --- | --- |
  | 16.1 | Normalise Alpine package names for OSV queries | **Done** (v0.2.1) |
  | 16.2 | Integration test: Alpine SBOM ingest | **Done** (`TestV021AlpineSBOMOSVCorrelation`) |
  | 16.3 | Integration test: rpm SBOM | **Done** (`TestV021RPMSBOMIngestSkipsUnsupportedOSV`) |
  | 16.4 | Artifact registration endpoint | Moved → `themis-core-model` |
  | 16.5 | Upload helper script | **Done** (`scripts/upload-sbom.sh`, `scripts/alpine-e2e-gate.sh`) |
  | 16.6 | `make check` passes clean | **Done** (v0.2.1) |
  | 16.7 | `adapter/store/` coverage ≥ 90% | **Done** (91.6%) |
  | 16.8 | `adapter/osv/` coverage ≥ 90% | **Done** (93.6%) |
  | 16.9 | Tag `v0.1.0` + Phase 1 release notes | **Done** (retroactive tag) |
  | 16.10 | Version registration endpoint | Moved → `themis-core-model` |

- **Group 31 — Feed reliability and signal-quality (8 tasks complete on branch; targets v0.2.1)** —
  completed in `themis-v0-2-1`; these fixes remain a Phase 2b prerequisite until
  `v0.2.1` is merged/tagged from `themis-phase-2`.
  All originated from Phase 2a runtime failures found during live Alpine SBOM bring-up.
  Full detail: `openspec/changes/archive/2026-06-17-themis-phase-2a/tasks.md` §31.

  | # | Task | Status |
  | --- | --- | --- |
  | 31.1 | Normalize `ALPINE-CVE-*` IDs to `CVE-*` in `mapOSVVuln` | **Done** (v0.2.1) |
  | 31.2 | Fix `ParseOSVFeed.firstCVE()` Alpine prefix strip | **Done** (v0.2.1) |
  | 31.3 | Fix OSV CVSS vector parsing (`fmt.Sscanf` bug) | **Done** (v0.2.1) |
  | 31.4 | Alpine OSV URL fix — HTTP 302 → GCS zip | **Done** (v0.2.1) |
  | 31.5 | Rocky Linux OSV URL fix — HTTP 404 → GCS zip | **Done** (v0.2.1) |
  | 31.6 | Red Hat CSAF — implement `CSAFDirectoryFeedSource` | **Done** (v0.2.1) |
  | 31.7 | Expose `exploit_public` in scan findings API | **Done** (v0.2.1) |
  | 31.8 | Wire `themis_exploitdb_sync_total` Prometheus counter | **Done** (v0.2.1) |

## Completed Changes

| Change | Archived | Delivered |
| --- | --- | --- |
| themis-core-model | 2026-07-02 | Core data-model restructure (breaking, v0.3.0): `sboms` + `scan_reports` split, merged `artifacts` (unique `image_digest`), `versions.project_id`, `risk_context` identity PK `(artifact_id, component_purl, cve_id)` + Durable-Enrichment Identity Contract (D15), `v_latest_findings` view, schema-skew guard, artifact/version registration endpoints. 58/58 tasks; delta specs (artifact-registration, cve-triage, sbom-ingestion, sbom-management, sbom-store) synced to main specs |
| themis-v0-2-1 | 2026-06-17 | Alpine signal reliability: canonical CVE-ID normalization (`domain.NormalizeCVEID`), OSV CVSS vector parsing, Alpine package-name normalization, `ZipOSVFeedSource` + `CSAFDirectoryFeedSource` vendor feeds, `exploit_public`/enrichment on findings API, `themis_exploitdb_sync_total` metric, component-mismatch correlation logging, Group 31 + Group 16 remainder; 9 spec requirements synced. Merge/tag `v0.2.1` (7.7) still manual |
| themis-phase-2a | 2026-06-17 | EPSS/KEV sync, ExploitDB CSV, Layer 1 rules, asset graph, blast-radius, composite risk score V2, upstream vendor VEX (RHEL/Alpine/Rocky/Wolfi), VEX export, system status API, SBOM management, error UX, AC-16..AC-24, FR1–FR8; v0.2.0 merged to main (PR #16) |
| themis-phase-1 | 2026-06-09 | artifact-trust, sbom-parser, sbom-ingestion, sbom-store, intelligence-enrichment, cve-triage, cve-watch, notification-service; v0.1.0 (retroactive tag on Phase 1 commit, 2026-06-17) |

---

## Release tags

| Tag | Commit | Marks |
| --- | --- | --- |
| `v0.1.0` | `a94f3ba` (PR #10) | Phase 1 core platform — tagged retroactively 2026-06-17 (replaced `themis-phase-1`) |
| `v0.2.0` | `d02883c` (PR #15) | Phase 2a Signal Foundation |
| `v0.2.1` | `5e77d2b` | Maintenance: Group 31 feed fixes + Group 16 hardening remainder |
| `v0.3.0` | `469dd8c` (2026-06-24) | `themis-core-model` (breaking) + Layer-0 Correctness & Observability refactor (CR-1…CR-10) |
| `v0.3.2` | `4feae12` | Correlation correctness (canonical CVE-ID keying + el8/el9 release-stream scoping) + feeder resilience |
| `v0.3.3` | `711b0ac` | Distro-authoritative correlation identity + NVD by-CVE backfill robustness + `fixed_version`/`installed_version` on findings API |
| `v0.3.4` | `7e6c077` | Preserve backfilled CVSS in the catalog upsert (no clobber to `unknown`/0 on re-correlation) |
| `v0.3.5` | `62e0acc` (PR #38) | Red Hat VEX overlay via on-demand Security Data API (Option B) |
| `v0.3.6` | `e6b5faa` (PR #39) | Red Hat VEX minor-stream false-resolution fix (main-stream scoping + `epoch=` qualifier) |
| `v0.3.7` | `6fc334f` (PR #41) | OSV GIT-range over-match fix (skip GIT-type ranges; no commit-hash version bounds) |
| `v0.3.8` | `29943cf` (PR #42) | Scoped vulnerability-listing endpoints (product / project / version) |
| `v0.3.9` | `5d5ee3c` (PR #44) | Feed registry — user-defined `vexfeed.feeds` delta list |
| `v0.4.0` | — (planned) | Phase 2b AI Intelligence |
| `v0.5.0` | — (planned) | Phase 2c AI-Assisted VEX |

## Phase Roadmap

| Phase | Change | Theme | State |
| --- | --- | --- | --- |
| Phase 1 | themis-phase-1 | Core intelligence platform — Go REST API + PostgreSQL | Complete (archived 2026-06-09; v0.1.0) |
| Phase 2a | themis-phase-2a | Signal Foundation — feeds, graph entities, VEX export | Complete (archived 2026-06-17; v0.2.0) |
| — | (maintenance) | v0.2.1 — feed reliability + Phase 1 hardening | Released (v0.2.1) |
| core-model + Layer-0 | themis-core-model + CR-1…CR-10 | Schema restructure (breaking) + correlation/feeder/observability refactor | **Released (v0.3.0, 2026-06-24)** |
| — | (maintenance) | v0.3.2–v0.3.9 — correlation/VEX correctness + ergonomics on the v0.3.0 schema (canonical CVE keying, el8/el9 streams, distro-authoritative identity, CVSS-clobber fix, Red Hat VEX overlay + minor-stream fix, OSV GIT-range fix, scoped vuln endpoints, feed registry) | **v0.3.2–v0.3.9 released** |
| Phase 2b | themis-phase-2b | AI Intelligence — workers, RAG, pgvector | Planned (unblocked) — targets v0.4.0 |
| Phase 2c | themis-phase-2c | AI-Assisted VEX — auto-apply, FP, thresholds | Planned — targets v0.5.0 |
| Phase 3 | themis-phase-3 | Production platform — Docker, UI, Redis, RBAC, cosign | Not started |

Architecture reference for Phases 2a–2c: `openspec/changes/themis-phase-2/`

Cross-phase intelligence source tier classification: `openspec/intel-source-tiers.md`

Canonical capability specs (source of truth, Phase 1 + 2a merged): `openspec/specs/`
(17 capabilities). Seeded 2026-06-17 when `themis-phase-2a` was archived with spec sync;
future changes update this tree via `openspec archive`.
