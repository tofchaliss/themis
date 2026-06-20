# Themis — Project Status

_Maintained automatically by openspec skills (`propose`, `apply`, `archive`).
Last updated: 2026-06-20 (themis-core-model implementation complete)._

---

## Active Changes

| Change | Status | Started | Progress | Blocked On |
| --- | --- | --- | --- | --- |
| themis-core-model | Implementation complete | 2026-06-17 | proposal ✓  design ✓  specs ✓  tasks ✓ (57/58; only 9.6 release-tag open) — code, all gates (unit/coverage/integration/clean-arch/verify-build) green | — (ready to archive; tag `v0.3.0` only once Phase 2b is ready, per 9.6) |
| themis-phase-2 | Architecture Reference | 2026-06-09 | proposal ✓  design ✓  scenario ✓ | — (reference doc, not implemented) |
| themis-phase-2b | Ready to start | — | not started | — (`themis-core-model` schema/identity base implemented — unblocked) |
| themis-phase-2c | Planned | — | not started | themis-phase-2b complete + KB seeded |

## Prerequisite Work

- **`themis-core-model` restructure (HIGHEST PRIORITY)** — **planning complete 2026-06-17**
  (proposal/design/specs/tasks; ready to implement). Splits `sbom_documents` into `sboms` +
  `scan_reports`; fixes silent triage loss via `risk_context` identity PK; removes
  `is_latest`/`supersedes_id`; merges `artifacts`+`images`; adds `version.project_id` FK; folds
  in the moved Group 16 registration endpoints. **Greenfield migration — no data backfill; dev
  DBs re-init.** Gates Phase 2b; merges first under the `v0.3.0` line. Change:
  `openspec/changes/themis-core-model/`. Full background: `project-backlog.md` §Core Data Model
  Restructure.

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
| themis-v0-2-1 | 2026-06-17 | Alpine signal reliability: canonical CVE-ID normalization (`domain.NormalizeCVEID`), OSV CVSS vector parsing, Alpine package-name normalization, `ZipOSVFeedSource` + `CSAFDirectoryFeedSource` vendor feeds, `exploit_public`/enrichment on findings API, `themis_exploitdb_sync_total` metric, component-mismatch correlation logging, Group 31 + Group 16 remainder; 9 spec requirements synced. Merge/tag `v0.2.1` (7.7) still manual |
| themis-phase-2a | 2026-06-17 | EPSS/KEV sync, ExploitDB CSV, Layer 1 rules, asset graph, blast-radius, composite risk score V2, upstream vendor VEX (RHEL/Alpine/Rocky/Wolfi), VEX export, system status API, SBOM management, error UX, AC-16..AC-24, FR1–FR8; v0.2.0 merged to main (PR #16) |
| themis-phase-1 | 2026-06-09 | artifact-trust, sbom-parser, sbom-ingestion, sbom-store, intelligence-enrichment, cve-triage, cve-watch, notification-service; v0.1.0 (retroactive tag on Phase 1 commit, 2026-06-17) |

---

## Release tags

| Tag | Commit | Marks |
| --- | --- | --- |
| `v0.1.0` | `a94f3ba` (PR #10) | Phase 1 core platform — tagged retroactively 2026-06-17 (replaced `themis-phase-1`) |
| `v0.2.0` | `d02883c` (PR #15) | Phase 2a Signal Foundation |
| `v0.2.1` | — (planned) | Maintenance: Group 31 feed fixes + Group 16 hardening remainder |
| `v0.3.0` | — (planned) | `themis-core-model` (breaking) + Phase 2b AI Intelligence |
| `v0.4.0` | — (planned) | Phase 2c AI-Assisted VEX |

## Phase Roadmap

| Phase | Change | Theme | State |
| --- | --- | --- | --- |
| Phase 1 | themis-phase-1 | Core intelligence platform — Go REST API + PostgreSQL | Complete (archived 2026-06-09; v0.1.0) |
| Phase 2a | themis-phase-2a | Signal Foundation — feeds, graph entities, VEX export | Complete (archived 2026-06-17; v0.2.0) |
| — | (maintenance) | v0.2.1 — feed reliability + Phase 1 hardening | Planned (Group 31 + Group 16 remainder) |
| Phase 2b | themis-phase-2b | AI Intelligence — workers, RAG, pgvector | Planned (blocked: Group 31 + core-model) |
| Phase 2c | themis-phase-2c | AI-Assisted VEX — auto-apply, FP, thresholds | Planned |
| Phase 3 | themis-phase-3 | Production platform — Docker, UI, Redis, RBAC, cosign | Not started |

Architecture reference for Phases 2a–2c: `openspec/changes/themis-phase-2/`

Cross-phase intelligence source tier classification: `openspec/intel-source-tiers.md`

Canonical capability specs (source of truth, Phase 1 + 2a merged): `openspec/specs/`
(17 capabilities). Seeded 2026-06-17 when `themis-phase-2a` was archived with spec sync;
future changes update this tree via `openspec archive`.
