# Themis — Project Status

_Maintained by the openspec skills (`propose`, `apply`, `archive`) and by hand when work lands outside a
change. Last updated: 2026-10-14._

**Phase-3 greenfield pivot — the sole go-forward.** The DDD bounded-context rebuild (Evidence → Knowledge →
Governance → Communication, over Kernel/Registry, with the Intelligence AI gateway beside it), per the
architecture book `docs/architecture/` Books I–III + the 69 ADRs `docs/adr/`, replaced the single-binary
monolith — which is **frozen at v0.3.x (last tag `v0.3.11`), reference-only**.

**v0.4.0 — released 2026-08-02 (`6e03396`), the first greenfield release.** The whole pipeline over the
Postgres event bus: M2 Kernel/Registry · M6 Evidence · M7 Knowledge · M8 Governance · M9 Communication · M5
Event Infrastructure · M4 Intelligence (Δ1 + Δ2). Plus the post-M5 parity/hardening work — opt-in
relevance-bounded feeds (NVD / EPSS-KEV / ExploitDB / Red Hat / CSAF), governed vendor-VEX suppression
(EDR-VEX-01 Phase 1–3), the enterprise estate graph + blast-radius priority (EDR-ESTATE-01, C1/C2), and
inbound-edge API-key auth (EDR-SECURITY-01, F1). Validated end-to-end on a live deployment before tagging.

**OpenSpec state: see "Active Changes" below** (as of 2026-10-14: `phase3-report-intake` groups 1–4
merged, `phase3-bot-intake` archived 2026-10-13 as `2026-10-13-phase3-bot-intake`,
`phase3-vendor-statements` — EDR-VEX-02 D13–D17, the whole vendor record kept — implemented, verified on
the VM and archived 2026-10-14 as `2026-10-14-phase3-vendor-statements`). `phase3-trust-model` was implemented and archived 2026-08-06. Every other
Phase-3 change is archived (see "Archived Phase-3 changes" below). Note: the post-M5 parity / VEX / auth / estate / D14 work
landed on `main` **driven by its EDRs + `docs/engineering/PARITY-GAP.md` + `docs/BACKLOG.md` directly, not as
OpenSpec changes** — which is why this file's former "Active Changes" table (branch `phase3-evidence`,
"uncommitted") had gone stale.

**`phase3-trust-model` — IMPLEMENTED 2026-08-06 (63/63 tasks, all 11 groups), gated green at every group boundary**, scaffolded from
**`EDR-TRUST-01` (T1–T12, ACCEPTED)**. It is **cross-context by construction** — Knowledge, Governance and
Intelligence move together, because the trust model is exactly the horizontal that per-context EDRs left
ownerless. It adds **no new bounded context and no new deployable**. Delivers: evidence trust classes
(Observed / Asserted / Inferred, keyed on *derivable vs declared*) · monotonic trust propagation · a
**constitutional stage** in Governance barring auto-acceptance of `Inferred` under any policy · reservations
derived from immutable `PositionInputs` (never a state) · **Deterministic Inference** as a stage inside
evidence-owning contexts, moving the version-range rule out of the AI runtime · **Selection** replacing the
bare finding id · **Domain Projections**, after which the AI Runtime gathers nothing. **Group order is the
migration order** — `recommend_position` stays behaviourally identical throughout, and groups 6→7 must not be
reordered.

**Then — AI-capability expansion** (v0.4.x): **GOV-14** (EDR-GOVERNANCE-01 D14 — disposition-aware
`residual_priority` + the deterministic disposition re-evaluation watcher, AI-judge optional), then
Intelligence **Δ3b** (Python engine) and **Δ4** (autonomy + LLMOps). Both are now **downstream** of the trust
model. Note `EDR-INTELLIGENCE-01` Revision 5 is **superseded** by `EDR-TRUST-01`; scaffold from the latter.

Live greenfield status → `docs/engineering/PHASE3-STATUS.md`. Backlog → `docs/BACKLOG.md` (Part 1). Parity →
`docs/engineering/PARITY-GAP.md`.

---

## Active Changes

**2026-10-13 — `phase3-bot-intake` is COMPLETE and archived** (`openspec/changes/archive/2026-10-13-phase3-bot-intake`). Live VM round passed with inbound auth on every node (#156); results in `docs/engineering/vm-test-2026-10-12.md` (2026-10-13 addendum).

**Earlier the same day — report intake is merged; `phase3-bot-intake` Groups 0–3 were complete, Group 4 next.**

- **`phase3-report-intake`** — **groups 1–4 merged** (#138–#141: the one `POST /intake` door, the
  server-side converters, the receipt, and the GUI + scripts uploading through it). Beside them, **#142**
  the dashboard's password login and Admin tab, and **#143** the 2026-10-12 VM round (intake dedup fix,
  the upgrade runbook, the test log). Later groups are still open in the change.
- **`phase3-bot-intake`** — **Gate A approved and merged** (#144, `69bada2`): EDR-INTAKE-01's 2026-10-12
  amendment ("Bot-friendly intake", `B1`–`B7` + the status-code table) plus proposal/design/tasks.
  **Documents only — no code in #144.**
  **Gate B — `Group 0` + `Group 1` — is COMPLETE** (#145–#148 plus 1.9–1.11; 0.1 and 1.1–1.11 all
  ticked in the change's `tasks.md`): the four new reject reasons as vocabulary, Registry uniqueness
  enforced by the database (migration `000003`: a pre-flight that refuses by name, then three named
  unique indexes), idempotent find-or-create on the three creates answering `201`/`200`, and B4's
  honest abstention — `ProductIDByName` / `ProjectIDByName` / `ReleaseIDByVersion` in
  `registry/adapters/store` return `app.ErrAmbiguousName` on `>1` (`ReleaseIDByVersion` no longer
  picks the first match), which `cmd/evidence` translates into `subjectref.ErrAmbiguousName` so no
  registry error value crosses the seam, and the resolver refuses with `ambiguous_name` worded as
  **ambiguous**, never as not-registered.
  **Gate C — `Group 2` — is COMPLETE** (#149–#152 plus 2.7–2.11; 2.1–2.11 all ticked in the
  change's `tasks.md`): intake's bot road, end to end. `create_release=true` with the whole
  `{product, project, version}` triple finds-or-creates **the version only**, through Registry's
  own idempotent upsert, at B7's **step 8** — after every border check and immediately before
  filing, so a refused submission creates nothing. Both doors authorize the **resolved Product**
  read-only before anything is written, and for a `product:<id>` key the refusals B3 requires to be
  indistinguishable — another product's name, no such name, an ambiguous name, another product's
  release id, a release id that does not exist — are equal **as bytes** (one detail constant, and
  the `403` names no receipt, because a fresh `intake_id` could never be byte-identical). `build_id`
  is captured as artifact provenance on the evidence row and echoed on the receipt, and is
  deliberately **inert**: it takes no part in dedup, so a byte-identical retry keeps the FIRST
  upload's build id while the retry's value appears only on its own receipt — the two differ by
  design, and that is now asserted rather than assumed. B6's unchanged behaviours carry regression
  guards (`409 duplicate_other_release`; a different SBOM for the same release still filed as new
  history, which **EDR-DELIVERY-01 M2-5** rests on; D6's SBOM-before-report, including a brand-new
  version with the provisioner uncalled). Architecture: the Evidence→Registry seam's exported write
  surface is exactly one method, and **no `internal/evidence/…` package imports
  `internal/registry/…`** — only `cmd/evidence` may.
  One shared-gate change came with the group gate: `evidence/adapters/store` moved from the **80%
  aggregate-store tier to the 90% adapter tier** in `scripts/check-coverage.sh` (86% → **93.6%**),
  because the branches that justified the lower tier turned out not to need pool-fault injection —
  a cancelled context reaches every read, both receipt sweeps, `Save`'s `Begin` and the relay's two
  fault windows, pinned as *a read that could not be performed is never reported as an absence*.
  The other aggregate stores are untouched at 80%, and the injectable-pgxpool follow-up still owns
  the mid-transaction residue.
  **Gate D — `Group 3` — is COMPLETE** (3.1–3.6 ticked in the change's `tasks.md`): **documents and
  one script, no Go code.** `scripts/gf-upload-sbom.sh` gained `-c` (`create_release=true` — the whole
  triple required explicitly, incompatible with `-r`, and **no Registry call at all**) and `-b`
  (`build_id`), with the triple percent-encoded through `jq @uri` because curl's `-G` would move the
  `--data-binary` document into the query string, and the release id read off the receipt's
  `release_id` since on that road the server is what knows it. INSTALLATION.md **§5b** is the
  CI-pipeline runbook — two requests, SBOM first, the triple + `create_release=true`, `build_id`,
  minting a `product:<id>` key with `cmd/authadmin`, and the `403` stated plainly as *this key is not
  for this product* rather than *that product does not exist*, with Products and Projects created by a
  human first. TESTING.md **§ bot intake** carries the amendment's 19-row status-code table **copied,
  not paraphrased** (and the rows-5-and-6 note with it), restates that D6's SBOM-before-report rule
  holds **across** the two requests, and adds paste-safe `--fail-with-body` + `X-API-Key` examples
  including the byte-identical-`403` comparison. EDR-SECURITY-01's realization notes now record that
  D4's product-scope deferral is closed for **both** Evidence write doors — `POST /intake` **and**
  `POST /evidence` authorize `admin` or the release's owning product, read-only, fail-closed and
  non-disclosing — while the rest of the Evidence write surface keeps the method-based floor.
  **Group 4 (Gates E–F) — verification on the VM — is NEXT and is all that remains**: the duplicate
  census re-run before `000003` reaches the estate (stop if it finds any — resolving one is an estate
  decision, not a migration), the two-request `-tags=e2e` bot test, the non-leak matrix on a real
  auth-enabled node, two concurrent `create_release=true` requests for one unregistered version,
  `vm-verify.sh` still reading the expected migration version from the migrations directory, then the
  final gate and `openspec archive phase3-bot-intake --skip-specs -y`.
  Three things Group 3 left alone on purpose, because it carries no code change:
  `api/evidence.openapi.yaml` still declares no **`403`** response on `POST /intake` or
  `POST /evidence` though both doors can answer one (the body shape is the already-declared
  `IntakeProblem` / `Problem`, so the addition is additive — but it needs
  `make generate-api-evidence`); `EvidenceFacts` does not expose `provenance_build_id`, so the
  filed-vs-receipt `build_id` asymmetry is observable only in the column, which TESTING.md says
  outright instead of implying a read API that does not exist; and `gf-upload-sbom.sh`'s
  long-standing extension strip stays unconditional, so `-p my.app` is still sent as `my` — a
  first pass narrowed it to the derived default, which is a behaviour change 3.1 forbids, so it was
  reverted and the limit is documented in `usage()` pending the owner's call (on the `-c` road a
  truncated product name lands as B3's non-disclosing `403`).
- Other scaffolded `phase3-*` changes under `openspec/changes/` carry their own state in their
  `tasks.md`; this file records the resume pointer, never per-task state.

Live greenfield narrative and the resume point → `docs/engineering/PHASE3-STATUS.md`.

## Archived Phase-3 changes

The greenfield rebuild shipped as these changes, all under `openspec/changes/archive/`. (`phase3-*` changes
carry **no `specs/` deltas** — EDRs are the source of truth — so each was archived with `--skip-specs`.)

| Change | Milestone | Tasks | Archived |
| --- | --- | --- | --- |
| `phase3-shared-kernel` | M2 — Kernel value objects + Registry identity | 20/20 | 2026-07-25 |
| `phase3-evidence` | M6 — Evidence (content-addressed SBOM/VEX + inventory) | 7/7 | 2026-07-25 |
| `phase3-knowledge` | M7 — Knowledge / Faultline aggregate + reconciliation | 25/25 | 2026-07-25 |
| `phase3-knowledge-feeds` | M7+ — real OSV/NVD clients · CVSS-4.0 (D-NVD-2) · source tiers (D-FEED-2) · scanner Proposals | 19/19 | 2026-07-23 |
| `phase3-governance` | M8 — Findings + append-only Enterprise Positions | 24/24 | 2026-07-25 |
| `phase3-communication` | M9 — Publication aggregate + 6-serializer registry | 22/22 | 2026-07-25 |
| `phase3-intelligence` | M4 — AI Gateway Δ1 (reactive `recommend_position`) | 37/37 | 2026-07-25 |
| `phase3-intelligence-d2` | M4 — Δ2: `[Rule → LLM]` dispatch + admission spine + `insufficient` | 9/9 | 2026-07-25 |
| `phase3-event-infrastructure` | M5 — the platform event bus (`EDR-EVENTBUS-01` D1–D11) | 43/43 | 2026-07-29 |
| `phase3-trust-model` | the enterprise trust model (`EDR-TRUST-01` T1–T12) — cross-context: Knowledge + Governance + Intelligence | 63/63 | 2026-08-06 |
| `phase3-{shared-kernel,evidence}-prescaffold` | pre-scaffold drafts (superseded by the real changes) | — | 2026-07-15 |

Post-M5 parity / VEX / auth / estate / D14 work (parity clusters, EDR-VEX-01 Phase 1–3, EDR-SECURITY-01,
EDR-ESTATE-01, EDR-GOVERNANCE-01 D14) landed on `main` via its EDRs + `PARITY-GAP.md` / `BACKLOG.md` — **not**
as OpenSpec changes. Detail lives there, not here.

### Superseded legacy proposals (frozen v0.3.x era)

| Change | Note |
| --- | --- |
| Layer-0 refactor (CR-1…CR-10) | Released v0.3.0 (2026-06-24); closed D-CVSS-1 / D-FEED-1 / D-NVD-1 / D-LOG-1 |
| ~~themis-phase-2~~ | Archived 2026-07-14 — superseded by `docs/architecture/` + `docs/adr/`; reference input for Phase-3 grilling |
| ~~themis-ai-1~~ | Archived 2026-07-14 — never built; AI design folded into Phase-3 Intelligence (M4) |
| ~~themis-phase-2b / 2c~~ | Superseded by the greenfield rebuild (2c → Governance/Intelligence roadmap) |

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
| `v0.3.10` | `79bfb84` | Housekeeping — archive `themis-core-model`, sync delta specs into `openspec/specs/`, refresh status/context docs to v0.3.9 |
| `v0.3.11` | (PR #47) | Housekeeping — consolidate docs under `docs/` (release-notes / current-changes / architecture) + refresh stale context |
| `v0.4.0` | `6e03396` (2026-08-02) | **First greenfield release** — the bounded-context platform: the whole pipeline over the event bus (M2/M6/M7/M8/M9/M5 + M4 Δ1/Δ2) + opt-in relevance-bounded feeds + governed vendor-VEX suppression (EDR-VEX-01) + estate/blast-radius (C1/C2) + inbound API-key auth (EDR-SECURITY-01). Monolith frozen at `v0.3.11`. |
| `v0.4.x` | — (next) | **AI-capability expansion** — GOV-14 (EDR-GOVERNANCE-01 D14), Intelligence Δ3 (Python + RAG/pgvector), Δ4 (autonomy + LLMOps) |

## Roadmap

**Legacy v0.3.x monolith line (frozen, reference-only):**

| Phase | Change | Theme | State |
| --- | --- | --- | --- |
| Phase 1 | themis-phase-1 | Core intelligence platform — Go REST API + PostgreSQL | Released v0.1.0 (2026-06-09) |
| Phase 2a | themis-phase-2a | Signal Foundation — feeds, graph entities, VEX export | Released v0.2.0 (2026-06-17) |
| — | (maintenance) | Feed reliability + Phase 1 hardening | Released v0.2.1 |
| core-model + Layer-0 | themis-core-model + CR-1…CR-10 | Schema restructure (breaking) + correlation/feeder/observability refactor | Released v0.3.0 (2026-06-24) |
| — | (maintenance) | Correlation/VEX correctness + ergonomics on the v0.3.0 schema | Released v0.3.2–v0.3.11 |

The former monolith roadmap (**Phase 2b** AI Intelligence, **Phase 2c** AI-Assisted VEX, **Phase 3**
Docker/UI/RBAC) was **superseded by the Phase-3 greenfield rebuild** — those capabilities are delivered in the
bounded-context services instead (AI Intelligence → the M4 Intelligence gateway; AI-Assisted VEX → EDR-VEX-01
+ Intelligence Δ3/Δ4).

**Greenfield line (go-forward):**

| Release | Delivers | State |
| --- | --- | --- |
| v0.4.0 | The bounded-context platform — M2/M6/M7/M8/M9/M5 + M4 Δ1/Δ2 + parity/VEX/auth/estate | Released 2026-08-02 |
| v0.4.x | AI-capability expansion — GOV-14 (D14), Intelligence Δ3 (Python + RAG/pgvector), Δ4 (autonomy + LLMOps) | **Next** |

Greenfield milestone map + resume point: `docs/engineering/PHASE3-STATUS.md`.

Cross-phase intelligence source-tier classification: `openspec/intel-source-tiers.md`

`openspec/specs/` holds the **frozen v0.3.x** capability specs (17 capabilities, Phase 1 + 2a merged) — a
legacy reference only. Greenfield `phase3-*` changes carry **no `specs/` deltas**; their source of truth is
the per-context EDRs (`docs/engineering/decisions/`), which is why `openspec archive` runs with `--skip-specs`.
