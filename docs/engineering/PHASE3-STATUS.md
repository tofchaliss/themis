# Phase-3 Greenfield Rebuild — Status & Resume Point

**Updated:** 2026-08-27 · **Read this first when resuming.** Open work is tracked ONLY in
[`docs/BACKLOG.md`](../BACKLOG.md) (tracking rule agreed 2026-08-27) — this file carries the narrative
and the resume pointer, never item state.

> ## ⏭ RESUME 2026-08-24 — next up is the **Δ4 grill** (design-first, no code yet)
>
> The tiered enhancement roadmap (`EDR-ENHANCE-T1…T5`) drove several arcs to `main` and each was
> **live-verified on the VM** the same or next day. Current `main` = `25c5335`; `make check-ci` green.
>
> **Shipped + live-verified since the 2026-08-19 compare-read release (v0.4.2):**
> - **T2 correctness:** GOV-15/**D17** — `effective`/`residual` priority UNCLAMPED (0–200 ranking numbers;
>   the 100-clamp destroyed triage order at a saturated estate). Live: 12-customer estate → 2.0×,
>   CVE-2019-10086 at eff **152** leading the queue. · **R6/F5** — `internal/platform/health` (4th platform
>   pkg): `/healthz`+`/readyz` on all nodes + fresh-connection credential watch + systemd `StartLimitBurst`.
>   Live: readyz green all six. · EV-DEDUP-2 design = **EDR-EVIDENCE-01 D10 (PROPOSED)** filings model.
>   GUI-11 re-scoped design-first (aliases aren't persisted).
> - **T5/R1 AI chain — the whole pre-Δ4 surface:** **AI-CMP-1** `compare_releases@v1` (Information; ordered
>   [baseline,candidate]; grounded verbatim on the D16 read; live 200 vs CyberPal, e2e-llm PASS). ·
>   **G-AI-3** delta-aware precedent ranking (release-overlap weight in the one PrecedentService seam; live
>   `release_overlap`). · **AI-TEL-1** invocation-total tokens · **AI-204-2** deterministic decline detail ·
>   **G-AI-2(c)** classification half (`decline_class` + `themis_ai_declines_total`) · **G-AI-4** per-run
>   token ceiling · **G-AI-1 half (a)** on-demand `POST /faultlines/gather` (live: fetched a fresh CVE) ·
>   **G-AI-5** deferral confirmed + guarded by `TestEveryShippedCapabilityIsLocalOnly`.
> - **e2e-llm** now drives all four capabilities; **4/4 PASS on cyberpal20b** (2026-08-24). The PLAN-4
>   merged-step citation regression is confirmed dead.
> - v0.4.2 tagged (2026-08-21). Two LOW gaps filed from the VM round: **AI-CMP-1b** (Information path
>   doesn't validate the model's `subject_id` echo) · **AI-PROSE-1** (narration renders priority numbers as
>   words — expected; the gate anchors to identifiers, not prose arithmetic).
>
> **Δ4a GRILLED + DESIGNED (2026-08-24, no code):** the Δ4 split was accepted (Δ4a store+LLMOps first, Δ4b
> autonomy next). Δ4a's eight decisions are in **EDR-INTELLIGENCE-01 § Δ4a** (D-Δ4a-1…6) and scaffolded as
> **`openspec/changes/phase3-intelligence-d4a`** (proposal/design/tasks). Net shape: co-locate an operational
> store in the existing `intelligence` DB (capped invocation log · durable golden set · eval reports · version
> stamp) + an offline live-model eval command — NO DB prompt registry, NO model registry, NO automated
> promotion, NO scheduled loop, NO CI net. **Δ4a IMPLEMENTED (2026-08-24, 5 groups, `make check-ci` green): store (migrations 000003:
> invocation_log · golden_entries · eval_reports · prompt_versions), a content-hash prompt version
> stamp, redacted best-effort capture + boot version-seed + age retention, and `cmd/intelligence-eval`
> (`make eval-llm`) — replay the golden set through a live model, score deterministically, promote
> curated cases. Grill state in [`DELTA4-GRILL-PREP.md`](DELTA4-GRILL-PREP.md).
>
> **Δ4 COMPLETE + VM-VERIFIED (2026-08-26).** Δ4b (autonomy walking skeleton) grilled, implemented,
> merged: one cross-release consistency analyst, default-OFF cadence, separate capped pool, idempotent
> pushes, and the immovable authority bar (`TestAIProposalNeverAutoAccepts`). VM round:
> - **Δ4a** full loop `1/1 passed` — capture→promote→replay→score on a real CyberPal invocation.
> - **Δ4b SAFE** — `decided_findings=0`, every autonomous `ai` proposal stays `proposed`, the
>   constitutional bar held at volume; **IDEMPOTENT** — `autonomous_proposals` held at 110 across ~6h
>   of 2m ticks (dozens of sweeps re-proposed nothing).
> - Four defects found LIVE, all FIXED (JSONB-vs-redacted-string capture, cancelled-capture-context,
>   eval-promote flag-order, and **AUTO-VOL-1** — 110 proposals in one sweep, the volume the design feared).
>
> **AUTO-VOL-1 DONE + LIVE-VERIFIED (2026-08-26, `feat/auto-vol-1`).** `bestQualifyingPrecedent` gates on
> min cosine (0.75) + known min release-overlap (0.5, the G-AI-3 delta; exact-CVE fallback exempt) and a
> per-sweep `maxPerPass` cap (20, worst-first, `Capped` flagged); operator-tunable via
> `THEMIS_INTELLIGENCE_AUTO_MIN_SCORE`/`_AUTO_MIN_OVERLAP`/`_AUTO_MAX_PER_PASS`. VM re-test on the same
> 215-Finding estate: four 2m sweeps each `proposed=20 capped=true`, `skipped` 107→127→147→167 (+20/pass
> = idempotence), `ai_accepted=0`, decided count unmoved. 110→20. app-ring coverage 100%, `make check-ci`
> green. EDR D-Δ4b-7 records it.
>
> **GUI-2b DONE (2026-08-27, `feat/knowledge-apk-verdict`, unmerged).** Grilled → **EDR-VEX-01 D9**
> and shipped the same session: `value.APKFixedByBounds` (max-bound over strictly-`apk`-stamped
> bounds, fail-closed) + `EnterpriseView.StrictFixesFor` + the correlation gate beside the rpm
> verdict; the pre-existing apk comparator defect (lexicographic `r5` > `r10`, `rc1` above release —
> reached the range gate) found and fixed; `make check` green, 100% tiers, rapid properties. Live
> verification waits on an Alpine estate. GUI-2c (precise branch scoping) filed, consciously deferred.
>
> **GUI-3 + GUI-5 DONE (2026-08-27, same branch) — the Distro-feed completeness cluster is COMPLETE.**
> GUI-3: step zero verified NO (VEXFEED covers only `not_affected`), so the **D10** modified-since gate
> ships in the Red Hat sweep — the per-CVE VEX `changes.csv` (verified live) feeds a fail-open
> `RedHatChangeSignal`: first sweep full, then changed-or-never-fetched only; signal failure → full
> sweep; restart heals. GUI-5: **D11** `rocky` feed — RXSA-only (29-advisory universe measured live;
> RLSA clones stay with the Red Hat feed), source-package rpm fixes, SeverityUnknown, Observed/Tier-2,
> opt-in `THEMIS_ROCKY_ENABLED`. `make check` green; app 100%, new adapters covered.
>
> **NEXT = the consolidated VM test round** (GUI-2b needs an Alpine SBOM · D10 gate log lines · rocky
> feed + health row), then **GUI-12** per the after-cluster order. GUI-2's bounds half and GUI-4
> shipped 2026-08-13 (PR #95). The deferred Δ4b refinements wait on demand; R1/AI harness is COMPLETE.

**Historical snapshot below (2026-08-06).**

Phase-3 is a **greenfield DDD rebuild** of Themis into four bounded contexts —
**Evidence → Knowledge → Governance → Communication** — plus an Intelligence Gateway, realized from the
architecture book (`docs/architecture/` Books I–III) and the **69 ADRs** (`docs/adr/`). It is the **sole
go-forward**; the current architecture is **frozen at v0.3.x**.

> **Resume snapshot (2026-07-27 session):** The four-context pipeline **plus M4 Intelligence Δ1 + Δ2** is
> IMPLEMENTED, gated, and **merged to `main`** (`origin/main` = `762bbac`). Two more PRs landed on `main` this
> session: **#53 — CI** (`.github/workflows/{pr,main}.yml` running a **greenfield-scoped `make check-ci`**;
> whole-repo `make check` is macOS-only-green because the frozen legacy tree has a clock-precision integration
> test) plus a Faultline concurrent-fold fix; and **#54 — the consolidated `docs/BACKLOG.md`** (Part 1 active /
> Part 2 frozen, replacing the two old backlog files) + the **M5 scaffold**. **M5 — Event Infrastructure is now
> BEING IMPLEMENTED** on branch **`phase3-event-infrastructure`**: `docs/engineering/decisions/EDR-EVENTBUS-01.md`
> (D1–D11) + `openspec/changes/phase3-event-infrastructure/` (**9/43 tasks — Groups 1–2 done**, 10 groups
> EB-01…EB-11), via `/opsx:apply phase3-event-infrastructure`. To verify green on resume: **`make check-ci`**
> (the greenfield gate CI runs, not whole-repo `make check`).
>
> **Update (2026-07-29): M5 is DONE — all 10 groups (43/43), gated `make check` green + `make e2e-pipeline`
> green.** Groups 1–2 (scaffold + `Envelope` threading), Group 3 (integration-contract v1 schema guard),
> Group 4 (`Publisher` → `bus.event_log`), Group 5 (stream `Reader` — gap-free txid watermark + D8
> poison-halt), Group 6 (consumer inbox — exactly-once application), Group 7 (subscriptions — stream +
> interest set), Group 8 (`cmd/knowledge` + readers in every cmd + in-process pipeline runner), Group 9
> (black-box **SBOM → published-OpenVEX** e2e + focused D5/D6/D8 tests + the "no synchronous cross-context
> orchestration" arch assertion), Group 10 (docs). **The pipeline flows end-to-end over the real Postgres
> bus.** Remaining maturations are tracked, not blocking: the D8 subject-aware scheduler (M5 ships stream-halt)
> and the D9 explicit integration DTOs (M5 froze the current wire shapes as v1).
>
> **Update (2026-07-30): deployed end-to-end on a Linux VM + first parity cluster closed.** The full
> post-M5 stack was brought up from scratch on Ubuntu 24.04 — all six services under **systemd**, a real
> 542/556-component OAMP image SBOM driven through to a published OpenVEX, and **cyberpal (Ollama)** as the
> reactive AI plane. Landed on `main` this session:
> - **PR #59 — post-M5 deployment hardening.** `INSTALLATION.md` Part A rewritten for the real M5 world
>   (the `THEMIS_BUS_DATABASE_DSN` switch, database-per-context + `bus`, ordered 6-service runbook, the
>   Ollama/cyberpal + on-demand `/recommend` seam, a systemd step); `deploy/systemd/` (templated
>   `themis@.service` + installer); `scripts/gf-upload-sbom.sh` (greenfield register+upload, streams large
>   SBOMs); and a **real correlation bug fix** — a shared-CVE SBOM used to poison-halt the Evidence stream
>   (GetByCVE read the pool while Save joined the inbox tx); fixed with tx-aware reads + a savepoint
>   (`TestInboxCorrelatesSharedCVEWithoutHalt`). Deployment defects logged in `docs/BACKLOG.md`.
> - **Monolith→greenfield parity analysis** — full capability diff captured in
>   [`docs/engineering/PARITY-GAP.md`](PARITY-GAP.md).
> - **First parity cluster (intelligence/enrichment) — 4 PRs merged (#60–#63):** distro (rpm) correlation
>   via OSV, format-agnostic (Evidence captures the source-package name; #60); **NVD** modified-since
>   CVSS/severity enrichment, relevance-bounded (#61); **EPSS / KEV / ExploitDB** signal enrichment (#62);
>   deterministic **priority level + composite score** on the Faultline (#63). All the enrichment feeds are
>   **opt-in** (`THEMIS_NVD_ENABLED`, `THEMIS_EPSSKEV_ENABLED`) and respect D5 (enrich existing cards, never
>   mirror the feed). A greenfield Faultline now correlates language + distro packages and carries
>   authoritative CVSS + EPSS + KEV + public-exploit + a 0–100 score.
> - **Remaining parity gaps (delivery/security cluster):** real notifications (Communication's `LogDeliverer`
>   stub → SMTP/Teams), the org blast-radius graph (Product→…→Customer + the score multiplier), and API auth
>   (no auth on any greenfield endpoint). Plus tracked follow-ups: NVD by-CVE backfill, per-Finding blast
>   multiplier, distro ubuntu/suse mapping, and the per-record ACL tidy-up (BACKLOG §C).

> **Update (2026-07-31): full parity audit + six clusters advanced (9 PRs, all off `main`, all CI-green,
> awaiting merge).** A 6-reader two-tree code audit rewrote [`PARITY-GAP.md`](PARITY-GAP.md) into the complete
> gap inventory (stable IDs A1–F8) and corrected the "correlation CLOSED" claim. Design-first throughout —
> **four new decision records**: `EDR-SECURITY-01`, `EDR-ESTATE-01`, `EDR-VEX-01` (+ realization notes on
> `EDR-KNOWLEDGE-01`). Landed as PRs:
> - **#65 — F1/F2/F3 auth.** `internal/platform/auth` (the 3rd shared platform package): `X-API-Key` bcrypt
>   store + method-based scopes, HMAC webhook seam, `cmd/authadmin`; wired across all six services behind
>   `THEMIS_AUTH_DATABASE_DSN` (opt-in; `THEMIS_AUTH_REQUIRED=1` prod guard). Closed the "zero inbound auth" gap.
> - **#66 — B1 feed-health.** Wired the unwired `feedtier.go` policy end-to-end: `feed_health` store, per-poll
>   recording, `GET /feeds` (`signals_stale` + `degraded_feeds`).
> - **#67 — no-AI SBOM→VEX CI gate.** `tests/pipeline` now registers a real release via Registry and runs on
>   every PR (`pr.yml`); the runbook's no-AI path made explicit.
> - **#68 → #69 (stacked) — A1 + A2 correlation depth.** A1 wires the reconciled range gate into correlation
>   (realizes D3 — was trusting OSV's server filter); A2 makes NVD a bounded, opt-in discovery source
>   (keyword + CPE-product + version triple-gated). **Merge #68 before #69.**
> - **#71 — C1/C2/C6 estate & blast-radius.** Registry estate graph (Product→Microservice→Deployment→Customer
>   + `GET /releases/{id}/blast-radius`), the base score threaded to Governance (C6), and the blast multiplier
>   applied to Finding priority (`base × 1.0–2.0×`, fail-safe 1.0×). A vuln in a 40-customer service now
>   outranks it in a zero-customer dev tool.
> - **#73 — vendor-VEX ingest (EDR-VEX-01 Phase 1).** Uploaded OpenVEX → `applicability` Proposals on the card
>   (Evidence serves raw bytes; Knowledge parses; the card carries, never suppresses). **Phase 2** (Governance
>   suppression overlay — the visible payoff) and **Phase 3** (Red Hat CSAF / generic crawler feeds, B3/B4)
>   remain.
> - **Net:** the intelligence/enrichment, correlation-depth, risk-fidelity, and edge-security halves of parity
>   are essentially closed; the longer tail (A3–A6, B2/B5/B6, C3–C5, D2–D7 notifications, E1–E11 input-integrity,
>   F4–F8 metrics/traces/probes) is fully enumerated in PARITY-GAP.md with priorities.

> **Update (2026-08-03): v0.4.0 shipped — the first greenfield release (`6e03396`, tagged 2026-08-02).**
> Everything above merged to `main`, and the EDR-VEX-01 vendor-VEX line completed end-to-end. Landed this
> session:
> - **EDR-VEX-01 Phase 2 — governed suppression overlay.** A reconciled `not_affected` (uploaded or fed)
>   raises a **system Proposal** on the covered Finding that policy auto-accepts or a human decides — it never
>   auto-suppresses ("Gathering Is Not Knowing"). Package-scoped matching prevents over-suppression.
> - **EDR-VEX-01 Phase 3 — vendor feeds.** The **Red Hat** relevance-bounded feed (per-CVE vendor severity +
>   `not_affected` applicability + RPM fixed-version bounds; covers RHEL/Rocky/Alma via clone) and a **generic
>   CSAF-VEX** directory feed (B4), plus a **stream-scoped RPM fixed verdict** (a `pkg:rpm/…` at/above its
>   same-EL-stream fix opens no Finding; an unpatched build still does). Both opt-in, both D5-bounded.
> - **Correctness fixes:** OSV **`upstream`** distro correlation (RHEL/Rocky/Alma advisories via the upstream
>   CVE), **path-safe** VEX proposal ids, **package-scoped** Red Hat applicability, and eventbus **D7**
>   (Preparer read/write split). Provider timeout is now configurable (`THEMIS_LLM_TIMEOUT`, default 60s → a
>   slow local model returns an honest `insufficient` 204, not a hang).
> - **GOV-14 (EDR-GOVERNANCE-01 D14) — decided this release, implemented next:** a disposition-aware
>   `residual_priority` on the posture + a deterministic **disposition re-evaluation watcher** (KEV /
>   EPSS-threshold / new exploit / reversing VEX → re-surface a suppressed or accepted Finding), AI-judge optional.
> - **Net: current development (pipeline + parity + vendor-VEX) is done and released.** The next line is
>   **AI-capability expansion** — GOV-14 implementation, then Intelligence **Δ3** (Python + RAG/pgvector) and
>   **Δ4** (autonomy + LLMOps).

> **Update (2026-08-03, later): Intelligence Δ3 RAG integration — designed + decided (docs only, staged).**
> A 3-session evaluation under `docs/engineering/` chose the RAG stack against the real use cases:
> - **`RAG-INTEGRATION-OPTIONS.md`** (S1) — two-axis survey (vector store × orchestration) + scored matrix.
> - **`RAG-SESSION-2-SPIKE.md`** (S2) — a real pure-Go cosine benchmark: **~47 ms/query @ 50k** single-thread,
>   ~150 MB (corrected an earlier "<10 ms" guess); persist embeddings in plain Postgres, load on boot.
> - **`RAG-SESSION-3-DECISION.md`** (S3) — the decision record (R1–R6).
> - Folded into **`EDR-INTELLIGENCE-01` Revision 4** (Δ3 concrete cut) + **STACK.md** reconciled.
>
> **Decision:** Δ3a = semantic precedent for `recommend_position` (G-AI-3) via **in-memory Go search over
> plain-Postgres-persisted embeddings** (no pgvector — corpus ≤~50k), hand-rolled Go retrieval; Python DSPy
> deferred to Δ3b; pgvector/Qdrant = port-swap upgrades. Demo target = use-case **#4 triage automation**.
> **Open:** R5 embedding-model pick (`nomic-embed-text`) pending a local Ollama eval (`RAG-SESSION-2-SPIKE.md`
> §4). Also today (housekeeping): reconciled `openspec/STATUS.md` + `openspec/config.yaml` to the v0.4.0
> reality, refreshed this resume point, and added a `THEMIS_LLM_TIMEOUT` note to `CLAUDE.md`. **All docs
> staged, uncommitted.** Resume at the Next-action § below.

> **Update (2026-08-04): `/repository-discovery` for Δ3a + Book IV Chapter 8 restructured around Semantic
> Retrieval.** Two read-only recon agents mapped the Intelligence seams (VectorIndex/Embedder ports absent →
> additive; `EngineKnowledge` a new kind on the existing plan-walk; `AssembledContext.Precedents` exists but
> its element type lacks `SourceCVE`/`Score`; Intelligence has **no datastore + no bus reader today** → Δ3a
> introduces both = CLAUDE.md "Must ask") and confirmed the reuse patterns (Knowledge bus consumer + inbox,
> Governance store + migrations, `.golangci.yml` intelligence allow-lists). **Book IV** (`docs/architecture/
> 04-ai/`) Chapter 8 was rewritten from "RAG = external-only" to **Semantic Retrieval over three Knowledge
> Spaces**: KS1 System of Record (Themis) · KS2 Operational Semantic Index (AI Runtime, derived/rebuildable) ·
> KS3 Supporting Documentation (external). Key idea: **the retrieval mechanism is independent of the corpus** —
> so Δ3a = **RC-1** (semantic precedent over Enterprise Positions, KS1→KS2) is the *first* capability, and
> external-doc RAG = **RC-2** (KS3→KS2) is a later corpus behind the same `VectorIndex` port; principle
> unchanged (AI never owns truth). Also updated Book IV Principle 7/9, WF-004, two diagrams + ownership map,
> and cross-linked EDR-INTELLIGENCE-01 Rev 4 ↔ Book IV Ch 8. **Δ3a is discovery-complete but NOT started** —
> awaiting go-ahead on the Must-ask items (new `intelligence` DB, `PrecedentPosition` field add, first
> bus-consumer role). All staged, uncommitted.

> **Update (2026-08-04, end of day): Δ3a IMPLEMENTED, gated, committed + PUSHED to `origin/main`.** The whole
> RAG / Knowledge Engine shipped in six gated groups (A1–A6) plus the R5 eval harness — all on `origin/main`
> (`2c1d826`), `make check-ci` green. Commits: `fe9218e` (A1–A3 store + embedder + retrieval engine) ·
> `245adfa` (A4 bus-consumer population, exactly-once) · `3825735` (A5 plan `[Rule → Knowledge → LLM]` + A6
> wiring / cmd / e2e / docs) · `2c1d826` (R5 harness, `make e2e-embed`).
> - **Behavior:** `recommend_position` now retrieves semantically similar **past** Positions (a *different* CVE
>   on the same component) to ground — and can flip — a recommendation. Best-effort Knowledge step + exact-CVE
>   fallback ⇒ **cold-start-safe**; every failure mode degrades to no-precedent, never blocks.
> - **New surface:** Intelligence's first datastore (the optional `intelligence` DB / KS2 Operational Semantic
>   Index, derived + rebuildable) and first bus-consumer role (drains Governance Position events, exactly-once).
> - **How to test (tomorrow's first step):** `go test -run TestDemoSemanticPrecedentChangesRecommendation
>   ./internal/intelligence/adapters/wiring/` proves the demo with **no model**; **`make e2e-embed`** runs the
>   R5 retrieval-quality eval on a live Ollama (SKIPS without one). See TESTING.md §6 + RAG-SESSION-2-SPIKE §4.
> - **Only open item: run R5** on the Ollama box → confirm `nomic-embed-text` (or pick the winner + reboot with
>   `THEMIS_INTELLIGENCE_REBUILD=1`). Δ3b (Python DSPy) + Δ4 deferred; two LOW freshness follow-ups in BACKLOG §C.

---

## Ground rules (do not re-litigate)

- **ADR wins; the existing `internal/` code is PoC reference only.** Where an ADR and the PoC disagree,
  follow the ADR.
- **One EDR per context** → `docs/engineering/decisions/EDR-<CONTEXT>-NN.md`, then an OpenSpec change
  `openspec/changes/phase3-<context>/`.
- **System of record = OpenSpec** (`tasks.md` groups), **not** a GitHub/issue tracker. `/to-issues`
  publishing is intentionally not used.
- **Skills are user-invoked** (`disable-model-invocation: true`): the model cannot trigger
  `/grill-with-docs` or `/to-issues` — the user types them. `/grill-with-docs` runs `/grilling` +
  `/domain-modeling` (maintains a domain glossary + docs as it goes).

## Done so far

| Milestone | EDR | OpenSpec change | Issues |
| --- | --- | --- | --- |
| **M2 — Shared Kernel** | `EDR-KERNEL-01` (D1–D4) | `phase3-shared-kernel` — **IMPLEMENTED** (20/20, gated) | KERN-01…06 (+ M5 seed) |
| **M6 — Evidence** (exemplar) | `EDR-EVIDENCE-01` (D1–D9) | `phase3-evidence` — **IMPLEMENTED** (7/7, gated) | EVID-01…13 |
| **M7 — Knowledge / Faultline** | `EDR-KNOWLEDGE-01` (D1–D12) | `phase3-knowledge` — **IMPLEMENTED** (25/25, gated) | KNOW-01…13 |
| **M8 — Governance** (Findings + Positions) | `EDR-GOVERNANCE-01` (D1–D13) | `phase3-governance` — **IMPLEMENTED** (24/24, gated) | GOV-01…13 |
| **M9 — Communication** (publish Positions) | `EDR-COMMUNICATION-01` (D1–D12) | `phase3-communication` — **IMPLEMENTED** (22/22, gated) | COMM-01…12 |
| **M4 — Intelligence** (AI Gateway) | `EDR-INTELLIGENCE-01` (Rev 3, D1–D13 + Δ2 cut) | `phase3-intelligence` — **Δ1 IMPLEMENTED** (37/37); `phase3-intelligence-d2` — **Δ2 IMPLEMENTED** (9/9 groups, gated, 2026-07-24); Δ3–Δ4 remain | INTEL-01…12 |
| **M7+ — Knowledge feeds** (follow-on) | `EDR-KNOWLEDGE-01` (D5/D6) | `phase3-knowledge-feeds` — **IMPLEMENTED** (19/19, gated) | real OSV/NVD clients · CVSS 4.0 (go-fwd D-NVD-2) · source tiers (go-fwd D-FEED-2) · scanner Proposals |
| **M5 — Event Infrastructure** (the shared event bus) | `EDR-EVENTBUS-01` (D1–D11) | `phase3-event-infrastructure` — **IMPLEMENTED** (43/43, all 10 groups; gated `make check` + `make e2e-pipeline` green; 2026-07-29) | EB-01…EB-11 |

**Post-M5 (parity + hardening — EDR-driven, landed on `main` without an OpenSpec change; all shipped in
v0.4.0):** opt-in relevance-bounded feeds (NVD / EPSS-KEV / ExploitDB / **Red Hat** / **CSAF**);
**EDR-SECURITY-01** (F1) inbound-edge API-key auth (`internal/platform/auth` + `cmd/authadmin`);
**EDR-ESTATE-01** (C1/C2) enterprise estate graph + blast-radius priority (`base_score × blast_multiplier`,
fail-safe 1.0×); **EDR-VEX-01** Phase 1–3 governed vendor-VEX suppression (system Proposals, never
auto-suppress) + stream-scoped RPM fixed verdict; **EDR-GOVERNANCE-01 D14** (GOV-14) decided
(residual-priority + disposition re-evaluation — implementation is the next line). Detail + the full gap
inventory: [`PARITY-GAP.md`](PARITY-GAP.md) and [`docs/BACKLOG.md`](../BACKLOG.md).

All the EDR docs are lint-clean (`markdownlint-cli2`). Superseded work archived 2026-07-14:
`openspec/changes/archive/2026-07-14-themis-ai-1` (folds into Phase-3 Intelligence / M4) and
`…-themis-phase-2` (superseded reference). Each has a `SUPERSEDED.md` with a restore command.

### Key resolved cross-context facts

- **Registry** (Shared Kernel) owns **Product → Project → Release** identity only; **Governance** keeps
  Findings/Positions (ADR held on top). **No Artifact entity** — the image **digest is Evidence
  provenance**; Themis never stores images.
- Evidence's `SubjectRef` **validates a Release** via the registry's `ReleaseExists`.
- Event **envelope** lives in the kernel; the **outbox machinery is Event Infrastructure (M5)**, seeded
  by Evidence's D7.
- **Knowledge → Governance seam:** Knowledge emits `ComponentMatched` (Governance creates a Finding) and
  `FaultlineEnriched` (Governance re-evaluates existing Findings). Events fire on enterprise-view change,
  not per Proposal. A **Faultline** = one card per canonical CVE (own internal ID; CVE = alias), fed by
  source **Proposals** (CON-0002) reconciled by a fixed precedence rule; cards created **lazily** (only
  for CVEs relevant to seen components).
- **Evidence → Knowledge seam:** Knowledge reacts to `EvidenceRegistered(SBOM)`, reads `GetInventory`
  (no copy), correlates components → Faultlines.
- **Governance model (EDR-GOVERNANCE-01):** the PoC's single `risk_context.effective_state` splits into
  **two objects** — a **Finding** (release-scoped concern, one per (Release, Faultline), own investigation
  lifecycle) and an **Enterprise Position** (the authoritative decision, append-only immutable versions).
  Decisions flow **Governance Proposal → evaluate → accept/reject → Position** (DOM-0024); **AI proposes,
  authorized humans decide, Governance-owned policy rules may auto-accept**. "Proposal" is disambiguated:
  a **Knowledge Proposal** (source claim about a CVE) vs a **Governance Proposal** (proposed decision about
  a Finding). VEX **generation** moves to Communication (DOM-0025); Governance only establishes Positions.
- **Knowledge → Governance seam (locked both sides):** `ComponentMatched` → idempotent find-or-create of
  the (Release, Faultline) Finding (every match → a Finding); `FaultlineEnriched` → auto-raise a Governance
  Proposal + flag for review, **never auto-decide** (DOM-0026).
- **Governance → Communication seam (locked both sides):** Governance publishes thin `PositionEstablished`
  / `PositionRevised` events (+ read API); **Communication consumes Enterprise Positions only** (DOM-0025),
  fetches via Governance's read API, records lineage as reference handles (never copies).
- **Communication model (EDR-COMMUNICATION-01):** first-class immutable **Publication** artifact
  (permanent lineage metadata + **capped, regenerable payload** — CON-0016). **Deterministic
  materialization** Position → four artifact types (VEX / advisory / notification / audit report) with a
  hard **stance-equality invariant** (never reinterpret — CON-0010/DOM-0025). **All artifact creation is
  human-triggered** (no automation, for now — CON-0015 strict reading; delegated auto-publish deferred).
  Revision by **append-and-supersede** (both kept). Delivery via transactional outbox (exactly-once,
  channel-per-artifact, routing/digest/redaction reused from PoC `notify`). **Terminal audit events only**
  (`Publication*`), never fed upstream. Publication = own aggregate (immutable content + guarded delivery
  status). Layout `internal/communication/{domain,app,adapters}`.
- **Intelligence model (EDR-INTELLIGENCE-01):** a **supporting AI Gateway** beside the pipeline (not in the
  line), owns **no truth** — the single exclusive provider entry (INT-0059), invoked as **named
  capabilities** (INT-0058), producing **validated structured advisory Proposals** (INT-0057/0063) that
  Knowledge/Governance record + govern. **Dual-mode:** reactive (called, returns to caller) + autonomous
  engine (scheduled analysts push cross-cutting Proposals to proposal-intake) — **both advisory-only**;
  **ship reactive first.** Guardrail: autonomy of *generation* yes, of *authority* never (INT-0056/0066,
  CON-0015); confidence is a **governance-policy input**, not self-authority. Gateway internals:
  deterministic Context Construction via **Knowledge Providers** (read APIs, never DB — INT-0061/0068);
  prompt + model routing are Gateway infra (INT-0060/0062); mandatory **3-stage validation** (INT-0063);
  **budget governance** (per-run/context/autonomous-pool/global, degrade-not-fail, **local-model-first**);
  **pre-invocation security/privacy** (INT-0069, sensitive → local-only); **OpenTelemetry** + eval loop
  (acceptance-rate → routing/versioning, never truth); Capability Registry + independent versioning +
  Gateway-confined provider adapters (INT-0067/0070). **Independently deployable** service (API + events).

## Context / milestone map

```text
M2 Shared Kernel ──► M6 Evidence ──► M7 Knowledge ──► M8 Governance ──► M9 Communication
                                     (M4 Intelligence Gateway feeds Knowledge/Governance)
                                     (M5 Event Infrastructure = outbox + bus, used by all)
```

## Testing strategy (staged) — decided 2026-07-16

Test each context **per-context** as it lands; **defer the full cross-context pipeline e2e** until the
pipeline is actually wired (it needs M5 Event Infrastructure + the downstream contexts). Contexts are
decoupled by events + read APIs, so a per-context e2e validates the exact contract downstream contexts
depend on — no throwaway. Add a **thin seam test** each time a consuming context arrives; save the one true
SBOM → published-VEX e2e for last.

| Test level | Build it when |
| --- | --- |
| Per-context e2e (own REST API + real DB) | with each context — **Evidence done** (see below) |
| Evidence→Knowledge seam (`EvidenceRegistered` + `GetInventory`) | when Knowledge lands |
| Knowledge→Governance seam (`ComponentMatched` / `FaultlineEnriched`) | **Governance done** — inbound consumer tests drive the exact wire JSON |
| Governance→Communication seam (`PositionEstablished` / `PositionRevised`) | **Communication done** — inbound consumer tests + Governance read-API client (httptest) drive the exact wire JSON |
| Full-pipeline e2e (SBOM → published VEX) | **all four contexts + seams built**; the single wired SBOM→published-VEX e2e still awaits **M5 Event Infrastructure** (the bus that carries the events the per-context consumers already parse) |

Evidence's per-context e2e is a 5-scenario suite (happy CycloneDX, SPDX, unknown-release 422,
unsupported-format 422, concurrent-duplicate); baseline + test-learnings in
`docs/engineering/EVIDENCE-VERIFICATION.md`.

## Next action (resume here)

**2026-08-06 — the trust model was discovered; the AI line is re-ordered. START HERE.** A capability-surface
audit (one AI capability implemented; **0 of Book IV's 9 AI workflows**) opened a design session that escalated
from "widen the Gateway's invocation surface" into **the enterprise trust model**. Captured as
**[`EDR-TRUST-01`](decisions/EDR-TRUST-01.md)** (**ACCEPTED** — grilled + closed 2026-08-06, T1–T12) with coordinated updates to **Book I-adjacent
vocabulary** (Book II Ch 2 §2.7 + **Domain Invariant 4 — Trust Is Inherited, Never Granted**), **Book III
Ch 16** (Domain Projections + Deterministic Inference), and **Book IV** (§2.1–2.3 capability classes,
runtime contract, principles 10–17). `EDR-INTELLIGENCE-01` **Revision 5 is SUPERSEDED** by it the same day.

What changed, in one line each: trust derives from **evidence provenance**, not the producing component ·
three classes **Observed / Asserted / Inferred**, propagating **monotonically** · **Inferred is
constitutionally barred from auto-acceptance** · **Deterministic Inference** runs provable rules before AI —
a **stage, not a service**, executed inside evidence-owning contexts (**behaviour follows ownership**: new
evidence justifies a context, never new rules), and the version-range rule **moves out of** the AI runtime ·
capabilities are **Information** or
**Decision**, and only Decision outputs enter Governance · the context owning a Selection Type produces
authoritative, business-named **Domain Projections** (`ReleasePosture` is the first — the pattern already
works) while capability-specific shaping stays **in-memory and unpersisted**, bounding the runtime to **four
rules** (no orchestration · information-preserving shaping · full provenance · grounding anchors to authority;
rewrites `EDR-INTELLIGENCE-01` **D5**, amends **D2**) · **Selection** (type + set + cardinality) replaces the
bare finding-id subject.

**IMPLEMENTED 2026-08-06 — `phase3-trust-model`, all 11 groups, on branch
`docs/2026-08-06-trust-model`.** `make check-ci` + `make e2e-pipeline` green at every group boundary.
What shipped, in order: `TrustClass` in the kernel · source classification + per-field-group trust on the
reconciled view · trust across the Knowledge→Governance seam (additive on v1, **no v2**) · the
**constitutional stage** barring `Inferred` auto-acceptance under any policy · reservations derived from
immutable `PositionInputs` (never a state) · **Deterministic Inference** re-evaluating existing Findings
against the reconciled range · the version-range rule **deleted from the AI runtime** · **Selection**
replacing the bare finding id · **Domain Projections** (`AssembleContext` deleted, closing **G-AI-6**) ·
**Information vs Decision** capability classes + **Business Verification** in Governance · docs.

**Three tasks were wrong as written and were corrected against the code**, which is the pattern worth
carrying into the next change: T6's "drop the producer check" (it is an *authority* rule, not a trust one);
group 3's "mint a v2 schema" (the house pattern is additive-optional on v1, used twice already); and group
6's premise (Knowledge already ran a version-range check — as a **filter at match time**, so the real gap was
a Finding born *before* the range was known, which nothing revisited). Writing tasks before touching code
buys sequencing, not correctness.

**Reading order for a reviewer:** `EDR-TRUST-01` (T1–T12) is the **reason of record** — read it before the
diff, because the code will not explain *why* trust is a property of evidence rather than of the producer.
Then the retrospective + reviewer notes at the tail of
`openspec/changes/archive/2026-08-06-phase3-trust-model/tasks.md`, which record what the task list got wrong,
why the group order was load-bearing anyway, and the four things a reviewer should know going in (the one
deliberate behaviour change, the one breaking request shape, the moved config knob, and that
**`EDR-INTELLIGENCE-01` Revision 5 is superseded** — scaffold future AI work from `EDR-TRUST-01`).

**Open:** the Decision Proposal payload shape, deferred by construction until a second Decision capability
defines it. `TRUST-1/2/3/4` in `docs/BACKLOG.md` are LOW follow-ups. The AI-line ordering below
(GOV-14 → Δ3b → Δ4) is now unblocked — the capability surface those use cases need exists.

---

**2026-08-05 — from-scratch VM bring-up + two HIGH bug fixes (both merged to `main`).** A full cold-start
deployment on the enterprise VM (Postgres → 7 DBs → build → the 6 nodes → Ollama `cyberpal20b` +
`nomic-embed-text` → the Δ3a vector store), driven through real use cases (SBOM→Finding→`recommend_position`
with semantic precedent→OpenVEX→vendor-VEX suppression→estate blast-radius→multi-format publish), surfaced,
scoped, fixed, live-verified, and **merged** two defects — plus ran R5:

- **BUG-1 (PR #86, on `main`)** — Governance poison-halted the `knowledge` stream on a shared-CVE
  `faultline_enriched` carrying a VEX applicability: aggregate reads (`GetByID`→`load`) ran on the pool while
  `Save` joined the inbox tx, so a 2nd same-envelope mutate never saw the 1st's uncommitted version →
  `ErrConcurrent` never converged → D8 halt. Fix: `querier(ctx)`/`exec(ctx)` seams so reads/`SetBaseScore` join
  the ambient inbox tx (mirrors the PR #59 Knowledge fix) + convention **R3** in `CONVENTIONS.md` (aggregate
  reads in an event handler join the ambient tx). Live: 0 halts, cursor advanced, suppression proposals land.
- **BUG-3 (PR #87, on `main`)** — `base_score` was materialized onto Findings **only** by `SetBaseScore` on
  `faultline_enriched`, so a Finding born (via `component_matched`) on an already-enriched card was stranded at
  0 — a critical CVE shown as priority 0. Fix: the card's composite score now rides the
  `knowledge.component_matched` event (+ `.v1` schema `Score`) and Governance stamps it in `OpenOrUpdateFinding`
  (guarded `>0`; `SetBaseScore` joins the inbox tx per BUG-1). Live: a fresh log4j release is born scored
  (44228=90, 45046=90, 45105=70, others=40) instead of 0 — OSV scores, no NVD needed.
- **R5 (task #10) run** — `make e2e-embed` on the VM Ollama confirmed **`nomic-embed-text` + `components+severity`**
  (recall@1=1.00, MRR=1.00, ~46 ms); `+cve` neutral, `+description` **hurts** (recall@1 0.83). Detail:
  `RAG-SESSION-2-SPIKE.md` §4. No embed-model change needed.
- **Open (filed in `docs/BACKLOG.md`, decisions/config — not bugs):** DN-1 (`effective_priority` clamps at
  100), DN-2 / **A2** (NVD *discovery* doesn't cover Maven→CPE and the watch doesn't backfill old CVEs — the
  flat prioritization was BUG-3, not the feed), DN-3 (component-level embedding conflates distinct CVEs →
  contradictory precedents → the AI honestly declines). **A2 (NVD as a real discovery source) is the next
  substantive code fix if live prioritization + the dormant reactive Rule step are wanted.**

**Current development is done and released as v0.4.0** (`6e03396`, tagged 2026-08-02). The whole pipeline
(M2 Kernel/Registry · M6 Evidence · M7 Knowledge · M8 Governance · M9 Communication · M5 event bus · M4
Intelligence Δ1/Δ2) plus the post-M5 parity/hardening work (opt-in feeds, EDR-SECURITY-01 auth,
EDR-ESTATE-01 estate/blast-radius, EDR-VEX-01 Phase 1–3 governed suppression) is IMPLEMENTED, gated, merged,
and archived. `openspec list` → **no active changes**. Milestone detail is in "Done so far" above; don't
re-narrate it here.

**Next line — AI-capability expansion (v0.4.x).** In order:

1. **GOV-14 — EDR-GOVERNANCE-01 D14 (decided in v0.4.0, implement next).** A disposition-aware
   `residual_priority` on the release posture + a deterministic **disposition re-evaluation watcher**
   (KEV / EPSS-threshold / new public exploit / reversing VEX → re-surface a suppressed or accepted Finding),
   with an optional AI-judge upgrade layered on the deterministic core.
2. **Intelligence Δ3 — RAG / Knowledge Engine.** **Design + decision DONE (2026-08-03)** — a 3-session
   evaluation (`docs/engineering/RAG-INTEGRATION-OPTIONS.md` · `RAG-SESSION-2-SPIKE.md` ·
   `RAG-SESSION-3-DECISION.md`) → **`EDR-INTELLIGENCE-01` Revision 4** (R1–R6) + STACK.md reconciled.
   Decided: semantic precedent for `recommend_position` (**G-AI-3**) via **in-memory Go cosine over
   embeddings persisted in a plain Postgres table** (no pgvector — measured ~47 ms/query @ 50k), behind an
   `app.VectorIndex` port; hand-rolled Go retrieval; **Python DSPy deferred to Δ3b**; pgvector/Qdrant are
   port-swap upgrades. **Δ3a IMPLEMENTED + gated (A1–A6, 2026-08-04, `make check-ci` green):** the store
   (`internal/intelligence/adapters/store`, its own `intelligence` DB) · embedder (`adapters/embed`, Ollama
   `/v1/embeddings` + a deterministic fake) · in-memory `VectorIndex` + `EngineKnowledge`
   (`adapters/{index,engine}`) · bus-consumer population (`adapters/inbound`, exactly-once, Preparer-split so
   the embed stays out of the tx) · plan `[Rule → Knowledge → LLM]` with a **best-effort** Knowledge step +
   **exact-CVE fallback** (cold-start-safe) · the demo e2e (`adapters/wiring/demo_e2e_test.go` — a semantic
   precedent flips a recommendation) · cmd wiring (store pool, bus reader, boot-load, `THEMIS_INTELLIGENCE_REBUILD`
   = purge + cursor-reset re-embed) · CLAUDE.md/node.env/INSTALLATION/TESTING/BACKLOG docs. **Commit state:**
   A1–A6 committed + pushed to `origin/main` (`3825735`). **R5 harness built** — `make e2e-embed`
   (`internal/intelligence/adapters/embed/embed_eval_test.go`, opt-in `//go:build embed_eval`, SKIPS without
   Ollama) embeds a labeled component-grouped corpus with each candidate model + text composition and reports
   recall@1/@3 + MRR + latency. **RUN 2026-08-05** on the VM Ollama — `nomic-embed-text` + `components+severity`
   confirmed (recall@1=1.00, MRR=1.00, ~46 ms; `+cve` neutral, `+description` hurts at 0.83); no model change
   (`RAG-SESSION-2-SPIKE.md` §4).
   **Δ3b** (Python DSPy, only if needed) + **Δ4** (autonomy + LLMOps) deferred; two LOW freshness follow-ups
   filed in BACKLOG §C.
3. **Intelligence Δ4 — autonomy + LLMOps.** The scheduled autonomous-analyst mode (advisory-only — pushes
   Proposals to proposal-intake) + eval / routing / weight-tuning. Guardrail unchanged: autonomy of
   *generation* yes, of *authority* never.

Workflow for each: grill the EDR delta → scaffold the OpenSpec change → `/opsx:apply` → gate on `make check`.
The longer parity tail (A3–A6, B2/B5/B6, C3–C5, D2–D7 notifications, E1–E11 input-integrity, F4–F8
metrics/traces/probes) stays enumerated in [`PARITY-GAP.md`](PARITY-GAP.md); pull from there between AI
increments as capacity allows.

Note (Option A in effect): `/grill-with-docs` is user-invoked, but the model can run the same via
`grilling` + `domain-modeling` directly — that is how `EDR-KNOWLEDGE-01` was grilled. Either works.

## Deferred / pending work

**All pending and deferred work lives in one place: [`docs/BACKLOG.md`](../BACKLOG.md) (Part 1)**, with the
full monolith→greenfield gap inventory in [`PARITY-GAP.md`](PARITY-GAP.md). Between them they track the next
line, the remaining parity tail (input-integrity E1–E11 and the A/B/C follow-ups), and the standing
per-context follow-ups. Update those files, not this section, as items open or close.

## Checkpoint — session 2026-08-08/09 (clean-slate VM rebuild + the AI harness)

**Resume here.** 27 commits, all on `main`, `make check-ci` + `make vet-tags` green at every one.

**The VM was rebuilt from scratch** (7 databases, one generated credential, six nodes under
systemd). Migrations current: registry 2 · evidence 2 · knowledge 5 · governance 10 ·
communication 4. Three releases ingested; feeds osv/nvd/epsskev/redhat all writing.

**Verified working end-to-end on real data:** DASH-1 traversal · DASH-2 enriched posture (0.5s for
20 rows) · KN-FIX-1 fix attribution · C1/C2 blast radius incl. **fail-safe under a Registry
outage** · `plan_remediation` · `recommend_position` (advisory, nothing auto-decided) ·
**Δ3a semantic precedent** (`precedents_used: 4` on a live recommendation).

**Two EDR decisions landed:** `EDR-CORRELATION-01` (new — advisory scope is not a vulnerability
claim; both steps implemented and verified) and D5a within it (re-classify when attribution
arrives late).

**Defects found and fixed this session, by class:**

- *Deployment* — installer never created the estate tables; `chown` non-portable; a runbook's
  example password had become a live credential.
- *Seams between events* — BUG-3b (band/fixes stamped at the wrong event), D5a (classification
  before its evidence), `AbsorbComponent` discarding a re-delivery that carried new information.
- *Prompt↔gate disagreement* — PLAN-6 three times (truncated heading, `<--` annotations, `"..."`
  placeholder), AI-CTX-1 (an unbounded projection field exhausted the model's budget: 8192 tokens
  → truncated JSON; now 1841 tokens and 45s).
- *Computed-then-discarded* — the plan grouping, a proposal's evidence trust, `precedents_used`.
  All three were auditable facts that existed nowhere observable.
- *Recogniser looser than its evaluator* — the CVSS v2 vector, my own module `name:stream` regex,
  the PII redactor destroying PURLs (which silently disabled `recommend_position` entirely).

**Where we stopped.** Working the AI list in priority order:
1. ✅ **Done** — Δ3a enabled and its acceptance test passed; AI-CTX-1 fixed. The `insufficient`
   path is wired and metered but not naturally triggerable on this estate (no card is thin enough).
2. ⏳ **In progress** — G-AI-4's per-capability window ceiling is enforced
   (`THEMIS_INTELLIGENCE_BUDGET_TOKENS`/`_WINDOW`, unset = unlimited). **Blocked next:**
   degrade-not-fail (G-AI-4) and escalation (G-AI-2b) both need a **model router**, and the box has
   exactly one chat model. Clearing it is one `ollama pull`.
3. Not started — G-AI-3 (needs a release-comparison read API), G-AI-5 (inert while local-only).
4. Not started — structured AI-proposal fields, TRUST-3, PLAN-5.

**VM state to know:** the estate carries **12 customers**, which saturates the blast multiplier at
2.0× and pins every `effective_priority` to 100 (GOV-15). Trim to ~3 before using the posture for
anything where ranking matters. Δ3a is enabled on the Intelligence node; both AI timeouts are 300s.

**Landed after the checkpoint above was first written:** Δ3a enabled and verified live
(`precedents_used: 4`); `precedents_used` surfaced on the API (it had been computed and read by
nothing); **AI-CTX-1** — an unbounded `affected_ranges` field exhausted the model's budget, giving
`schema_invalid` after 164s/8192 tokens, now 45s/1841 tokens; **G-AI-4** per-capability spend
ceiling enforced; `evidence_trust` exposed on proposals; and `scripts/vm-verify.sh`, a single
read-only report replacing the five or six hand-written one-liners deployment verification used to
take.

**17 items open** in `docs/BACKLOG.md` (was 18 here; CORR-1 closed once step 2 landed — recounted in the
2026-08-10 doc/code parity pass below); no P0. The highest-value open work is the AI harness (R1),
then F5 (a node that cannot start is indistinguishable from a healthy one) and F1 auth — which is
**built but never enabled** on this deployment.

**Session 2026-08-07 closed the P0/P1 tail.** The backlog went **31 open → 13, with no P0 and no P1
remaining**; the highest-priority open item is now roadmap (the AI harness), not a defect. Closed that
day: GOV-14b (the disposition watcher — the safety net under `residual_priority`, which had shipped a
day earlier WITHOUT it), the accepted-risk expiry worker (folded into that same sweep), DASH-1/DASH-2
(the read surface a GUI needs), OTel traces, CVSS vector selection + v3.x derivation, and the first
release-scoped AI capability (`plan_remediation@v1`).

Three defects found that day are worth knowing about because they share a shape — **a recogniser looser
than the evaluator that consumes it**, which turns the evaluator's *failure* into a *verdict*:
**RANGE-PARSE-1** (P1: an unparseable affected range read as "provably not affected" and the shipped
policy auto-accepted it), the CVSS v2 vector recogniser accepting any prefix-less string, and the plan
prompt inviting citations the grounding gate refused. See `EDR-TRUST-01` T5 and `docs/BACKLOG.md`.

## Doc/code parity pass — 2026-08-10

Every mechanically checkable claim in the docs was diffed against the code. **The system descriptions were
accurate; the drift was all in tracking tables.** Verified correct and left alone: the six port defaults,
the migration versions (registry 2 · evidence 2 · knowledge 5 · governance 10 · communication 4, up/down
23/23), the `make check` / `check-ci` composition, the coverage tiers, every `make` target and every test
name cited anywhere in the docs, all of `STACK.md`'s stack against `go.mod`, and — the strong one —
**all 40 generated handler operations against all six OpenAPI specs**. `go build ./...` and
`go test ./tests/architecture` both green, so the no-cross-context-imports guarantee still holds.

Eleven discrepancies were corrected: `STACK.md` credited Evidence with JSON-schema validation it does not
do (its trust gate is `json.Valid` only — the gap PARITY-GAP **E1** already tracked, so two "read before
you implement" docs disagreed) and omitted `golang.org/x/crypto`; **B6** was refuted by one line
(`trust_sources.go` calls `feed.NewRegistry()`) and is now closed; **A6** narrowed to `related`-only since
`upstream` landed; **F2**'s progress row implied it shipped when only the verifier exists and no route
mounts it; `INSTALLATION.md` still warned about the pre-2026-08-07 Knowledge port default; `CONVENTIONS.md`
R1 named four of six nodes; `API.md` was missing six operations (the whole estate/blast-radius group, the
raw-document seam, `GET /feeds`); **CORR-1** was still checkbox-open with its own body recording both steps
implemented; and the three circulating open-counts were reconciled to **17**.

**The one finding NOT fixed here, because it is code:** `scripts/gf-upload-sbom.sh` sends no `X-API-Key`
while `release-posture.sh`, `list-open-vulns.sh` and `vm-verify.sh` all do — so following
`INSTALLATION.md` §4a (enable auth) and then §5 (drive an SBOM) in order yields a 401. Its header comment
still asserts "the greenfield services are unauthenticated (dev)".

**The pattern worth carrying forward:** prose stayed current, tables rotted. A prose update is one edit; a
table update means finding the right row among forty. Two of these classes are a shell script away from
never recurring — a spec-vs-`API.md` operationId diff, and an "every `THEMIS_*` in code appears in
`deploy/node.env.example`" check. The second one, run once, also found that
**`THEMIS_BUS_DATABASE_DSN` — the cross-context switch — was referenced by `node.env.example` as
"(shared, above)" but defined nowhere in it.**

## Key file pointers

- **Pending/deferred work (single backlog):** `docs/BACKLOG.md` — Part 1 (greenfield, active)
- EDRs (source of truth): `docs/engineering/decisions/EDR-{KERNEL,EVIDENCE,KNOWLEDGE,GOVERNANCE,COMMUNICATION,INTELLIGENCE}-01.md`
- **Tech stack + rationale (read before `/opsx:apply`):** `docs/engineering/STACK.md` — canonical stack;
  each change's `design.md` has a per-context **Stack** section pointing to it
- **Cross-cutting build rules (read before `/opsx:apply`):** `docs/engineering/CONVENTIONS.md` — R1 every
  node logs to console + OpenTelemetry; R2 config is self-documented in the config file with comments.
  **R1 is realized (2026-07-18) by `internal/platform/observability`** (zap console + OTel logs via the
  `otelzap` bridge, one `Setup`; config-driven level/format/OTLP endpoint via `ConfigFromEnv`; a
  `RequestLogger` correlation-id middleware; domain/app stay log-free by depguard). All four greenfield cmds
  wire it; example config at `deploy/node.env.example`. **R1 is COMPLETE as of 2026-08-07**: metrics
  (Prometheus registry, 2026-08-06) and **traces** (OTLP `TracerProvider` + a server span per request,
  carrying the correlation id so traces and logs are joinable) both landed. Egress decision:
  **Prometheus-scrape for metrics, OTLP for traces** — one exporter dependency instead of two, and metrics
  keep working on a node with no collector, because a trace has no pull model and a counter does.
- Changes: **none active** — `phase3-trust-model` IMPLEMENTED + ARCHIVED 2026-08-06 (**63/63**, 11 groups),
  from `EDR-TRUST-01` (T1–T12). Cross-context by construction (Knowledge + Governance + Intelligence);
  **group order is the migration order** and groups 6→7 must not be reordered. All other Phase-3 changes are
  IMPLEMENTED + archived (`openspec/changes/archive/`). `openspec validate` reports **"no deltas"** — expected
  for `phase3-*`; archive with `--skip-specs -y`
- Blueprints (to fill from Evidence exemplar): `docs/engineering/implementation-blueprint/01–06`
- Architecture source of truth: `docs/architecture/` (Books I–III) + `docs/adr/` (69 ADRs)
- Change status: `openspec/STATUS.md`
