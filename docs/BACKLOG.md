# Themis — Backlog

The single project backlog. Two parts:

- **Part 1 — Greenfield (go-forward, ACTIVE):** the live tracker for the Phase-3 rebuild — start here.
  Milestones not yet implemented, full-pipeline verification, deferred follow-ups, observability, process.
- **Part 2 — Legacy PoC history (frozen — reference only):** the Phase 1/2/3 planning history and the
  Layer-0 refactor log from the v0.3.x monolith. Kept for provenance and defect IDs (D-NVD-2, D-FEED-2);
  do not action against the frozen tree.

## Part 1 — Greenfield (go-forward, ACTIVE)

**Updated:** 2026-08-27 · The one consolidated list of everything **not yet done** in the Phase-3 rebuild.
Status of what **is** done lives in `PHASE3-STATUS.md`; the monolith→greenfield capability diff lives in
[`engineering/PARITY-GAP.md`](engineering/PARITY-GAP.md). This file is only the open work. Each item states
**what**, **why it's open**, **where it plugs in**, and its **dependency**.

**Tracking rule (agreed 2026-08-27):** this file is **the ONE tracking document**. When a feature ships,
its item here is marked done **in the same change** — and every other doc that lists the item (tier EDRs,
plan docs, status resume blocks) gets its marker updated then too, until tracking moves to a tool. The
rule exists because the 2026-08-26 work order below was written against two items (GUI-2 bounds, GUI-4)
that had shipped two weeks earlier: closure was recorded in `GUI-UPGRADE-PLAN.md` but the checkboxes here
were never ticked, and the stale text was then trusted.

Snapshot: the four-context pipeline **plus M4 Intelligence Δ1+Δ2 and M5 (event bus) are merged to `main`**,
and the stack is **deployed end-to-end on a Linux VM under systemd** (2026-07-30). The first monolith→greenfield
**parity cluster (correlation + enrichment) is closed** — distro (rpm) correlation, NVD/EPSS/KEV/ExploitDB
enrichment, and a deterministic priority+score (PRs #60–#63). Open work: the **delivery/security parity
cluster** (notifications, org blast-radius graph, API auth — see PARITY-GAP.md §B), M4 Δ3–Δ4, and the
per-context follow-ups below.

---

### 0. Cluster index — read this before picking work

**Added 2026-08-06 · counts re-derived 2026-08-10.** The item list below is organized by *where code
lives*, which is right for finding things and wrong for deciding what to do. **17 open items resolve to 7
areas**, none of them P0 or P1. Fix a cluster, not an item — several entries in each cluster close
together, and some close for free.

Ordered by priority; **cluster IDs are stable, so they are not in numeric order** — R6/R7 were added after
R1–R5 and outrank them. "Measured" means the claim rests on an observation from a running system, not a
code reading.

| # | Cluster | Priority | What is actually wrong | Items |
|---|---|---|---|---|
| **R7** | ~~The blast multiplier destroys the order it exists to create~~ ✅ **CLOSED 2026-08-23** | ~~P2, measured~~ | Resolved by **EDR-GOVERNANCE-01 D17**: the output clamp is removed — `effective_priority`/`residual_priority` are unclamped ranking numbers (0–200; the bound lives on the multiplier's saturation). A constant multiplier now provably preserves within-release order and amplifies across releases as C2 intended. | GOV-15 ✅ |
| **R6** | ~~A node that fails announces nothing~~ ✅ **CLOSED 2026-08-23** (orchestration residual filed LOW-MED) | ~~P2, measured~~ | Resolved by the `internal/platform/health` seam: `/healthz` + `/readyz` on every node (DB ping · migrations probe · fresh-connection credential watch), systemd `StartLimitBurst` turning crash loops into visible failed units, and a vm-verify Readiness section. The rotation *rewrite-the-fleet* verb remains as its own LOW-MED item. | F5 ✅ · rotation detection ✅ · rotation orchestration (open) |
| **R1** | **AI harness build-out** | **P2** | Roadmap, not defects — the largest remaining body of work and the only cluster that is about capability rather than correctness. Kept separate so it never competes with correctness work. | M4 Δ4 · G-AI-1 · G-AI-2(c) · G-AI-3 · G-AI-4 (remaining scopes) · G-AI-5 · PLAN-5 · Δ3a component-embedding · AI-TEL-1 · AI-204-2 — *(closed 2026-08-13: G-AI-2b escalation, G-AI-4 degrade-not-fail, GUI-1 explain)* |
| **R2** | **Governance decision depth** | **P2** | The governed road works end to end, but a proposal still records AI confidence as prose in its rationale, so a confidence-threshold policy has nothing to read. | structured AI-proposal fields |
| **R3** | **Communication has one delivery channel, and it is a log line** | **P2** | The exactly-once / idempotent / outcome-recorded mechanics are done; what is missing is anywhere real to send an artifact. | concrete delivery channels (SMTP / Slack / webhook) |
| **R4** | **Guarded deferrals** | **P3** | Correct today, with a TEST that fails the build the moment they stop being correct. They are on the list to be found, not to be done. | TRUST-1 (applicabilities uniformly Asserted) · TRUST-3 (no AI→Knowledge path exists yet) |
| **R5** | **Consciously deferred, with the trade stated** | **P3** | Judged not worth doing now, in writing, so nobody re-decides them by reflex. | store fault-injection · feed-health-after-poll residual · Δ3a component-embedding design |

**Re-derived 2026-08-07 (third time that day).** The N1–N10 clusters are gone because the work in them is
done: **31 open → 13**, and the four P0/P1 clusters closed entirely.

**GUI batch filed 2026-08-11:** the first live dashboard days added six items (GUI-1…6 in §C) —
one R1 roadmap capability, one MED-HIGH data gap (Alpine, GUI-2), three LOW-MED feed items, one
productization marker. The CVE-summary gap those days ALSO found was fixed the same day
(`feat/knowledge-cve-summary`), so it is deliberately not an entry. Still no P0/P1.

**Re-counted 2026-08-10 against the checkboxes.** The 13 above was right on 2026-08-07 and then went stale
in the ordinary way: the 2026-08-08/09 VM session filed four new items (GOV-15, F5, DB-password rotation,
PLAN-5) and closed one (CORR-1, both steps implemented + verified live). **17 open**, plus three M5
maturations nested under a completed parent that the clusters deliberately do not carry (Kafka transport
swap · subject-aware scheduler · explicit integration DTOs — the contract is stable, only the mechanism
evolves). Three counts have circulated — 13 (clusters), 18 (`PHASE3-STATUS.md`, before CORR-1 closed) and
21 (raw `- [ ]`); they differ only by those two conventions, not by disagreement.

**Tiered enhancement roadmap (2026-08-21, PROPOSED — EDR-ENHANCE-T1…T5).** The open items above,
arranged as an execution sequence rather than a filing system. The tiers do not replace the
R-clusters — they order them: each tier maps to existing IDs (no duplication), and only two items
are NEW with this roadmap (GUI-15, AI-CMP-1, filed below). One decision record per tier under
`docs/engineering/decisions/EDR-ENHANCE-T<n>.md`, all **awaiting confirmation before any
implementation**:

| Tier | Theme | Items (existing IDs) | Order rule |
| --- | --- | --- | --- |
| **T1** | Basic polish | GUI-12 ✅ (2026-08-28) · GUI-10 · GUI-4 ✅ (shipped PR #95, 2026-08-13) · KN-SCAN-3 · vanilla-JS decision note | opportunistic, each self-contained |
| **T2** | Correctness & robustness | ✅ **EXECUTED 2026-08-23**: R7 (GOV-15 ✅ D17) · R6 (F5 ✅ + rotation detection ✅) · EV-DEDUP-2 design ✅ (D10 PROPOSED) · GUI-11 re-scoped design-first (aliases not persisted) · R4/R5 stay guarded/deferred | done first, as required |
| **T3** | Enterprise & platform | **R2** (structured AI-proposal fields) · **R3** (SMTP/webhook delivery) · F2 · GUI-15 · GUI-3 · GUI-5 · (Kafka swap stays parked) | after T2, R-table order within |
| **T4** | AI groundwork (deterministic) | AI-204-2 · AI-TEL-1 · PLAN-5 · Δ3a per-CVE embedding | before/interleaved with T5 as prerequisites |
| **T5** | AI capabilities (R1) | AI-CMP-1 · G-AI-3 · G-AI-1 · G-AI-2(c) · G-AI-4 · G-AI-5 · Δ4 (eval harness, then autonomy) | entry via AI-CMP-1 → G-AI-3 |

**GUI/Scanner work order (agreed 2026-08-26; CORRECTED 2026-08-27 against the code).** The 2026-08-26
paragraph clubbed GUI-2 · GUI-4 · GUI-3 · GUI-5 as one **"Distro-feed completeness"** cluster — the
seam was right (all `internal/knowledge/adapters/feed/` + `app/feed_health.go`, all bounded by the D5
relevance rule, one EDR-VEX-01 delta) but the state was stale on two of the four: **GUI-2's bounds half
and ALL of GUI-4 had already shipped 2026-08-13 in PR #95** (`b4ed088`: EDR-VEX-01 D7 + the `alpine`
ACL/client/sweep behind `THEMIS_ALPINE_ENABLED`, and the per-distro `<source>/<distro>` Tier-3 health
rows in `adapters/feed/health_source.go`; live-verified — 78 bounds folded in 28s, `osv/rocky` row
observed). **The cluster COMPLETED 2026-08-27** — all three remaining items grilled/designed and
shipped in one arc on `feat/knowledge-apk-verdict`: **(1) GUI-2b ✅** (apk fixed-verdict, EDR-VEX-01
D9); **(2) GUI-3 ✅** (VEXFEED-coverage verified NO first, then the D10 per-CVE-VEX changes.csv gate);
**(3) GUI-5 ✅** (D11 Rocky RXSA feed, 29-advisory universe measured live). One consolidated VM test
round covers all three (plus live-verifying GUI-2b needs an Alpine SBOM). This SUPERSEDES the T1/T3 scattering of these IDs for scheduling purposes —
the tiers still describe theme, this describes the seam. After the cluster: **GUI-12** (measured MED
dedup fix, pure code) → **KN-SCAN-3** (ecosystem canon, Go-side) → **GUI-10 → GUI-15** (translator test
harness, then Grype — build-change, Must-ask). GUI-11 + EV-DEDUP-2 stay design-blocked (own EDR/domain
decision each). ~~NEXT SESSION: grill GUI-2b as the EDR-VEX-01 delta~~ — **the whole cluster is done
2026-08-27** (D9 + D10 + D11, one branch, `make check` green). **NEXT: the consolidated VM test round**
(GUI-2b apk verdict with an Alpine SBOM · D10 gate log lines · `rocky` feed + health row), then
**GUI-12** (measured MED dedup fix, pure code) per the after-cluster order.

**The shape of the list changed again, and not in the good direction.** On 2026-08-07 it was dominated by
"we have decided not to build this yet". Two clusters now hold **measured defects** — R7 (triage order) and
R6 (silent failure) — both found by running the system rather than by reading it, which is the argument for
the VM sessions in one line.

**Suggested next move:** **R7** or **R6** before any feature. Both are correctness/operability, both were
observed live, and both are small next to R1. After them the next work is a CHOICE — most likely **R1**
(the AI harness: Δ4 evaluation loop, model escalation, the remaining budget scopes) or **R3** (a real
delivery channel, which is what makes a published artifact reach anyone). Pick by what a user is waiting
for, not by this list.

**Filing rule going forward:** a new item names its cluster, and states whether its claim is **measured**
or **read from code**. Three items in C1 were filed separately over three weeks describing one defect from
three angles, and two of them proposed fixes that would not have worked.

---

### A. Milestones not yet implemented (in dependency order)

- [x] **M4 Δ1 — Intelligence (AI Gateway) walking skeleton** — `phase3-intelligence`, `EDR-INTELLIGENCE-01`
  (Revision 2, D1–D13). **IMPLEMENTED + gated** (2026-07-18): one reactive capability `recommend_position`
  (affected/not-affected triage) end-to-end, pure Go, **disable-able** (D13 no-op gate) — `internal/intelligence/
  {domain,app,adapters}` + `cmd/intelligence` (stateless) + the Governance caller seam (`adapters/intelligence`
  client + no-op + on-demand `POST /findings/{id}/recommend`). Ollama (OpenAI-compatible) + fake provider;
  3-stage validation; read-API grounding.
- [x] **M4 Δ2–Δ4 — Intelligence, the rest of the harness** ✅ **PARENT CLOSED 2026-08-28**
  (checkbox ticked late under the tracking rule — every delta had already shipped: Δ2 2026-07-24,
  Δ3a 2026-08-04, Δ4a 2026-08-24, Δ4b + AUTO-VOL-1 live-verified 2026-08-26; R1 declared COMPLETE
  in PHASE3-STATUS). What the umbrella still holds, all demand-gated, tracked in the R-clusters
  not here: the deferred Δ4b refinements (analyst portfolio · event-reactive triggering · cloud
  tiers) and the consciously-replaced Δ3 Python/pgvector idea (all-Go won; Δ3a component-embedding
  design stays R5-deferred). Original plan text below for provenance.
  (`docs/engineering/THEMIS-AI-HARNESS.md`): **Δ2**
  typed Engine Dispatcher + Rule Engine + budget (4 scopes) + security/privacy admission; **Δ3** Python LLM
  engine (DSPy/LangGraph, a service behind the engine port) + RAG/Knowledge Engine (pgvector); **Δ4**
  autonomous engine + push seam + the LLMOps plane (prompt registry, golden datasets, A/B, model registry,
  capability promotion) + the operational store. Each additive behind the Δ1 seams; each safe because the
  plane is disable-able. **Δ2 is grilled + scaffolded (2026-07-24):** `EDR-INTELLIGENCE-01` **Revision 3**
  (Δ2 concrete cut, grounded component decisions C1–C7) + `openspec/changes/phase3-intelligence-d2`
  (proposal/design/tasks, 9 task groups) — **IMPLEMENTED + gated (9/9 groups, `make check` green, 2026-07-24)**.
  The grill narrowed Δ2 scope: budget =
  **meter only** (enforcement → G-AI-4), admission = **local-only** (classification/clearance → G-AI-5); plus
  the two-step `[Rule → LLM]` plan, the honest `insufficient` outcome, precedent-Positions grounding, and a
  which-step-decided provenance stamp.
  **Δ3a IMPLEMENTED + gated (A1–A6, 2026-08-04):** the RAG / Knowledge Engine, **all-Go, NO pgvector** —
  in-memory cosine over embeddings persisted in a plain-Postgres `intelligence` DB (`EDR-INTELLIGENCE-01`
  **Revision 4**; Book IV Ch 8 RC-1). Adds Intelligence's first datastore + first bus-consumer role (populates
  from Governance Position events, exactly-once). The plan is now `[Rule → Knowledge → LLM]`; the demo — a
  semantic precedent flips a recommendation — is the acceptance test. Still deferred: **Δ3b** (Python DSPy
  reasoning engine, only if a task needs it) + **Δ4** (autonomy + push + LLMOps). **R5** (embedding-model pick,
  leaning `nomic-embed-text`) pending the local Ollama eval.

- [x] **M5 — Event Infrastructure (the shared event bus)** — **DONE (2026-07-29)** on branch
  `phase3-event-infrastructure`. `docs/engineering/decisions/EDR-EVENTBUS-01.md` (D1–D11) +
  `openspec/changes/phase3-event-infrastructure/` (**43/43 tasks — all 10 groups EB-01…EB-11**), gated
  `make check` + `make e2e-pipeline` green. The platform-owned channel (`internal/platform/eventbus` +
  a `bus` database) now carries the full kernel `Envelope` between contexts: schema-guarded integration
  contract v1, `Publisher` → `bus.event_log`, gap-free stream `Reader` (txid watermark) + D8 stream-halt,
  per-consumer inbox (exactly-once **application**), stream/interest-set subscriptions, `cmd/knowledge` +
  readers in every cmd, and an in-process runner proving **SBOM → published-OpenVEX** black-box. The staged
  maturations are their own low-priority entries now (M5 shipped the stable contract, not the final mechanism):
  the **Kafka transport swap** (D1/D2), the **subject-aware scheduler** (D8 target — M5 halts the whole
  stream), and **explicit integration DTOs** (D9 target — M5 froze the current wire shapes as v1). See §C/§E.
  - **Progress (2026-07-28):** ✅ **Group 1 (EB-01)** — `internal/platform/eventbus` scaffold + `bus` database
    + `platform-eventbus-infra-only` depguard / `TestPlatformEventbusIsBusinessAgnostic` arch guard. ✅
    **Group 2 (EB-02)** — full kernel `Envelope` threaded through all four producers' outboxes
    (`000002_*_envelope` migrations rename the context-specific subject column and add
    `source_context`/`schema_ref`/`correlation_id`) and both inbound consumers (`Consumer.Handle(ctx,
    Envelope)`). Both gated (`make check` green). **Two M5-cut seams noted:** `schema_ref` is a placeholder
    (`= event type`) until Group 3 pins it; `correlation_id` is each context's own aggregate id (cross-context
    propagation deferred to the Group 9 e2e). **Next: Group 3 (EB-03)** — integration-contract v1 + per-event
    JSON-schema guard.
  - **M5 maturations (LOW — contract stable, mechanism evolves; not blocking):**
    - [ ] **Kafka transport swap (D1/D2).** Replace the Postgres event_log + cursor with a broker behind the
      same `Envelope` + Publisher/Reader ports; the inbox (exactly-once application) and per-subject ordering
      guarantees are transport-independent and carry over unchanged.
    - [ ] **Subject-aware scheduler (D8).** M5 halts the *whole stream* on a poison event; the architectural
      target isolates the halt to the failing `Subject` so unrelated aggregates keep flowing — replace the
      single drain loop with a per-Subject scheduler, no changes to D5/D6/D7 or the event contracts.
    - [ ] **Explicit integration DTOs (D9).** M5 froze the current wire shapes as v1 (Knowledge/Governance/
      Communication still marshal the raw domain struct — PascalCase). Introduce per-type outbound DTOs while
      keeping the bytes identical (else a v2 `schema_ref`); Evidence already has one (`eventPayload`).

---

### B. Full-pipeline verification

- [x] **SBOM → published-VEX pipeline e2e** ✅ **DONE** (M5 landed; verified still true 2026-08-07).
  `tests/pipeline/pipeline_test.go` `TestPipeline_SBOMToPublishedVEX` is a black-box run across **five**
  services — Registry → Evidence → Knowledge → Governance → Communication — over the **real** event bus
  (database-per-context + the `bus` DB), asserting only through public HTTP APIs and never reading a
  context's tables. It registers a release, uploads an SBOM, lets correlation open a Finding, has a human
  govern an `affected` Position, triggers an OpenVEX publication, and asserts the rendered artifact names
  the CVE. **CI runs it on both `pr.yml` and `main.yml`** (`make e2e-pipeline`), so it is a merge gate, not
  an optional target. As of 2026-08-07 it also wires the shipped auto-accept policy (D15), so the proof
  exercises the real composition rather than an empty one. _(This entry sat open claiming "awaits M5" long
  after M5 landed — see the C3 note on stale assurance items.)_

---

### C. Deferred follow-ups inside completed contexts

#### GUI-session follow-ups (filed 2026-08-11 — surfaced by the first live dashboard days)

The dashboard spike (`gui/dashboard-spike`, `docs/engineering/DASHBOARD-SPIKE.md`) put a human in
front of the product for the first time. What it surfaced and what was FIXED the same days: the
missing CVE summary (delivered by every feed, parsed by nothing — closed on
`feat/knowledge-cve-summary`) and a set of pure GUI issues. What stays open is below. All are
**read from code / user observation on the VM**, not measured defects; none qualifies as P0/P1
under the 2026-08-07 re-derivation standard.

- [x] **GUI-1 — AI "explain this vulnerability in our context" capability.** ✅ **CLOSED 2026-08-13** (`explain_vulnerability@v1` shipped in PR #94; drawer auto-run shipped with the keeper dashboard, PR #96). Cluster **R1** (AI
  harness), **P2 — roadmap, deliberately NOT a defect.** An Information-class capability (T7, like
  `plan_remediation`): grounded ON the stored feed summary + the assessment projection, it says
  what no feed can — "…and your `python3-libs` sits in billing-api's request path." Ephemeral,
  clearly AI-labeled, never a substitute for the stored summary (that layering was decided
  2026-08-11 when the summary was made evidence; see the `VulnFacts.Summary` doc comment).
- [x] **GUI-2 — Alpine secdb enrichment feed.** ✅ **CLOSED (bounds half) 2026-08-13** — EDR-VEX-01
  **D7** written first, then shipped in PR #95 (`feat/knowledge-distro-feeds`, `b4ed088`): the
  `alpine` feed ACL + branch-DB client + sweep (trust=Observed, tier=2, opt-in
  `THEMIS_ALPINE_ENABLED`/`_BRANCHES`/`_URL`/`_POLL_INTERVAL`), fetch-the-branch-DB-whole /
  fold-only-carded per D5. Live-verified 2026-08-12: 5 branches fetched, **78 bounds folded in
  28s**. The apk fixed-VERDICT half was split out and continues as **GUI-2b** below. *(Checkbox
  ticked late, 2026-08-27 — the staleness that produced the tracking rule at the top of Part 1.)*
  _Original filing (2026-08-11):_ RHEL/Rocky/Alma get vendor severity, `not_affected` and fixed
  NEVRAs from the Red Hat feed, Ubuntu/Debian ride OSV, but Alpine had correlation only. Source:
  `security.alpinelinux.org` per-branch secdb; not per-CVE addressable. Mirrors B3's shape.
- [x] **GUI-2b — apk fixed-verdict (split from GUI-2 on 2026-08-12; unblocked by KN-FIX-3/D8 since
  2026-08-13).** ✅ **CLOSED 2026-08-27** — grilled and shipped same day (`feat/knowledge-apk-verdict`,
  EDR-VEX-01 **D9**): `value.APKFixedByBounds` (max-bound rule, rapid property invariants) +
  `EnterpriseView.StrictFixesFor` (verdict-grade selection — only positively-`apk`-stamped bounds) +
  the correlation gate beside the rpm verdict; kernel/domain/app at their 100% tiers, `make check`
  green. Along the way the pre-existing apk COMPARATOR defect was found and fixed (lexicographic
  fallback ordered `r5` above `r10` and `rc1` above its release — reached the range gate too).
  Live VM verification deliberately waits on an Alpine estate (none deployed; D9 records the smoke
  case). _Original filing:_ **MED for estates shipping Alpine.** D7 put fixed-apk BOUNDS on the card, but the
  correlation verdict is still rpm-only: `internal/knowledge/app/correlate.go` drops a match only
  via `value.RPMFixedByStream`, so an apk component installed at-or-above its vendor fix keeps its
  match — and Governance's display twin (`internal/governance/app/assessment.go`) renders no
  fixed-by-verdict for apk either. The kernel already orders apk versions
  (`value.VersionClassAPK`, `-rN` build revisions) and D8 gave fixes the `apk` ecosystem
  qualifier, so what remains is the verdict function plus its one design question: **branch
  scoping** (is a v3.20 secdb bound valid evidence for a v3.19 component? — the apk analogue of
  the rpm EL-stream rule). Design-first as an EDR-VEX-01 delta, mirroring the Red Hat PR2
  (bounds) / PR3 (verdict) split. Cluster: Distro-feed completeness (work order above).
  **Scope:** SMALL-MED. **Grilled 2026-08-27 → EDR-VEX-01 D9:** max-bound rule over
  strictly-`apk`-stamped bounds, match-time only, rpm parity; the precise branch model is GUI-2c.
  **LIVE-VERIFIED 2026-08-28 (A/B on the VM, real sidecar SBOM):** `musl-utils@1.2.5-r1` →
  CVE-2026-6042 finding present, card carrying SIX multi-branch apk bounds incl. the v3.20 fix
  `1.2.5-r2` (`alpine` proposal on the audit trail — the drawer's remediation line);
  `musl-utils@1.2.5-r2` → the CVE absent, with a below-fix zlib control on the same release
  proving the absence is meaningful (3 findings, zlib present). Honest attribution: on this
  multi-branch card the absence is delivered by OSV's branch-aware filter — the max-bound
  verdict correctly ABSTAINS (newer branches' bounds r10/r22/1.2.6-r1 sit above r2), the exact
  conservative trade D9 records; the verdict's unique wins (backports OSV admits) are carried by
  the kernel/domain/app tests, and sharpening the multi-branch case is GUI-2c. The same round
  also surfaced + fixed KN-DISTRO-1 (below).
- [ ] **GUI-2c — precise apk branch scoping (filed 2026-08-27 with EDR-VEX-01 D9; consciously
  deferred — R5 posture).** LOW. The exact rpm mirror the D9 verdict declined for now:
  `FixedVersion` gains a branch/stream field, the D7 Alpine client stops discarding branches, and
  the verdict scopes the component's PURL `distro=` qualifier to the bound's branch. A
  domain-model change with D8-class store-codec/decode-healing surface, bought against D9's
  stated residual (component's branch unswept AND its true bound above every collected one →
  false-"fixed"; max-bound's converse is a needless "affected"). **Revisit only on a measured
  hit in either direction** — read from code, nothing measured. Cluster: Distro-feed
  completeness. **Scope:** MED (domain change — Must-ask, design before code).
- [x] **GUI-3 — Red Hat `changes.csv` modified-since sweep.** ✅ **CLOSED 2026-08-27**
  (`feat/knowledge-apk-verdict`, EDR-VEX-01 **D10**). Step zero verified first: the VEXFEED path
  covers only `not_affected` applicability, not severity/fixes — so it complements, never
  replaces. The gate ships in the Red Hat sweep itself: the **per-CVE VEX** `changes.csv`
  (verified live — `"<year>/cve-<id>.json"` rows; the advisory-level CSV is NOT per-CVE) feeds an
  optional `RedHatChangeSignal`; after the first full sweep only changed-or-never-fetched carded
  CVEs are re-asked. Three fail-open rules (first-sweep-full/restart heals · signal failure →
  full sweep · fold error doesn't advance the watermark) keep it an efficiency gate, never a
  correctness gate. `THEMIS_REDHAT_CHANGES_URL` overrides the CSV; no switch of its own.
  **LIVE-SOAKED 2026-08-28:** ~60 sweeps at a 3-minute test cadence over 3 hours on the VM —
  **zero** `red hat enrichment failed` lines; the gate never degraded correctness.
  _Original filing:_ LOW-MED, efficiency — the feed re-asked Hydra per carded CVE per interval.
- [x] **GUI-4 — per-distro feed-health rows.** ✅ **CLOSED 2026-08-13** — shipped in PR #95
  (`b4ed088`): distro component queries record under `<source>/<distro>` (`osv/alpine`,
  `osv/rocky`, …) at the Tier-3 informational tier (`adapters/feed/health_source.go`), so a quiet
  distro reads as an old timestamp and never as degraded, while the aggregate `osv` row keeps the
  tier-2 verdict. Live-verified 2026-08-12 (`osv/rocky` row on the dashboard). *(Checkbox ticked
  late, 2026-08-27.)* _Original filing:_ `GET /feeds` showed one `osv` row, so Alpine data flowing
  and quietly absent looked identical; this was the visibility half of "add feeds for
  rhel/rocky/alpine" — the rhel/rocky DATA already flowed; only Alpine (GUI-2) was a real gap.
- [x] **GUI-5 — Rocky errata feed for RXSA-only advisories.** ✅ **CLOSED 2026-08-27**
  (`feat/knowledge-apk-verdict`, EDR-VEX-01 **D11**). Verified live first: the RXSA universe is
  **29 advisories** with structured `cves[]` + per-product NVRA lists, which settled the shape —
  a D7-pattern feed (walk the tiny whole set, intersect with carded CVEs in memory), not per-CVE
  queries. Ships as the `rocky` feed: RXSA-prefix only (RLSA clones stay with the Red Hat feed),
  fixes from **source** packages only (binary rpms are the rebuild SCOPE per EDR-CORRELATION-01),
  `SeverityUnknown` (never contends for the headline), trust=Observed, tier=2, opt-in
  `THEMIS_ROCKY_ENABLED`/`_URL`/`_POLL_INTERVAL`, health row `rocky`.
  **LIVE-VERIFIED both ways.** 2026-08-27: the failure path (VM egress firewalled → sweep error
  logged, `rocky` row degraded, `consecutive_failures` counting; timeout raised 30s→120s along
  the way). 2026-08-28, after the `errata.rockylinux.org` allowlist opened: the success path —
  first sweep `folded=1` (the SIG-Cloud-9 kernel fix `0:5.14.0-687.36.1.el9_8.cloud.1.0` onto
  the gathered CVE-2026-23415 card, 27s after startup), `rocky` row `healthy`/tier-2.
  **End-to-end evidence demo (2026-08-28, on the VM):** two one-component releases of a
  SIG-Cloud-9 kernel — `5.14.0-687.15.1.el9_7.cloud.1.0` (old) vs `…687.36.1.el9_8.cloud.1.0`
  (the RXSA build). Old: **113 findings, CVE-2026-23415 present**; card shows proposal source
  `rocky` and kernel fixes `[0:…el9_8, 0:…el9_8.cloud.1.0, 0:6.12…el10_2]` — the `.cloud` NEVRA
  exists in NO Red Hat data, so its presence (and the drawer's published-fix line) is
  attributable to the rocky feed alone. New: **45 findings, the CVE absent** (false positive
  suppressed). D16 compare: `{fixed:68, new:0, persisting:45}` with the CVE in `fixed` —
  113−45=68 exact. Off-VM OSV predictions (113/45) matched the live counts precisely.
  _Original filing:_ LOW-MED — RXSA advisories (Rocky-exclusive/SIG packages) exist in no Red Hat data.
- [x] **KN-DISTRO-1 — Trivy's bare-version `distro=` qualifier skipped every distro component
  (measured live 2026-08-28; FIXED same day, `e5bb11b`).** The first real Alpine SBOM ever driven
  through discovery (Trivy CycloneDX, 62 components) produced a **zero-finding release that read
  as a clean image**: `osvDistroEcosystem` required `name-version` in the qualifier
  (`distro=alpine-3.20.2`), but Trivy's apk dialect puts the name in the PURL namespace
  (`pkg:apk/alpine/…`) and only the bare version in the qualifier (`distro=3.20.2`) — the split
  found no name, returned "", and every component was silently skipped by the OSV distro query.
  Worst-direction failure: vulnerable reads as clean, with nothing logged. **Fix:** one shared
  `distroNameVersion` resolves both dialects (bare numeric qualifier → name from the PURL
  namespace) and feeds both `osvDistroEcosystem` and `healthDistro`, so the per-distro health
  rows (GUI-4) heal too. Found by the GUI-2b live round — the "first real SBOM of a kind finds
  the dialect gap" class, same family as KN-FIX-3.
- [ ] **FEED-CERT-1 — CERT advisory-membership signal (CERT-In / CERT/CC) + the filtered list
  (filed 2026-08-28, user ask; design-first).** LOW-MED — MED **if** the driver is CERT-In
  compliance (Indian-regulated estates track CIVN/CIAD advisories under the 2022 CERT-In
  directions). NOT a new vulnerability list: a CERT note is an authority flagging an existing
  CVE — the KEV shape — so the design is an **advisory-membership signal on carded CVEs**
  (D5-bounded, never a mirror), generic once for any national CERT. Three parts: (1) domain —
  `ExploitSignal` (or sibling) gains additive advisory memberships `(source → advisory id)`;
  a domain change, Must-ask, EDR-KNOWLEDGE-01 delta; memberships join KEV/EPSS as
  disposition-watcher premise drift and as deterministic AI-grounding facts. (2) sources —
  CERT/CC is per-CVE JSON (`kb.cert.org/vuls/api/`, perfect D5 fit, cheap, LOW value);
  CERT-In has NO structured feed (HTML/PDF, maybe RSS) — **step zero is a verification probe**
  of what is machine-readable; if scraping is the only path, the honest scope may be an
  operator-curated list upload (the scanner-report pattern), not a poller. (3) the read half —
  a findings/posture filter ("flagged by cert-in") + later a Communication compliance-report
  serializer, which wants R3's delivery channel anyway. Sequence: after the GUI/scanner track,
  beside R3.
- [ ] **GUI-16 — "What's new" page: newest CVEs and their details (filed 2026-08-28, user ask;
  design settled at filing, D5-bounded).** LOW-MED, capability. NOT a world-feed mirror — a page
  listing every CVE published this week would persist uncarded-CVE data, exactly what
  EDR-KNOWLEDGE-01 D5 forbids, and would be a worse copy of NVD/cve.org. Two doctrine-clean
  layers instead: **(1) the page** — newest **carded** Faultlines sorted by card-creation time
  (CVE · stored summary · severity band · exploit signals · published fix · which releases it
  touches), pure read over persisted estate-relevant data; the staying-current sweep, gather,
  and the autonomous analyst are what keep it fresh. Needs a small Knowledge read addition
  (list-faultlines-by-recency) + one GUI view. **(2) optional panel** — an ephemeral
  latest-published list fetched on view through the proxy (displayed, never persisted —
  "Gathering Is Not Knowing"), each row with a **Gather** button onto the existing
  `POST /faultlines/gather`, so entering the estate stays an explicit operator act. Related:
  [[FEED-CERT-1]] (a CERT-flagged filter would be a natural facet on this page). **Scope:**
  SMALL-MED (layer 1) + SMALL (layer 2).
- [ ] **REP-1 — Enterprise reports section (filed 2026-08-28, user ask; the R3 arc grown to its
  real size — grill as ONE design before any code).** MED-HIGH aggregate value; the named report
  set: PSM · SLA · **SVM-status (SVM = Software Vulnerability Manager, confirmed 2026-08-28 —
  possibly mirroring an incumbent tool's report; get a SAMPLE of the current report for the
  grill, reports are contracts with their readers)** · Fixed-Vulnerability · Fault · CVE-Status ·
  Customer-scan · Configuration/EOL. PSM expansion still unconfirmed.
- [ ] **REP-2 — assessment-workflow metrics page: the enterprise state vocabulary as a
  projection (filed 2026-08-28, user ask; design-first, grill WITH R2).** MED. The user's
  state set: Initial severity · Not Assessed · In Progress · In Analysis · Completely
  Assessed · Mitigate-with · Waiting-on-solution · No Release / Release / Mitigate-in-Future-
  Release · Accepted · No Solution · False Positive · Transferred. Mapping at filing: ~8 states
  are PROJECTIONS over existing data (no-position=Not-Assessed · under_investigation=In-
  Analysis · has-position=Assessed · accepted_risk=Accepted · not_affected+justification=False-
  Positive · affected+no-published-fix=Waiting-on-solution, flips automatically when a feed
  delivers a bound · proposals-trail=initial-vs-current severity). Three are GAPS needing
  structured Position fields: **mitigation link** (what mitigates), **target release** (fixed-in
  planning), **transfer/ownership** — the SAME structured-fields surface R2 has been waiting
  for; grill the two as one design. Architectural line: the enterprise vocabulary is a
  **configurable mapping** (stance+justification+card-facts → org state names), never a
  replacement state machine — VEX stays clean on the wire while the GUI page and the REP-1
  SLA/SVM reports consume the same bucket rollup. Likely from the incumbent process — a sample
  of the current metric page/report is grill input, same as REP-1.
- [ ] **LIC-1 — license visibility → policy flags → escalation manager (filed 2026-08-28, user
  ask; phased, design-first).** License risk is ADJACENT to security risk — same pipeline shape
  (evidence → policy → finding → human decision → report), different domain (no CVEs, no OSV,
  legal authorities, per-product policy matrices) — so full workflow would be a NEW bounded
  context, not a Knowledge bolt-on. The data already flows: CycloneDX/SPDX declared licenses sit
  byte-for-byte in every stored SBOM; the inventory parser currently discards them. Phases:
  **(0) visibility, SMALL-MED** — parse declared licenses into the inventory (additive field;
  API change, Must-ask) + show on component views; **(1) deterministic policy flags, MED** — a
  configured allow/deny/review license policy evaluated over the inventory, violations on the
  posture + a REP-1-family report (this alone answers "which has license issues"); **(2) the
  escalation manager, LARGE, own EDR** — routed escalations, legal-review positions; THE grill
  question is Governance-machinery-reuse vs own context. Constitutional line unchanged: a
  classifier's license verdict is Information — humans/policy decide. AI (optional, later):
  obligation summarization as a clearly-labeled Information capability. Related: [[REP-1]]
  (Configuration/EOL is the sibling "component compliance" report). **Home is Communication, not the GUI**: each report is a Publication
  (deterministic materialization, immutable content, supersede-not-edit, human-triggered) with
  its own serializer; the GUI "Reports" section is a thin trigger+list over the existing
  CreatePublication flow. Cost map at filing: **SMALL serializers over existing reads** —
  CVE-Status (posture), Fixed-Vulnerability (the D16 compare's `fixed` bucket — live-proven
  2026-08-28), Fault (the card), PSM (DASH-1 product rollup); **MED reads to add** — SVM-status
  (estate-wide aggregates), Customer-scan (C1 estate-graph join); **design-first sub-items** —
  **REP-1a SLA policy model** (fix-within-N-days per severity: the policy config does not exist;
  timestamps do) and **REP-1b component EOL data** (Themis holds none; endoflife.date is a clean
  JSON API and D5 fits — fetch EOL only for products/distros in the estate; feeds the
  Configuration/EOL report AND could flag EOL components on the posture). Pairs with **R3
  delivery** (SMTP/webhook) — a report nobody receives is a log line; build as one arc. AI:
  optional clearly-labeled executive-summary overlay (Information-class), never the figures. ✅ **CLOSED 2026-08-13** (EDR-GUI-01 grilled D1–D13; all four phases shipped + live-verified in PR #96; spike branch deleted; OpenSpec `phase3-gui-dashboard` archived). **P2 — roadmap.** The spike branch never merges; when
  the VM evaluation settles the style and feature set, the keeper is rebuilt properly (EDR +
  OpenSpec change): auth on its own inbound edge, the authority-line buttons (accept/reject/
  publish) designed rather than spiked, tests, coverage registration. Until then the spike doc is
  the running requirements capture.
- [x] **GUI-7 — dashboard cannot upload a scanner report (filed 2026-08-14).** LOW-MED, usability.
  ✅ **CLOSED 2026-08-14** — (a) shipped same day; (b) realized by multi-scanner Phase C below
  (raw Trivy JSON translated in-browser; further tools by demand per D16, which is a design
  posture, not an open defect).
  ✅ **(a) SHIPPED 2026-08-14** — `scanner-report` in the SBOM-manager kind selector, curated
  `{findings:[…]}` shape auto-detected with a finding count in the file note, and `format` sent
  only for the sbom kind (`cmd/dashboard/static/app.js`). **(b) remains open:** accept a **raw**
  Trivy JSON and translate it to the curated document — a design question (client-side JS mirror
  of the TESTING.md jq recipe vs a server-side translator ACL; a translator that lives
  server-side belongs to a context, not the dashboard — "Must ask" before building). Skip counts
  must surface in the UI when (b) lands: "ingested most of the report" and "ingested the report"
  must not look alike to an operator.
  ✅ **Multi-scanner Phase A SHIPPED 2026-08-14** (EDR-GUI-01 amendment D14, the labeling
  phase): `provenance_source` on `EvidenceSummary` (spec + regen, threaded
  store→wiring→app→handler — the column existed since Evidence migration 000001; the D14-flagged
  API change, additive/read-only), the upload form auto-fills it from the report's per-finding
  `scanner` field (scanner-report kind only), and the evidence table gained Source (tool chip) +
  Filed (relative time) columns.
  ✅ **Phase B SHIPPED 2026-08-14** (D15): the release posture's "Scans" card lists each
  scanner-report row (tool chip · filed · async asserted-count), click-through to
  `#/scan/<evidenceId>` — the stored document fetched through the proxy and joined to the
  posture by CVE in the browser; per claim the tool's assertion beside the enterprise state
  (band/stance/priority bar, drawer deep-link); asserted/matched/decided/no-Finding tiles; the
  honest remainder rendered dimmed with a filtered-at-ingestion label. No new backend truth.
  ✅ **Phase C SHIPPED 2026-08-14** (D16): raw Trivy JSON accepted by the upload form —
  `detectTranslator` + `translateTrivy` (a pure-function port of the TESTING.md jq recipe,
  including the ecosystem vocabulary map), Kind auto-set to scanner-report, skip count in the
  file note, curated document is what uploads. Phase D stays deferred as recorded.
- [ ] **GUI-15 — second in-browser scanner translator: Grype first, Xray / Black Duck by demand
  (filed 2026-08-21 with the tier roadmap, EDR-ENHANCE-T3).** LOW-MED, capability. EDR-GUI-01 D16
  fixed the shape — one pure translate function + a detector per tool, the curated `{findings:[…]}`
  document staying the only wire contract — and Trivy proved it live. Grype is the closest dialect
  and the most requested; each further tool registers only on demand. **Dep:** GUI-10's test
  harness lands first, so the second translator is born tested (the first one's live-only testing
  is exactly the gap GUI-10 records). **Scope:** SMALL per tool.
- [ ] **GUI-10 — D16 translators have no unit-test harness (filed 2026-08-14).** LOW, quality.
  D16 says each translator is "a pure function with its own tests", but the repo has no JS
  test runner and `cmd/dashboard/static/app.js` is untested by design (the spike-ported GUI is
  tested at the Go proxy/handler seam). Adding a node-based dev dependency + Makefile hook is
  a build change ("Must ask") — decide harness vs porting translator tests to Go via a JS
  engine when a second translator lands. Until then the translator is exercised only live.
- [ ] **AI-CMP-1b — the Information path never validates `subject_id`; the model can echo the wrong
  one (filed 2026-08-24, live).** LOW. Live-witnessed twice on `compare_releases`: the prompt tells the
  model to echo the CANDIDATE release id in `subject_id`, and CyberPal returned the BASELINE id instead
  (`rel-old` on the e2e fixture; the baseline id on the MRF pair). Harmless today — `subject_id` is
  response metadata, the prose and cited CVEs were correct — but the Decision path validates its
  `finding_id` echo and the Information path validates nothing, so a capability cannot rely on the field.
  **Fix shape:** a cheap subject-echo check on the Information branch (the expected id is known — it is the
  Selection's subject), warning-not-fatal like the rationale scan (an echo mismatch is a labeling slip,
  not an ungrounded citation). **Scope:** SMALL.
- [ ] **AI-PROSE-1 — narration renders priority NUMBERS as severity WORDS / restates aggregates loosely
  (filed 2026-08-24, live).** LOW, expected-by-design note. `compare_releases` rendered "residual priority
  of critical" instead of "152", and once mis-restated a bucket count. Grounding Verification anchors to
  IDENTIFIERS, not to arithmetic in prose (T8), so this is not a gate failure — it is the documented limit
  of what the gate guarantees. **Not a bug to fix so much as a reading rule to socialize:** trust the named
  CVEs and the deterministic tiles; treat summary numbers in the prose as prose. Captured so the demo
  narration's "critical" wording is not mistaken for a defect. Revisit only if a stricter numeric-claim
  check is ever wanted (it would need the model to cite numbers as structured fields, not free text).
- [x] **AUTO-VOL-1 — the autonomous analyst proposes too much per sweep; one decision cascaded to
  110 advisory proposals (MEASURED LIVE 2026-08-26).** FIXED 2026-08-26 (`feat/auto-vol-1`). MED, usability. Δ4b's walking skeleton is
  SAFE (verified live: `decided_findings=0`, every ai proposal stays `proposed`, never
  auto-accepted — the constitutional bar held at volume) and IDEMPOTENT (`autonomous_proposals`=110,
  the count held at exactly 110 across ~6h of 2-minute ticks — dozens of sweeps re-proposed NOTHING). But one seeded `not_affected` cascaded — via semantic
  similarity — into **110 advisory proposals in a single 2m sweep** (examined 215, proposed 110).
  That is exactly the "operators distrust and disable the plane" noise D-Δ4b-5 worried about, made
  concrete: the guardrails contain the DANGER, not the VOLUME. Two levers are too loose:
  (1) **no per-sweep proposal cap** — the pool (500 tokens × cost 1) admitted all 110 without
  pausing; a first-run pool should be sized to pause, and/or a hard `max-proposals-per-sweep`;
  (2) **the precedent-match threshold is too permissive** — the analyst proposes on ANY decided
  precedent the semantic search returns, however weak; it should require a STRONG match (high cosine
  AND meaningful release_overlap, both already computed by the G-AI-3 delta ranking) before advising.
  **Fix shape:** add a min-similarity/overlap gate in `AutonomousSweep.gather` + a per-sweep cap;
  both are small, additive, and testable. A Δ4b follow-up refinement (the skeleton proved the seam +
  the guardrails, which was its job); this is the tuning the live run surfaced.
  **DONE (2026-08-26):** `bestQualifyingPrecedent` now gates on a min cosine (default **0.75**) AND
  a known min release-overlap (default **0.5**, the G-AI-3 delta) — the exact-CVE fallback (same CVE,
  Score 0 by lookup) is exempt from the cosine floor; plus a per-sweep `maxPerPass` cap (default
  **20**, worst-first, `SweepResult.Capped` flagged, the remainder held unproposed for the next
  window). All three are operator-tunable via `THEMIS_INTELLIGENCE_AUTO_MIN_SCORE` /
  `_AUTO_MIN_OVERLAP` / `_AUTO_MAX_PER_PASS` (the last `< 0` = explicitly uncapped); startup logs the
  effective values; the sweep log gains a `capped` field. app-ring coverage 100%.
  **LIVE-VERIFIED on the VM (2026-08-26):** clean-slate run (117 stale `ai` proposals + idempotence
  record cleared) against the SAME 215-Finding estate that produced 110 before. Four consecutive 2m
  sweeps each read `proposed=20 examined=215 capped=true`, with `skipped` climbing 107→127→147→167
  (+20/pass — the idempotence record advancing worst-first, never re-proposing). The gate rejected
  the weak precedents (skipped), the cap bounded each pass at exactly 20, `paused=false` (cap bit
  before budget). Guardrails held throughout: `ai_accepted=0`, `decided_findings=5` unchanged. 110→20.
  Box returned to default-OFF, test proposals cleared. **CLOSED.**
- [ ] **GUI-11 — the per-scan join is blind to aliases: a GHSA-keyed claim can never match
  (filed 2026-08-17, live test).** LOW → **re-scoped 2026-08-23 (T2 execution): DESIGN-FIRST,
  blocked on a Knowledge domain decision.** The T2 plan assumed the card's alias set existed to
  expose — it does not: every feed ACL normalizes GHSA/DSA/RHSA ids to the canonical CVE at
  ingestion and DISCARDS them (`osv.go` folds `rec.ID`+`rec.Aliases` to one CVE; nothing persists
  the aliases). The real fix is therefore a Faultline addition — an append-only union `aliases`
  set captured at ingestion, reconciled, stored, exposed on the card read (plus a per-release
  bulk read for the browser join) — a domain-model + migration + ACL change needing its own
  EDR-KNOWLEDGE-01 decision before code. Honest today (the chip's wording covers it); implement
  when the alias decision is taken.
  report's `GHSA-6v7p-g79w-8964` (msgpack) row renders "no Finding — filtered at ingestion"
  — correctly for that document, but the scan view's browser join (`viewScan`, join by literal
  `f.cve` against posture `p.cve`) would say the same even when the release DOES carry the
  corresponding CVE, because Knowledge normalizes aliases into the card while the client join
  never sees them. Honest today (the chip's wording covers it), silently pessimistic tomorrow:
  any tool that emits GHSA/DSA/RHSA ids inflates the "No Finding" tile. Fix shape: expose the
  card's alias set on the posture row (or a Knowledge alias-resolve read) and join through it.
- [x] **GUI-12 — raw-scanner re-upload dedup is defeated by the translation timestamp
  (filed 2026-08-17 from code, MEASURED live the same day).** ✅ **CLOSED 2026-08-28**
  (`fix/gui12-rescan-dedup`, per EDR-ENHANCE-T1 decision 1): `translateTrivy` now derives
  `observed_at` from the raw report's own `CreatedAt` (the time the tool actually observed;
  Trivy's 7-digit fractional seconds trimmed to milliseconds for `Date.parse`, offsets
  normalized to UTC, node-verified deterministic) — byte-identical raw re-uploads translate to
  byte-identical curated documents and Evidence's content addressing dedups them. The EDR's
  "omit and let the server stamp" fallback was verified NOT to exist on the wire (the scanner
  ACL's `parseObserved` rejects a blank `observed_at` — omitting would silently void every
  finding), so a report with no usable `CreatedAt` keeps the fresh stamp AND the file note says
  "stamped fresh, so a re-upload will NOT dedup" — silently losing dedup and visibly losing it
  must not look alike. Browser-side only; born untested by design — GUI-10's harness covers it
  when it lands. Live verification: re-upload the same raw Trivy file twice → one scan row +
  the 409/dedup toast.
  _Original filing:_ the SAME raw Trivy file uploaded twice yielded two curated documents and
  two scan rows (Round-2 live test 2026-08-17) — a double-click or re-run CI job inflated the
  Scans card and doubled every claim in the per-scan join.
- [x] **EV-DEDUP-1 — the same bytes filed against a DIFFERENT release were silently swallowed:
  `created=false` read as success while the new release received no evidence.** ✅ **CLOSED
  2026-08-19 (measured live: a fix-verification candidate stayed empty and only the compare's
  422 revealed it).** EDR-EVIDENCE-01 D3 (one observation, one record — dedup by bytes alone)
  holds; the defect was the SILENCE. Now: same bytes + same release ⇒ benign dedup (unchanged);
  same bytes + different release ⇒ **409** naming the release + evidence id the content already
  resolves to (`ContentFiledElsewhereError`, spec'd on POST /evidence, rendered verbatim by the
  GUI toast). Integration-tested (`TestSave_Idempotent` cross-release arm).
- [ ] **EV-DEDUP-2 — should one observation be attachable to MANY releases?** LOW, design-first.
  **Design DELIVERED 2026-08-23 (T2's last item): EDR-EVIDENCE-01 D10 (PROPOSED)** — observation
  stays one record (D3 upheld); a new `evidence_filings` association table carries
  (evidence, release); same bytes + new release becomes a FILING with its own
  `EvidenceRegistered` event (correlation runs for the new release), replacing the 409.
  Implementation enters the queue only when D10 is confirmed.
  The D3 refusal (EV-DEDUP-1) is honest but leaves "the same document genuinely describes two
  releases" (a re-tagged image; two releases cut from one build) unsupported — today the second
  release needs byte-different content. Supporting it means an association model (document
  stored once, filings per release, events per filing) — a real D3 revision with correlation
  and read-API implications. Needs an EDR decision before code; rarely bites in practice
  because real SBOMs carry serialNumber/timestamp and differ per build.
- [x] **GUI-14 — every SBOM over 1 MiB uploaded via the GUI died as a fake 502 "node
  unreachable".** ✅ **CLOSED 2026-08-19 (measured live the same day, first real-size SBOM
  through the authed dashboard).** The write-gate's D13 identity check buffered a mutation
  body via `LimitReader(1 MiB)` and handed the proxy ONLY the truncated bytes while
  Content-Length still promised the full file — the outbound write died mid-stream and the
  proxy's ErrorHandler reported the healthy Evidence node as unreachable. Invisible until now
  because every prior GUI write (decisions, scanner reports) fit under the cap. Fix, both
  halves honest: `documentPosts` routes (the evidence upload — a pure document intake, no
  identity claims to check) skip the identity buffer and stream through INTACT at any size;
  every other mutation over the cap refuses with a real 413 ("body too large for a
  decision") instead of forwarding truncated — which also closes the padding bypass that
  merely skipping the check would have opened in D13. Scope/session/reverify still enforced
  on document routes. Test: `TestGate_LargeBodies`.
- [x] **GUI-13 — the SBOM manager could not file a NEW build: every selector was a dropdown of
  what already exists.** ✅ **CLOSED 2026-08-19 (filed same day, live VM finding).** The upload
  form offered only registered Product/Project/Release — but a fresh SBOM is BY DEFINITION a
  build that is not registered yet (the fix-verification loop's candidate), so the GUI could
  receive a scan against an old build and never a new build at all; first registration lived
  only in `scripts/gf-upload-sbom.sh` (which itself always creates a fresh chain unless `-r`,
  and predates auth). Fix: each selector gains “＋ New…” revealing a name/version field; upload
  registers the missing Product→Project→Release chain first (existing Registry write endpoints —
  no new API surface; the D11 gate already classifies them as writes), then files the document
  against the new release. Reuse-not-duplicate guard: typing a name that already exists in the
  loaded list is refused with "pick it from the list". After registration the entries solidify
  into the dropdowns, selected, so the follow-up scan upload needs no re-typing.
- [x] **KN-SCAN-2 — detection origin is invisible past the card.** ✅ **CLOSED 2026-08-14**
  (filed same day). `DetectionOrigin` now rides the whole path: both `RecordMatch` producers
  stamp it (`discovery` for correlation + the re-discovery sweep; `scanner/<name>` from the
  record's previously-dropped `scanner` field, bare `scanner` when unnamed) →
  `ComponentMatched` (additive/omitempty, schema declared — the contract schema was also
  trued-up to declare the already-shipping additive fields it silently omitted) → Governance
  `finding_components.detection_origin` (migration 000011, first-wins upsert) → the read API
  (`detection_origin` on Component) → a "found by scanner/…" chip on the drawer's matched
  components (discovery stays unmarked — it is the default, not a signal). **One deliberate
  deviation from the filed fix shape:** the engine name did NOT go into the proposal source —
  source stays the closed-vocabulary `scanner` so the trust/precedence tables remain enumerable
  (TRUST-2); the card's proposal history therefore still reads generic `scanner`, and the
  per-engine answer lives on the match/Finding, which is where the operator asks it. Provenance
  only, never authority. **Live-verified 2026-08-14 on a fresh-wiped estate:** Anchore/Syft SPDX
  SBOM → 100 cards / 343 discovery matches / 100 Findings; a real Trivy report uploaded through
  the new GUI selector produced two `scanner/trivy` components (setuptools@70.3.0 on
  CVE-2026-59890 + CVE-2025-47273) sitting beside discovery's setuptools@39.2.0 on the SAME
  Findings — the two-engines-one-decision shape, with provenance distinguishing the rows.
- [ ] **KN-SCAN-3 — canonicalize scanner-report component ecosystems (filed 2026-08-14).** LOW,
  measured live the same day: Trivy names ecosystems in its own vocabulary (`python-pkg`,
  `node-pkg`, `gobinary`, …) and the curated recipe used to pass it verbatim, so a scanner row
  read ecosystem `python-pkg` beside discovery's `pypi` for the same package. Harmless by
  construction — `value.CanonicalEcosystem` doesn't know these names, and an unknown ecosystem
  never filters a fix nor hides anything (KN-FIX-3 fail-safe) — but the two roads should read as
  one vocabulary. The TESTING.md jq recipe now maps the common types (same-day fix); this item
  is the durable half: canonicalize at the seam where the component is parsed
  (`adapters/evidence/scanner_source.go`), extending the alias table rather than trusting every
  future recipe/client to remember.
- [ ] **KN-VERDICT-1 — a vendor-backported fix cannot clear a live finding: the rpm fixed-verdict
  never reaches it across any of its three links (filed 2026-09-02, MEASURED live on
  MRF/cdmrf-oamp/R20.1.0.0-118, CVE-2025-47273).** HIGH for the estate's trust in the queue;
  cluster EDR-VEX-01 / EDR-CORRELATION-01; link (a) is design-first. The estate flags setuptools
  vulnerable while Red Hat backported the fix into RHEL 8.10 (RHSA-2025:11044,
  `python-setuptools-0:39.2.0-9.el8_10`; Rocky's RLSA-2025:11044 is the 1:1 clone the `rocky`
  feed rightly skips — those bounds arrive via `redhat`). Every feed reads healthy because every
  feed IS healthy: the Hydra doc lists RHEL 8 as Affected-with-errata, NOT `not affected`, so the
  Phase-2 suppression overlay correctly never fires — the ONLY path that can clear this finding
  is the Phase-3 rpm fixed-verdict (`app/correlate.go` + `value.RPMFixedByStream`). Three links,
  each verified in code, keep that verdict away from it:
  **(a) No cross-ecosystem bridge — the big one, design-first.** The estate carries setuptools as
  a PYTHON package (`setuptools@39.2.0`, pypi/python-pkg — the very component KN-SCAN-2's
  2026-08-14 live verification recorded on this same CVE), while the vendor fix folds as Package
  `python-setuptools`, Ecosystem `rpm`. `FixesFor("setuptools", "pypi")` matches nothing and
  `RPMFixedByStream` refuses non-rpm ecosystems by construction — each fail-safe correct alone,
  jointly a PERMANENT false positive for every distro-owned site-packages component, patched or
  not. The relationship "this RPM provides that language package" does not exist in the model;
  bridging it (SBOM provenance/ownership relationship vs. a curated rpm↔upstream name map) is an
  EDR decision before code.
  **(b) Scanner-path matches take NO verdict at all.** `ScannerReportService.ApplyIngest` records
  as-is on the premise "the scanner already version-matched" — exactly false for backports, which
  scanners cannot see. The discovery-path gates (reconciled range + rpm/apk fixed-verdicts)
  should also run on scanner matches whose component is verdict-capable.
  **(c) Matches are append-only and the verdict fires only at correlation-apply time.** Vendor
  bounds fold on a later 12h sweep; nothing revisits an existing match when new bounds prove it
  fixed (the re-discovery sweep re-runs the gate, but `RecordMatch`'s dedup keeps the old row —
  the `continue` only avoids re-adding). Fix shape per "overlays, never deletes": folding new fix
  bounds re-evaluates existing matches and rides the system-proposal channel like the
  not_affected overlay — never a silent match delete.
  Recorded honestly: if the deployed image's RPM is OLDER than `-9.el8_10` the finding is REAL
  and Themis is right — the VM check (match row's component shape + installed NEVRA) decides
  which link is live for MRF; (b) and (c) are code facts either way.
  **VM-VERIFIED 2026-09-02 — the feed side is FULLY working; link (a) is the live defect.** The
  card holds the exact bound `python-setuptools 0:39.2.0-9.el8_10 (rpm)` (plus el9/el10 and the
  python39-module rebuild set); the `redhat` vuln-facts proposal folded; feed health green,
  0 consecutive failures. The open matches are `setuptools@39.2.0 (pypi, source empty)` on both
  releases plus scanner `setuptools@70.3.0` (once `python-pkg`, once `pypi` — KN-SCAN-3 again)
  and module-scope `python3-ply`/`python3-pyyaml`. Notably there is NO rpm-shaped setuptools
  match — either the SBOM never carried the RPM, or the rpm road worked and was verdict-cleared
  at correlation, leaving only the pypi shadow of the same installed files flagged (`rpm -q
  python3-setuptools` on the image discriminates). Design consequence, measured not assumed: a
  name map (`setuptools`↔`python-setuptools`) alone CANNOT fix (a) — the pypi component's
  version is bare `39.2.0`, no release segment, so an rpm compare against `0:39.2.0-9.el8_10`
  is undecidable-at-best from that row; the verdict must find the OWNING RPM component (full
  EVR) in the same inventory, i.e. the bridge is a provenance relationship, not vocabulary.
  **FALSE POSITIVE CONFIRMED on the image (2026-09-02):** `rpm -q` shows
  `platform-python-setuptools-39.2.0-9.el8_10.noarch` installed and its changelog names the
  CVE-2025-47273 fix — the flagged `setuptools@39.2.0 (pypi)` rows are the .egg-info shadow of
  a PATCHED rpm. Two further measured details for the grill: (1) the owning BINARY rpm is
  `platform-python-setuptools` (not `python3-setuptools`) while the card's bound is attributed
  to the SOURCE package `python-setuptools` — the bridge therefore needs file→binary-rpm→srpm,
  two hops, exactly what `componentPackage`'s source-wins rule already does for rpm-shaped
  components; (2) the scanner's separate `setuptools@70.3.0` (carrier, scanner/trivy) is a
  pip-installed copy BELOW the 78.1.1 upstream fix that no distro backport covers — it likely
  stays open legitimately after the bridge lands, so fixing (a) must not be validated against
  "the whole Finding disappears".
  **GRILLED + DESIGNED 2026-09-02 (same session, eight decisions, no code yet):**
  **`docs/engineering/decisions/EDR-VERDICT-01.md`** (D1–D9) is the decision record;
  **`openspec/changes/phase3-occurrence-verdicts`** (proposal/design/tasks) is the change. Net shape:
  Finding stays one-per-(release,CVE), verdict state moves to the OCCURRENCE (component row) —
  every examined occurrence is RECORDED with a state ("checked and fine" becomes visible; the
  scanner-path gap closes by unifying intake, not by a parallel gate); the ownership bridge runs at
  two labeled evidence grades (Observed = SBOM ownership edge · Inferred = same-inventory
  source-pkg + exact-version match, switchable off); an Inferred clearance leaves the queue by
  default, clearly labeled; Knowledge computes/stores, Governance mirrors; re-verdict = immediate
  on real card news + a stamped catch-up sweep (the phase that heals THIS finding); priority =
  full urgency from open carriers only; remediation + plan grouping per (package, world); drawer
  shows per-occurrence state/grade/reason. Four phases in tasks.md; binding validation criterion:
  39.2.0 cleared-with-reason, 70.3.0 still open, Finding still queued. Case-file report:
  artifact b57b9622-c500-4a8e-9e10-6503bdb91210. Implementation NOT started.

> **✅ The Knowledge feed items below are IMPLEMENTED under `openspec/changes/phase3-knowledge-feeds`**
> (19/19 tasks, gated, 2026-07-23): real OSV query-by-package + NVD modified-since fetch clients, **CVSS 4.0**
> in the NVD extraction (go-forward D-NVD-2), the **source-tier taxonomy** + tier-aware feed-health policy
> (go-forward D-FEED-2), and **scanner reports as advisory source Proposals** (EDR-KNOWLEDGE-01 D5/D6). The
> only remaining piece is the concrete Evidence `scanner-report` read adapter (a documented prerequisite,
> fakeable today). The v0.3.x monolith defects D-NVD-2 / D-FEED-2 themselves stay open (this is the Phase-3
> realization, not the v0.3.x fix).

- [x] **(LOW) Δ3a — re-embed on `knowledge.faultline_enriched`.** ✅ **DONE 2026-08-07.** Intelligence now
  holds a **second** bus binding, `FaultlineSubscription` (stream `knowledge`, interest
  `knowledge.faultline_enriched`), with its own consumer name — the cursor is per (consumer, stream), so
  sharing the Position name would make the two streams fight over one position. On an enrichment the
  consumer asks its **own index** which Findings it already holds for that Faultline (`IndexedForFaultline`)
  and rebuilds each. Querying its own store rather than asking Governance is the point: the set needing
  refresh is by definition the set already indexed, so no new read dependency is introduced to answer a
  question the store already knows.
  It reuses `buildRecord` unchanged, which means it **inherits the embed cache below** — an enrichment that
  did not move the severity produces the same subject text, the hash matches, and no model call is made. So
  subscribing to every enrichment costs one index read per event, not one embed per Finding. `rebuildIndex`
  now clears **both** cursors; resetting only the Position cursor would replay Positions against an index the
  enrichment stream still believed it had refreshed. Original report follows. The population consumer
  (`internal/intelligence/adapters/inbound`) indexes on Governance **Position** events only; a later Faultline
  severity change (which feeds `embed.SubjectText`) does not re-embed the affected findings until their next
  Position event. A freshness optimization, not correctness — the vector still matches on components. **Fix:**
  a second subscription (stream `knowledge`, interest `knowledge.faultline_enriched`) that re-embeds the
  faultline's findings. Surfaced building A4 (2026-08-04).
- [x] **(LOW) Δ3a — use `text_hash` to skip unchanged re-embeds.** ✅ **DONE 2026-08-07.** `Store.TextHash`
  existed, was documented for exactly this, and was consulted by nothing but its own test. It is now
  `CachedEmbedding`, returning the hash **and the vector** — the missing half: knowing the text is unchanged
  only avoids an embed if the stored vector comes back with it, because the row still has to be rewritten
  with the new stance/rationale. A revise that moves only the labels (neither of which is embedded —
  `SubjectText` keys on component + severity) now costs no model call. A cache-lookup failure falls through
  to the embed rather than failing: the cache is an optimization, and refusing to progress because it could
  not be consulted would let a storage hiccup stall index population. Original report follows. `position_embeddings.text_hash` is
  populated but not yet consulted: a Position revise always re-embeds even when the subject text is unchanged
  (only the stance/rationale label moved). Gate the Ollama embed on a hash mismatch, updating the labels
  in place otherwise — saves an embed call per revise. Surfaced building A4 (2026-08-04).
- [ ] **(LOW, design) Delta-3a — component-level embedding conflates distinct CVEs on one component, so
  contradictory precedents cancel and the AI declines.** `embed.SubjectText` keys on component + severity
  (deliberately excludes the CVE, so it matches by "what it is" — what makes cross-CVE precedent work). Side
  effect: two different vulns on the same component embed near-identically and both retrieve as precedent. When
  their enterprise stances differ, the retrieved set is self-contradictory and `recommend_position` honestly
  returns `insufficient`. Verified 2026-08-05 (AI-P2): cold -> insufficient; one affected precedent -> affected;
  affected + not_affected -> insufficient (tokens 834 -> 996 -> 1081 confirm the precedents were injected). Honest
  under ambiguity, but retrieval PRECISION degrades as history diversifies -> more frequent declines at scale.
  **Refinement:** enrich the embed text with vuln-class / CWE (ties to the R5 "+description" signal) or
  filter/weight retrieved precedent by vuln-similarity, not just component (overlaps G-AI-3). Not a defect.

  **Re-weighted 2026-08-10, and partly answered by exposing retrieval directly.**
  `GET /findings/{id}/similar` (`app.PrecedentService`, the same seam the Gateway grounds on) serves this
  same retrieved set to a human with no model in the path. For that consumer the "defect" inverts: a
  self-contradictory set is not ambiguity to resolve but the single most useful thing to show — *we ruled
  this shape of problem two different ways, here are both*. So the scaling risk is narrower than filed:
  precision decay makes the AI **quieter** (more honest declines) while making the human view **richer**.
  It also finally gives the refinement an evaluation signal — until now retrieval quality was measured only
  against the synthetic labelled corpus in `make e2e-embed`; "was this precedent relevant?" is now an
  answerable question on live data, which is what Δ4's eval loop needs and had no source for.

- [x] **Knowledge consumer inbox (M5 EB-06) — DONE in Group 8.** Built alongside `cmd/knowledge`:
  `internal/knowledge/adapters/inbound` (decode `EvidenceRegistered` → correlation + Subscription),
  `000003_knowledge_inbox` `processed_events` migration + `InboxConsumer`, and `Save`/`RecordMatch` join the
  ctx-tx (both fan out over SBOM components). Proven by the Knowledge inbox integration tests + the
  `tests/pipeline` SBOM→Faultline e2e.
- [x] **(HIGH) Knowledge correlation halts on any SBOM where two components share a CVE. — FIXED 2026-07-30.**
  Fix: store reads join the ambient inbox tx (`querier(ctx)`) so a later component reuses the in-flight card,
  and the faultline INSERT is savepoint-guarded so a genuine cross-process duplicate rolls back and the
  `ErrConcurrent` retry converges; regression `TestInboxCorrelatesSharedCVEWithoutHalt`. Original report:
  `FaultlineService.FoldProposal` reuses an existing card via `GetByCVE`, but `store.GetByCVE` read through
  `s.pool` (committed data) while `Save` joins the inbox unit-of-work transaction. Within one SBOM's
  single-tx, sequential correlation, the first component creates the card for CVE-X (uncommitted); a later
  component's `GetByCVE` can't see it (separate connection) → it INSERTs CVE-X again → `23505` on
  `faultlines_cve_key`. `Save` maps 23505 → `ErrConcurrent` to force a reload, but the failed INSERT has
  already poisoned the shared inbox tx (`25P02`), so the retry's first statement dies and correlation fails
  → **D8 poison-halts the entire Evidence stream** (`cmd/knowledge` reader stops until restart). The
  1-component demo never hit this; a real 542-component SBOM (many Spring modules → shared CVEs) halts on the
  first collision (verified live 2026-07-30, CVE-2026-8384). **Fix:** make reads join the inbox tx so
  `GetByCVE` sees in-flight creates (within-SBOM duplicates then take the update path), AND wrap the faultline
  INSERT in a SAVEPOINT so a genuine cross-process duplicate can `ROLLBACK TO SAVEPOINT` and let the existing
  `ErrConcurrent` retry converge instead of poisoning the outer tx — or dedupe discovered CVEs per SBOM in
  `Correlate` before folding. Add a multi-component-same-CVE correlation test. Plugs into
  `internal/knowledge/adapters/store/store.go` (`GetByCVE`/`load` + `Save`) and/or
  `internal/knowledge/app/correlate.go`. Surfaced 2026-07-30 during the end-to-end deployment.
  See [[feedback-backlog-surfaced-followups]].
- [x] **(HIGH — FIXED 2026-08-05, code green/uncommitted) Governance poison-halts the `knowledge` stream on a
  shared-CVE `faultline_enriched` — `concurrent modification` never converges. — SURFACED 2026-08-05 (from-scratch
  VM bring-up, UC-6).**
  **FIX LANDED:** `querier(ctx)`/`exec(ctx)` seams in `internal/governance/adapters/store/inbox.go`; aggregate
  reads (`load`/`loadComponents`/`loadProposals`/`loadPositions`/`FindingsByFaultline`) + `SetBaseScore` now join
  the ambient inbox tx in `store.go`; regression `TestInboxTwoMutationsOnOneFindingConverge` (fails without the
  fix with `concurrent modification`, passes with it); convention **R3** added to `CONVENTIONS.md`. **VM re-test PASSED 2026-08-05** — the
  live repro (a shared, critical CVE-2021-44228 `not_affected` VEX) produced 0 halts, the governance/knowledge
  cursor advanced (51 -> 1363), and 2 system `not_affected` proposals landed on the R1+R2 findings; UC-6 now
  completes end-to-end. Branch `fix/governance-enrichment-poison-halt` (732f3eb), pushed, PR-ready.
- [x] **(HIGH — FIXED 2026-08-05, code green) Governance base_score not materialized onto findings born on an
  already-enriched Faultline — silent mis-prioritization. — FOUND 2026-08-05 (BUG-3, DN-2 exploration).** `SetBaseScore` runs only on a
  `knowledge.faultline_enriched` event (C6). A Finding opened by `component_matched` for a Faultline that was
  enriched earlier receives no fresh enrichment event, so it is stranded at `base_score = 0` even though the
  card carries a real score. **Evidence:** the CVE-2021-44228 card reads `score 90 / severity critical (OSV)`,
  yet across 4 releases the findings read `90, 90, 0, 0` — the two earliest (born while the card was enriching)
  scored, the two later ones (settled card) did not. `effective_priority = base x blast`, so these findings
  read priority 0 — a critical CVE shown as lowest priority. NOT OSV sparsity (OSV scored it 90) and NOT NVD
  (the score already exists) — a materialization-ordering gap. **Fix options:** (a) `component_matched` carries
  the card's current score so Governance stamps `base_score` in `OpenOrUpdateFinding`; (b) Governance reads the
  card score via the Knowledge read-API at finding-open; (c) Knowledge re-emits a lightweight score on every new
  match. The exact `faultline_enriched` re-emit trigger needs a code trace. Touches
  `internal/governance/app/service.go` (`OpenOrUpdateFinding`) and/or the Knowledge correlation emit path.
  Surfaced chasing DN-2 — the flat prioritization is this gap, not the feeds. **FIX LANDED 2026-08-05:** the
  card's composite score now rides the `knowledge.component_matched` event (Knowledge `domain/event.go` +
  `app/correlate.go` + `adapters/store/store.go` + the `.v1` schema gains an optional `Score`); Governance
  stamps `base_score` in `OpenOrUpdateFinding` (guarded `>0` so a pre-enrichment match never zeroes a live
  score; `SetBaseScore` joins the inbox tx per the BUG-1 fix, so it sees the just-saved Finding). Regressions:
  `TestInboxComponentMatchedStampsBaseScore` (integration) + `TestOpenOrUpdateFinding_StampsBaseScore` (unit),
  both fail without the stamp. `make check-ci` green. **VM re-test PASSED 2026-08-05** — a fresh log4j release's
  findings are born scored (44228=90, 45046=90, 45105=70, others=40) instead of 0; OSV scores, no NVD needed.
  On branch `fix/governance-enrichment-poison-halt` (0f05ff2) with BUG-1, PR #86. See
  [[feedback-backlog-surfaced-followups]].
  Deterministic: on restart the Governance `knowledge`-stream reader re-processes the same
  `knowledge.faultline_enriched` envelope, fails `governance: concurrent modification` 5× (max retries), and
  **D8 poison-halts the whole stream** (envelope `198a567c…`, faultline `42ac1521…` = CVE-2021-45105). Restart
  does **not** help (same cursor, same event); it blocks ALL further knowledge→governance flow (no new SBOM
  yields Findings/Positions) until the cursor is advanced past it or the bug is fixed. **Trigger:** a CVE shared
  across ≥2 releases (so `FindingsByFaultline` returns multiple Findings) **plus** a VEX-applicability enrichment,
  so `ReactToEnrichment` fans `SetBaseScore` (bulk, version-bumping) + a per-Finding optimistic `mutate`
  (enrichment proposal, then `reactToApplicability`'s system not_affected proposal) across several Findings — a
  self-conflict window a single-release faultline never exercises. **Same class as the FIXED Knowledge shared-CVE
  halt above (PR #59) but a different context** (Governance enrichment handler, not Knowledge correlation) — that
  2026-07-30 fix did not cover this path. **ROOT CAUSE CONFIRMED 2026-08-05 (code trace):** `mutate` reads via
  `repo.GetByID` -> `store.load` -> `s.pool` (committed, no tx) while `Save` does `beginOrJoin(ctx)` (joins the
  inbox tx). `ReactToEnrichment` mutates the same Finding twice in one inbox tx (enrichment-proposal path AND
  `reactToApplicability`): the 1st `mutate`'s `Save` bumps `version` V->V+1 uncommitted in the tx, the 2nd
  `mutate`'s `GetByID` reads the pool (still committed V), so `Save ... WHERE version=V` hits 0 rows ->
  `ErrConcurrent`, and every retry re-reads the pool at V -> never converges -> 5 fails -> D8 halt. **SCOPE
  CONFIRMED:** a 542-component `oamp.json` correlation (211 shared-CVE findings, NO VEX) did NOT halt -> the
  trigger needs the applicability's 2nd same-tx write, not a plain shared-CVE flood. **Fix (mirror PR #59):**
  make aggregate reads join the ambient inbox tx (a ctx `querier(ctx)` seam behind
  `load`/`loadProposals`/`loadPositions`/`GetByID`) so the 2nd in-tx read sees the in-flight version and
  converges; alternatively fold the handler's per-Finding writes into one load-apply-save so each Finding mutates
  once. Add a shared-CVE-`faultline_enriched`-with-applicability regression test. Touches
  `internal/governance/app/service.go` (`ReactToEnrichment` / `reactToApplicability` / `SetBaseScore` + `mutate`)
  and the Governance inbound consumer. **Repro:** upload one log4j SBOM to two releases, decide a Position on one,
  upload a not_affected OpenVEX for a shared CVE → the Governance reader halts. See
  [[feedback-backlog-surfaced-followups]].
- [x] **(HIGH) Correlation ran its whole external-I/O fan-out inside the inbox transaction → cluster-wide
  bus stall. — FIXED 2026-08-01.** Root cause of "SBOM uploaded but no CVE entries captured": `InboxConsumer.
  Handle` opened one write transaction, then correlation made a per-component OSV/NVD HTTP call (`VulnsForPackage`)
  *inside* it. On a large SBOM / keyless-NVD-throttled call that transaction stayed open for minutes, pinning the
  **cluster-global** `pg_snapshot_xmin`; the bus reader's gap-free watermark (`insert_xid8 < pg_snapshot_xmin`,
  `reader.go:196`) then could not advance past any newer event and **every** reader on **every** stream starved.
  **Fix:** a `Preparer` seam on the inbox — the consumer runs the read/discovery phase OUTSIDE the transaction
  (`PlanCorrelation`/`PlanVEX` → `PrepareEvidenceRegistered` → `Consumer.Prepare`) and the inbox runs only the
  write closure (`ApplyCorrelation`/`ApplyVEX`) inside the claimed transaction, so it stays short. Honors EB-06
  (claim+writes atomic) and D7 (gap-free); EDR-EVENTBUS-01 D5 refined with the read/write-phase note. Integration
  regressions `TestInboxPreparerRunsReadOutsideTxAndDedups` / `...ReadErrorClaimsNothing` / `...RollsBackOnApplyError`.
  Surfaced 2026-07-31, fixed next session. See [[project-vm-fromscratch-test-20260731]].
  - **Fast-follow (LOW):** Governance's inbound consumer makes a Registry blast-radius HTTP call inside *its*
    inbox tx too (C2) — the same class, far smaller (one localhost call, not N throttled ones). Adopt the same
    `Preparer` seam there for symmetry before it ever matters at scale.
- [x] **(LOW) Feed-health omits the always-on OSV feed.** ✅ **FIXED 2026-08-07.**
  `feed.HealthRecordingSource` wraps the discovery source so every OSV query records success or
  failure under the shared tier taxonomy — so `GET /feeds` evaluates OSV against its tier's staleness
  rules rather than as a special case. It was omitted because health was recorded by the *scheduled*
  workers, which have a poll loop to hang it off; OSV has none, being queried per component at
  correlation time. The consequence: the one feed that runs on **every single upload** was the one feed
  with no health record, so an OSV outage read as "correlation found nothing", indistinguishable from
  "nothing to find". A health-write failure is deliberately swallowed — health is an observation *about*
  the pipeline and must never fail it. Original report follows. `RecordSuccess`/`RecordFailure` are called only by the
  opt-in schedulers (NVD watch, EPSS/KEV sweep), never by OSV correlation — so with only OSV running, the
  feed-health surface (B1) is empty even though the primary feed is healthy. Have correlation stamp OSV health on
  each discovery pass. `internal/knowledge/app` + `adapters/feed`. Surfaced 2026-07-31.
- [ ] **(LOW) Feed-health records only *after* a full poll.** **Premise corrected + partly mitigated
  2026-08-07.** The "~12 min" figure was never real: measured on the VM, a full-window poll completed in
  **under 60 seconds** — because it truncated at 20,000 records (NVD-WATCH-1). With slicing it is now
  genuinely multi-request, so a first poll does take minutes. **What changed:** `themis_feed_polls_total`
  now distinguishes *never polled* from *polled and failed* without waiting for a health row, so the
  "fresh node looks feed-dark" symptom is observable immediately. **What remains:** `GET /feeds` still has
  no row until the first success. **Further corrected 2026-08-07 (D5a):** the window walk this entry
  measured no longer exists — the NVD sweep is per-CVE over the carded set, so a first poll is
  proportional to the estate rather than to the feed's churn, and `folded: N` is logged on every
  sweep including zero. What remains is only the `GET /feeds` empty-until-first-success detail.
  Note that stamping health at poll *start*, as originally proposed, would
  make a broken feed report healthy **sooner** — the right shape is a distinct `pending` state, not an
  early success. Original report follows. The first NVD watch poll is a 120-day
  modified-since query (~12 min), so `nvd` health does not surface until it completes — a fresh node looks
  feed-dark for minutes. Stamp health at poll *start*, or use a smaller first window. `cmd/knowledge` `watchLoop`.
  Surfaced 2026-07-31.
- [x] **(MED) VEX round-trip mismatch — Themis cannot re-ingest its own published OpenVEX.**
  ✅ **FIXED 2026-08-07, together with the bare-UUID product item below — they were one defect seen from
  both ends.** The parser was right and the serializer was wrong: OpenVEX v0.2.0 defines `products` as
  **objects** with `@id`, optionally carrying `subcomponents`. The serializer emitted bare strings, so a
  published document fed back in yielded **zero** statements, silently.
  Fixing only the shape would have been worse than useless: the parser keys a statement's `Package` off the
  product id, so a document naming a release would have parsed cleanly and then matched no component —
  a round-trip that succeeds syntactically and suppresses nothing. The real fix is the semantic one:
  the **product** is the release (now a resolvable IRI, `…/release/<id>`, not a bare UUID) and the
  **subcomponents** are the affected package PURLs. The parser reads subcomponents when present and falls
  back to the product id otherwise, so third-party documents that put a PURL straight in `@id` — which the
  spec permits — still parse.
  Component PURLs now cross the Governance seam (`GET /findings/{id}` already returned them; no API change)
  and are **persisted** on the Publication (migration `000004`, JSONB — a PURL contains `:`, `/`, `@` and
  `%`, leaving no safe delimiter). Persisted rather than re-fetched because the payload must be
  **regenerable** (D1): re-rendering a stored Publication has to reproduce the bytes that were published,
  and the source Finding may have absorbed new components since. Existing rows default to `[]` and
  re-render exactly as they were published.
  **The contract is pinned by a test pair.** `TestParseOpenVEX_RoundTripsThemisOwnOutput` parses the
  serializer's golden bytes verbatim; the bytes are duplicated as a literal rather than imported, because
  Knowledge may not import Communication. Change the emitted shape and the serializer's golden test fails;
  stop reading that shape and the parser's does. Original report follows. The OpenVEX
  *serializer* emits `products` as bare id strings; the VEX-1 *parser* (`adapters/vex/parser.go`
  `openVEXProduct{ ID string json:"@id" }`) expects product **objects** `{"@id": …}`. So a Communication-published
  OpenVEX fed back into Knowledge yields zero applicability statements. Align the two shapes (parser accept both,
  or serializer emit objects). Surfaced 2026-07-31.
- [x] **(MED) VEX-applicability proposal ids embed a PURL (`/`), breaking the accept/reject REST path. — FIXED 2026-08-02 (code green, uncommitted).** A
  feed-/upload-derived suppression proposal is given the deterministic id `vex:<findingID>:<package-purl>`
  (observed: `vex:9da2…:pkg:pypi/setuptools@50.3.2`). The `/` inside the PURL makes
  `POST /findings/{id}/proposals/{proposalId}/accept` return **404 page not found** unless the caller
  percent-encodes the id (`/`→`%2F`) — so the documented §5a suppression-*accept* step fails as written. Real fix:
  keep the id deterministic but path-safe (e.g. `vex:<fid>:<sha1(purl)>`), or accept/reject by proposal id in the
  request **body** instead of the path. Client workaround meanwhile: `printf '%s' "$id" | jq -sRr @uri`.
  `internal/governance/app/service.go` (proposal-id construction) + `api/governance.openapi.yaml`. Surfaced
  2026-08-02 during the VM VEX-suppression test. **FIXED same day:** `reactToApplicability` now builds the id as
  `vex:<findingID>:<packageKey(purl)>` where `packageKey` is a short sha256 hex token — path-safe (colons only,
  no `/`), still deterministic (idempotent dedup), and the human-readable package stays in the proposal rationale.
  INSTALLATION.md §5a reverted to a direct accept (no URL-encode needed); governance app 100%. No API-contract
  change (proposalId is still an opaque path-param string). See [[feedback-backlog-surfaced-followups]].
- [x] **(MED) Release-posture `effective_priority` ignores the governed stance.** ✅ **FIXED 2026-08-06**
  (the `residual_priority` half of GOV-14; the D14 re-evaluation watcher is now tracked separately as
  **GOV-14b** below). `domain.StanceWeight` + `domain.ResidualPriority` implement D14's deterministic
  disposition policy, and `ReleasePosture` now emits **both** numbers: intrinsic `effective_priority`
  (unchanged, stance-independent) and `residual_priority` = effective × stanceWeight — `not_affected` and
  `accepted_risk` 0, `mitigated` 0.5 (`THEMIS_MITIGATED_WEIGHT`), `deferred` 0.9, everything open 1.0. Added
  additively to `PostureEntry` on the v1 spec (no v2). An unrecognized stance weighs **1.0**, failing loud —
  an unknown disposition must keep demanding attention rather than silently suppress a Finding — and an
  out-of-range weight override falls back to the default for the same reason. Tests assert the property that
  motivates keeping two numbers: suppressing a Finding zeroes its residual while leaving its
  `effective_priority` untouched, which is what lets GOV-14b re-surface it on the same evidence.
  Original report follows. `ReleasePosture`
  (`internal/governance/app/read.go:118`) computes `EffectivePriority = base_score × blast_multiplier` with no
  regard to the Finding's accepted Position — so a Finding dispositioned **not_affected** (or otherwise
  suppressed) still reports its full intrinsic priority (observed: CVE-2024-6345 accepted `not_affected`, yet
  `effective_priority: 70`). A human sorting the primary triage view by `effective_priority` sees suppressed
  Findings ranked as high as unaddressed ones — the suppression is visible only in the separate `stance` field.
  Decision needed (likely an EDR-GOVERNANCE point): zero/omit effective_priority for suppressing stances
  (not_affected / false_positive / resolved-fixed), add an explicit `residual_priority`/`suppressed` signal, or
  formally define effective_priority as *intrinsic* and require consumers to filter by stance. Surfaced
  2026-08-02 (VM suppression test). **DECIDED 2026-08-02 → EDR-GOVERNANCE-01 D14** (Option D): keep intrinsic
  `effective_priority` + add `residual_priority` = `effective_priority × stanceWeight(stance)` (not_affected 0,
  accepted_risk 0, mitigated 0.5, deferred 0.9, else 1.0), a read projection; plus a deterministic disposition
  **re-evaluation watcher** (KEV/EPSS-threshold/exploit/reversing-VEX → "disposition-stale" push event, never
  auto-decide) so `accepted_risk → 0` *expires* on signal drift; AI is the optional advisory upgrade. Ready to
  implement as **GOV-14**, **targeted for v0.4.x** (fits the AI-capability expansion; deliberately NOT blocking the
  v0.4.0 greenfield-baseline tag — the decision is durable in EDR-GOVERNANCE-01 D14). See
  [[feedback-backlog-surfaced-followups]] and [[feedback-ai-automation-lens]].
- [x] **(LOW) Intelligence provider HTTP timeout is hardcoded to 60s — too low for larger local models. — FIXED 2026-08-02 (code green, uncommitted).**
  `cmd/intelligence/main.go:75` builds the provider client as `&http.Client{Timeout: 60 * time.Second}` with no
  env override. A grounded `recommend_position` on a 20B local model (cyberpal20b via Ollama) exceeds 60s on
  modest hardware → the provider call aborts with `reason:"provider_error"` → 204 (no proposal); confirmed on the
  VM (two calls, each exactly 59.96s, while a tiny direct prompt answered in 9s). Advisory invariant holds (no
  bad proposal recorded), but the real-model path is unusable without a smaller/faster model. Fix: add a
  `THEMIS_LLM_TIMEOUT` (Go duration, default 60s). Surfaced 2026-08-02 (VM AI-recommend test). **FIXED same day:**
  added `THEMIS_LLM_TIMEOUT` (envDurationDefault, default 60s) threaded into the provider `http.Client` in
  `cmd/intelligence/main.go`; documented in `deploy/node.env.example`. See [[feedback-backlog-surfaced-followups]].
- [x] **(LOW) Wolfi distro unmapped in OSV discovery.** ✅ **FIXED 2026-08-07** — and it was not the
  one-line addition the entry assumed. Wolfi and Chainguard are **rolling** distros: no numbered release,
  so their OSV ecosystems carry no version and their PURLs may omit a version suffix entirely. The parser
  split on `-` and returned "" when it found no version, so adding a `case "wolfi":` to the switch would
  never have been reached. They are matched **before** the version split instead. Original report follows. `osvDistroEcosystem` (`adapters/feed/osv_client.go`) maps
  Rocky/Alma/Red Hat/Debian/Alpine but has no `wolfi` case; the legacy monolith had a `wolfi_osv_url` feed. Add the
  Wolfi ecosystem mapping. Surfaced 2026-08-01 during the legacy→greenfield feed-parity check.
- [x] **(HIGH) OSV distro correlation misses Red Hat/Rocky/Alma CVEs — the ACL ignores OSV's `upstream` field. — FIXED 2026-08-02 (code green, uncommitted).**
  OSV's Red Hat-ecosystem records are advisory-keyed (`id: "RHSA-2023:0835"`, `aliases: null`, `related: null`)
  and carry the addressed CVE(s) in the **`upstream`** field (verified live: `upstream: ["CVE-2022-40897"]`).
  The OSV ACL (`internal/knowledge/adapters/feed/osv.go:49`) resolves the canonical CVE from **only** `rec.ID` +
  `rec.Aliases`, so every Red Hat advisory record is dropped as "no canonical CVE" → an rpm component in a
  RHEL/Rocky/Alma SBOM gets **zero** OSV CVE matches. Confirmed on a from-scratch VM:
  `python-setuptools@39.2.0-5.el9?distro=rhel-9` → OSV returns 20 records, Themis correlates 0, posture empty.
  PyPI/npm/etc. are unaffected (they CVE-key `id`/`aliases`); Debian/Alpine may use a different shape (recheck).
  The Red Hat Hydra *enrichment* feed does NOT compensate — it only folds severity onto ALREADY-carded CVEs, and
  nothing cards them. **Fix:** add an `Upstream []string` (and likely `Related`) field to the OSV record struct
  (`osv.go`) and include them in the `firstCVE(...)` candidate list, with a translate test over a real
  RHSA/`upstream` record. Blocks the RPM fixed-verdict feature end-to-end (the gate never receives a match).
  Surfaced 2026-08-02 (VM fixed-verdict test). **FIXED same day:** `osvRecord` gained an `Upstream []string`
  field; `Translate` now gathers every CVE across id/aliases/upstream via a new `allCVEs` helper (`feed.go`) and
  emits one vuln-facts Proposal **per addressed CVE** (an RHSA fixing N CVEs cards all N, deduped). Regression
  test `TestOSVClient_RedHatAdvisoryUpstreamCVEs`; feed pkg 93.6%; `make check-ci` green. Live re-verify on the
  VM (redeploy + rpm SBOM → the fixed-verdict gate) still pending. See [[feedback-backlog-surfaced-followups]].
- [x] **(LOW) Red Hat vendor-VEX folds the entire product-catalog `not_affected` list per CVE. — FIXED 2026-08-02 (code green, uncommitted).**  One Red Hat
  per-CVE record carries a `not_affected` statement for every RHEL/OpenShift/Ansible product it ships (CVE-2024-6345
  → ~21 statements), so a single 68-card SBOM folded **3,418** applicability Proposals in one sweep. Correct and
  idempotent, and **no over-suppression** — package-precise `Finding.CoversPackage` means none of the RHEL-package
  statements (`python-setuptools`, …) suppress a non-RHEL component (PyPI `setuptools@50.3.2` correctly stayed
  `affected`) — but the stored applicability set is mostly irrelevant intel for a non-RHEL SBOM (volume + noise).
  Consider scoping folded Red Hat applicabilities to ecosystems present in the estate (or cap/summarize) vs.
  accepting them as raw gathered VEX. `internal/knowledge/adapters/feed/redhat_client.go` + `app/enrich_redhat.go`.
  Surfaced 2026-08-02 during the from-scratch VM enrichment test. **FIXED same day:** new `redhatIsPackageLevel`
  filter drops `not_affected` statements for container-image / layered-product package names (a `/` or `:`
  namespace, or a `-container` suffix) — they can never match a package-level SBOM component (proven no
  over-suppression this morning), so folding only the plain-package statements is lossless and cuts the volume.
  feed 93.6%. See [[feedback-backlog-surfaced-followups]].
- [x] **(LOW) `blast_radius_cap` is hardcoded, not configurable. — FIXED 2026-08-01.** `BlastMultiplier` now
  takes the cap as a parameter (`domain.DefaultBlastRadiusCap = 10`), threaded via `THEMIS_BLAST_RADIUS_CAP`
  through `cmd/governance` → `Wire` → `NewReadService` (which normalizes < 2 to the default); a fixed +0.1/customer
  slope clamped to 2.0×. Closes the feed-parity PARTIAL for `intelligence.blast_radius_cap`. Surfaced + fixed
  2026-08-01 (feed-parity check).
- [x] **(MED) Risk score — add the release-scoped blast multiplier per-Finding in Governance.**
  ✅ **CLOSED — shipped as C2 and re-verified 2026-08-07.** `ReadService.ReleasePosture` fetches the
  blast radius ONCE per release and stamps `Multiplier` + `EffectivePriority = BaseScore × mult`
  on every entry (`internal/governance/app/read.go`); the estate graph (C1, PR #75) supplies the
  unique-customer count and the multiplier saturates at `THEMIS_BLAST_RADIUS_CAP`. Fail-safe to
  1.0× when Registry is unreachable. `residual_priority` (D14) then scales by what was decided.
  Original text follows for the reasoning trail. The
  Knowledge Faultline now carries a CVE-intrinsic `priority`/`score` (Layer-1 level + severity+EPSS+KEV
  base, `internal/knowledge/domain/priority.go`). The monolith's composite also multiplied by a blast
  factor (1.0–2.0× off the unique-customer/affected-release count) — a *release-scoped* input that belongs
  on the Governance Finding, not the Faultline. Wire a per-Finding priority = Faultline base × blast, reading
  the Faultline score via the Knowledge read API and the release count via Governance's blast-radius
  projection. Depends on the org asset graph (Product→…→Customer) for the true customer-count multiplier;
  the affected-release count is a usable proxy meanwhile. Surfaced 2026-07-30. See [[feedback-backlog-surfaced-followups]].
- [x] **(LOW) OpenVEX output identifies the product by bare release UUID, with no vulnerable subcomponent.**
  ✅ **FIXED 2026-08-07** — see the VEX round-trip item above; the two were the same defect. `products[].@id`
  is now a resolvable IRI and the correlated component PURLs are emitted as OpenVEX `subcomponents`.
  Original report follows.
  The Communication OpenVEX serializer renders `statements[].products` as the raw `release_id`
  (e.g. `2859e949-…`) and emits no `subcomponents`. A downstream OpenVEX consumer can't resolve a bare UUID,
  and the affected package (e.g. `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`) is not named. Prefer
  a resolvable product identifier and add the correlated component PURL as an OpenVEX `subcomponent`. Plugs
  into the Communication serializer registry (`internal/communication/adapters/.../openvex`). Surfaced
  2026-07-30 verifying the end-to-end deployment. See [[feedback-backlog-surfaced-followups]].
- [x] **(LOW) `cmd/knowledge` default listen port collides with Registry.** ✅ **FIXED 2026-08-07** — the
  default is now `:8085`, matching the `THEMIS_KNOWLEDGE_URL` default every other node already used. Swept
  the three places that documented the workaround (`CLAUDE.md`, `INSTALLATION.md`, `node.env.example`).
  Deployments that set `THEMIS_KNOWLEDGE_ADDR=:8085` explicitly are unaffected. Original report follows. `THEMIS_KNOWLEDGE_ADDR`
  defaults to `:8082` — the same as `cmd/registry` — but the rest of the system addresses Knowledge at
  `:8085` (Intelligence's `THEMIS_KNOWLEDGE_URL` default; `deploy/node.env.example`). Running Registry +
  Knowledge on defaults fails to bind the second one. Fix: change the `cmd/knowledge` default to `:8085`.
  Until then the INSTALLATION.md runbook sets `THEMIS_KNOWLEDGE_ADDR=:8085` explicitly. Plugs into
  `cmd/knowledge/main.go` `loadConfig`. Surfaced 2026-07-30 wiring the end-to-end deployment.
  See [[feedback-backlog-surfaced-followups]].
- [x] **(MED) `cmd/registry` cannot self-migrate into the `evidence` DB it shares with Evidence.**
  ✅ **FIXED 2026-08-07** by the first of the two options the entry named — separating the migration DSN
  from the pool DSN. `migrationDSN()` attaches `x-migrations-table=registry_schema_migrations` to a
  **copy**, so golang-migrate sees it and pgx never does. That separation is the whole fix: the entry
  recorded that the obvious one-DSN approach makes migration succeed and then kills the service
  (`FATAL: unrecognized configuration parameter`), which is exactly the trap a future reader would fall
  into, so a test now asserts the caller's DSN is returned unmutated. `THEMIS_REGISTRY_MIGRATE=1` is safe;
  the manual `psql` load still works and remains the right choice when the service role should not hold DDL
  rights. `INSTALLATION.md` and `CLAUDE.md` updated — both described the limitation as permanent.
  Original report follows.
  The registry-backed SubjectRef reads registry tables in-process over Evidence's pool, so `cmd/registry`
  and `cmd/evidence` must share the `evidence` database. Both `applyMigrations` call `migrate.New` with the
  default `schema_migrations` table, so whichever migrates second reads the other's version and silently
  skips its own `CREATE TABLE`. **The obvious `x-migrations-table` DSN param does NOT fix it** — `cmd/registry`
  reuses the *same* DSN for `pgxpool.New`, and pgx forwards the unknown parameter to Postgres as a startup
  option → `FATAL: unrecognized configuration parameter "x-migrations-table"` on every runtime connection
  (migration succeeds, but the service can't serve; verified live 2026-07-30). The `make e2e-pipeline` proof
  hides all of this by using the **stub** SubjectRef (no registry). **Operational workaround** (now in the
  INSTALLATION.md runbook): load the registry schema directly — `psql -f
  internal/registry/adapters/store/migrations/000001_registry.up.sql` (idempotent) — and run `cmd/registry`
  with a plain DSN and no migrate flag. **Real fix:** separate the migration DSN from the pool DSN (so
  `x-migrations-table` rides only on migrate), or give registry its own DB behind a read-API SubjectRef
  instead of the in-process read. Plugs into `cmd/registry/main.go` (+ `cmd/evidence/main.go`).
  Surfaced 2026-07-30 wiring the end-to-end deployment. See [[feedback-backlog-surfaced-followups]].
- [x] **(LOW) Consolidate the inbox ctx-tx unit-of-work into a shared `platform/uow` helper.** The
  `txCtxKey` / `withTx` / `txFromCtx` + `InboxConsumer` are duplicated per consuming context (Governance,
  Communication, later Knowledge). It is business-agnostic infra and could collapse into one platform package
  (a third after `observability` + `eventbus`), trading a little context independence for less duplication.
  **✅ DECIDED 2026-08-07: NOT extracting it, and closing the entry.** The revisit trigger fired —
  three consumers now exist (Governance, Communication, Knowledge) — so the question was actually
  asked rather than deferred again. The answer did not change, and the reason is worth recording so
  a fourth consumer does not reopen it by reflex.
  **What is duplicated is ~8–10 lines per context:** a context key, `withTx`, `txFromCtx`. It is
  plumbing, not policy — there is no rule in it that could drift between copies, which is the usual
  reason duplication becomes dangerous.
  **What extraction would cost:** a fourth platform package that three bounded contexts must agree
  on forever. Platform packages are deliberately restricted (only adapters + the composition root
  may import them) precisely because they are the one place contexts couple, and a transaction
  abstraction is a poor thing to couple on — the moment one context needs a savepoint, a different
  isolation level, or a nested unit of work, the shared helper either grows options for everyone or
  gets forked back.
  **Trivial duplication is cheaper than coupling.** Revisit only if the copies start to DIVERGE in
  behaviour rather than merely to exist.
- [~] **Knowledge — real feed-fetch HTTP clients (PARTIALLY DONE).** OSV query-by-package (incl. distro
  ecosystems — separate PR) and the **NVD modified-since watch** are now wired: `cmd/knowledge` builds
  `feed.NewNVDClient` behind a `feed.RelevanceFilteredSource` (D5 relevance bound — only CVEs that already
  have a card are enriched, never a full feed mirror) into the `WatchService`, scheduled off
  `THEMIS_NVD_ENABLED`/`THEMIS_NVD_POLL_INTERVAL`. **EPSS/KEV/ExploitDB** are now wired too: a bulk
  `feed.ExploitSignalClient` (EPSS gzip-CSV + CISA KEV JSON + ExploitDB CSV) feeds an
  `app.SignalEnrichmentService` that folds exploit-signal Proposals onto already-carded CVEs (same D5
  relevance bound), scheduled off `THEMIS_EPSSKEV_ENABLED`/`THEMIS_EPSSKEV_POLL_INTERVAL` (default 24h). The
  bulk client bypasses the pre-existing per-record `epsskev.go`/`exploitdb.go` ACLs (a tidy-up follow-up: fold
  them out or align shapes). **Still open:** the **vendor-VEX / Red Hat CSAF** ACLs remain unwired (applicability
  overlay); and the NVD by-CVE backfill (below).
- [x] **Knowledge — NVD by-CVE backfill (targeted enrichment).** ✅ **DONE 2026-08-07** as
  **EDR-KNOWLEDGE-01 D5a** — and it did not merely *add* a by-CVE path, it **replaced** the
  modified-since watch entirely (see NVD-WATCH-1). Original report follows. The modified-since watch only covers CVEs
  changed within NVD's 120-day window; a card whose CVE fell out of that window (or was created after the
  last relevant modification) never gets NVD's authoritative CVSS/severity. Add a `FetchByCVEID` path and a
  targeted per-card enrichment trigger (e.g. on `FaultlineCreated`, or a backfill pass over cards missing an
  NVD proposal). Plugs into `internal/knowledge/adapters/feed` + a new backfill worker. Surfaced 2026-07-30.

- [x] **Knowledge — CVSS v4.0 in feed ACLs + Reconcile.** ✅ **CLOSED 2026-08-07 for OSV; NVD was
  already done.** NVD parses `cvssMetricV40` (the v0.3.x D-NVD-2 fix, carried forward). The real gap
  was OSV, and it was TWO defects in one line:
  1. `Severity[0]` let whichever vector the feed ordered FIRST decide the enterprise's severity. OSV
     lists CVSS_V2, CVSS_V3 and CVSS_V4 side by side, so a **v2 vector could silently outrank a
     v3.1 one** — a downgrade of the evidence with no trace. `value.PreferredCVSSVector` now ranks
     them by what this system can DO with them (v3.1 → v3.0 → v4.0 → v2).
  2. The numeric score came only from OSV's database-specific extension, so a record with a vector
     and no extension landed `severity=unknown` / `score=0` — and unknown scores zero, which sorts a
     real vulnerability to the BOTTOM of a triage queue. `value.BaseScoreFromVector` derives the
     **v3.x** base score from the vector per the published formula; a source's own published score
     still wins, because deriving over it would replace a source's verdict with our arithmetic.
  **A third defect fell out of it:** `CVSSVectorVersion` treated ANY prefix-less non-empty string as
  a v2 vector, so `"garbage"` was selected as a vector. Same shape as RANGE-PARSE-1 — a recogniser
  loose enough to accept anything turns unparseable input into a value the system acts on. It now
  requires v2's `Au:` discriminator.
  **Still open:** v4.0 SCORING. A v4.0-only record keeps its vector and scores 0 rather than having
  a number invented for it; the v4 formula is materially more complex than v3's and deserves its own
  change. Ranking v4 below v3 in `PreferredCVSSVector` is a CAPABILITY ordering that should be
  revisited when it lands. The feed ACLs and `Reconcile` headline-severity
  selection must parse **CVSS 4.0** (NVD `cvssMetricV40`; OSV v4.0 vectors), else recent CVEs land
  `severity=unknown` / `risk=0` — the go-forward equivalent of the v0.3.x **D-NVD-2** gap (root cause + fix in
  **Part 2 — D-NVD-2** below). Fold v4.0 into the source precedence when the real feed clients
  (above) land; prefer `v3.1 → v3.0 → v4.0 → v2`, Primary over Secondary.

- [ ] **Governance — structured AI-proposal fields.** Δ1 records an AI recommendation via existing fields
  (actor `{ai, "recommend_position@v1"}` = provenance; confidence + reasoning in the rationale). The additive
  follow-up gives `GovernanceProposal` first-class **confidence / evidence-refs / source (capability+version)**
  columns (nullable for non-AI proposals) — it ripples through domain + store schema + read API, hence
  deferred. Needed before the confidence-threshold auto-accept policy (EDR-INTELLIGENCE-01 D8).

- [x] **Governance — accepted-risk expiry/timer worker.** ✅ **CLOSED 2026-08-07, folded into the
  disposition sweep rather than built as a second worker.**
  The "accepted-risk-until field" this entry asked for is `PositionInputs.ReviewBy` (migration
  `000009`), settable on accept via `review_by` on the decision request. `domain.Expired` is the
  TIME-based sibling of `DetectDispositionDrift`, and `watchDispositions` now fires on either.
  **Why not a separate timer worker:** the two triggers answer different questions — drift asks
  "has the world changed?", expiry asks "has anyone looked at this lately?" — but they produce the
  SAME outcome, a `disposition_stale` fact that re-opens the question without touching the
  Position. Two workers emitting one event type would have meant two places to keep that guarantee.
  **Zero means no date was AGREED, not "never expires" and not "expired in year 1".** Inventing a
  deadline the decider did not set would re-surface every suppression on the next enrichment and
  train people to ignore the signal.
  **Drift wins the wording when both fire:** "the CVE entered KEV" is a stronger call to action than
  "your review date passed", and a re-surfacing gets read once.

- [ ] **Communication — concrete delivery channels.** Real **SMTP / Slack / webhook** push adapters + the
  **routing rules / digest / redaction** machinery (reuse the PoC `notify`: `routing.go`, `digest.go`,
  `retry.go`, `redact.go`, `smtp.go`, `teams.go`). Today a **logging deliverer + pass-through redactor** ship
  behind the `Deliverer` / `Redactor` ports; the exactly-once/idempotent/outcome-recorded mechanics are done.
  Plugs into `internal/communication/adapters/delivery`.

- [x] **Communication — delegated auto-publish policy.**
  ✅ **DECIDED 2026-08-07: NOT NOW, and the reason is worth keeping.** Publishing is the one action
  in Themis that is **outward-facing and irreversible** — a CycloneDX-VEX or CSAF document sent to a
  customer cannot be recalled, and a wrong `not_affected` published under the enterprise's name is a
  materially different mistake from a wrong one held internally. Every other automatic step here
  (auto-accept, correlation, enrichment) is internal and revisable.
  Adding a delegated trigger is genuinely a small change — an alternate trigger source beside the
  human one, no model change (D4). What is missing is not the code but a **reason**: no use case has
  asked for it, so the policy would be designed against an imagined operator. The stricter-than-
  CON-0015 initial scope stands until a real workflow needs it, at which point the trigger, its
  conditions and its audit trail can be designed together instead of guessed.
  **Revisit when:** an operator asks to stop hand-triggering a class of publication, or a
  contractual SLA requires publication within a window a human cannot guarantee. Currently **all** artifact creation is
  human-triggered (a deliberate stricter-than-CON-0015 initial scope). A Governance-defined delegated
  auto-publish policy becomes an alternate **trigger source** alongside the human trigger — no model change.
  (EDR-COMMUNICATION-01 D4 "for the time being".)

- [ ] **All contexts — store fault-injection coverage.** _(Consciously DEFERRED 2026-08-07, with the
  trade stated.)_ The work is a mechanical refactor across five contexts — replace each `Store`'s
  concrete `*pgxpool.Pool` field with an interface satisfying the existing `rowQuerier` + `execer`
  plus `Begin`, then inject a wrapper that fails the Nth call. The abstraction is already half
  present (`querier()` / `exec()` route through interfaces today), so the change is small per store
  and repeated five times.
  **Why deferred rather than done:** the uncovered lines are `if err != nil { return err }` branches
  whose happy path the embedded-Postgres integration tests already prove. Nothing about them is
  believed-but-unverified in the way TRUST-9 was — and TRUST-9's demonstration, written in the same
  session, uncovered a **P1 silent-suppression defect** (RANGE-PARSE-1). Effort spent demonstrating
  BEHAVIOUR found a real bug; effort spent covering error returns would not have.
  **When to do it:** when a store gains logic in an error path (a retry, a fallback, a
  compensating write) — at that point the branch stops being a passthrough and starts being a
  decision. **The 80% tier stays until then, deliberately, not by neglect.** Lift the aggregate stores
  (evidence/knowledge/governance/communication ~80–83%, registry 89%) toward 90%+ by covering the DB-error
  branches via an **injectable `pgxpool` interface** (fault injection). Behavior is already proven by the
  embedded-Postgres integration tests; only error-path lines remain. The store tier is intentionally set to
  80% until this lands.

- [x] **KN-SCAN-1 — scanner-report ingestion is UNWIRED: Evidence accepts the upload (201) and
  Knowledge silently no-ops it.** ✅ **CLOSED 2026-08-13, same day** (phase3-knowledge-staying-current):
  `evidence.ScannerSource` (document read + ACL per finding, skip-and-count), the curated report
  schema finally carries the component each finding names, `ScannerReportService` gained the D7
  plan/apply split, the coordinator dispatches the kind, and wiring connects it. Scanner matches
  now stamp Score/Priority/Fixes/ClaimClass like the discovery path (the old Ingest omitted them). _(Found 2026-08-13, same Q&A as KN-RECOR-1 — checking whether
  the "SBOM once + periodic scan reports" operating model works today.)_ The pieces exist:
  `domain.KindScannerReport` (Evidence accepts the kind), `app.ScannerReportService` (built,
  tested — folds proposals AND records matches so Findings open), and the scanner feed ACL
  (`adapters/feed/scanner.go`). What is missing is the seam between them: no adapter implements
  `app.ScannerReportSource` (an Evidence read-API client for the `scanner-report` kind — named a
  "documented prerequisite" in scanner.go's own comment), the coordinator dispatches the kind to
  a nil apply ("handled elsewhere" — there is no elsewhere), and nothing wires the service.
  **Why it matters:** the upload SUCCEEDS — an operator on a static estate who re-scans an image
  and uploads the report reasonably believes the new CVEs are in; nothing surfaces that they are
  not. The "wiring is no gate" class (parity audit, A1's shape) in the go-forward tree.
  **Fix shape:** an Evidence document-read client for the kind (the `…/document` endpoint
  exists — EDR-VEX-01 D1 built it for VEX) + the scanner ACL behind `ScannerReportSource` + a
  `scanner-report` branch in `Coordinator.PrepareEvidenceRegistered` (read/plan outside the tx,
  apply inside — the D7 split, same as sbom/vex) + wiring. Scanner trust stays Asserted — a
  scanner never sets truth. **Dep:** none. **Scope:** MEDIUM. **Priority: MED-HIGH** (silent
  acceptance; and with [[KN-RECOR-1]] open it is the ONLY intended discovery path for static
  estates — both halves of the static-estate story are currently missing).

- [x] **KN-RECOR-1 — no post-upload re-discovery: a CVE published AFTER a release's last upload is
  invisible until the next upload.** ✅ **CLOSED 2026-08-13, same day** (phase3-knowledge-staying-current):
  the `correlated_releases` ledger (migration 000006, stamped inside ApplyCorrelation's unit of
  work — latest evidence wins, zero-item plans still stamp) + `RediscoveryService` re-running the
  EXISTING idempotent correlation for the stalest releases + a default-ON loop
  (`THEMIS_REDISCOVERY_ENABLED=0` to disable, `_INTERVAL` 1h / `_STALE_AFTER` 24h / `_LIMIT` 3).
  The cross-release consequence closes with it: a CVE carded by one release's upload reaches its
  sibling releases on their next sweep. _(Surfaced in a Q&A walkthrough, 2026-08-13.)_ Discovery
  (OSV always-on + NVD A2 when enabled) runs only at CORRELATION time — an upload-driven
  snapshot. The enrichment sweeps are deliberately card-bounded (D5: enrich existing cards,
  never mirror a feed), so they keep KNOWN CVEs fresh forever but can never card a new one.
  Verified: every scheduled loop in `cmd/knowledge` (relay, reattribute, nvd-backfill, signals,
  redhat, alpine, vexfeed, reader) is enrichment-shaped, and the reattribute sweep explicitly
  refuses to become "an undeclared discovery pass". Consequence: a CI-driven estate (frequent
  uploads) is fine; a static/appliance estate is blind to new CVEs between uploads — for a
  monthly release cadence, up to a month.
  **Mitigations that exist today:** the next SBOM upload (content-addressed — needs changed
  bytes, which a new build has) or a scanner-report upload, both of which record matches.
  **Fix shape (design-first — an EDR-KNOWLEDGE-01 addendum):** a bounded RE-DISCOVERY sweep in
  the BackfillService mold — per distinct inventoried component, staleness-queued, capped per
  run, reusing the existing `PackageVulnSource` fan-out and the correlation apply path so new
  cards get MATCHES (a card without a match opens no Finding and is invisible in posture).
  D5-compliant by construction: per-component queries against the estate, never a feed mirror.
  Distinct from [[G-AI-1]] (on-demand gathering for CVEs the feeds have not ingested, AI-asked,
  Δ4-gated) — this is scheduled, feed-known, and needs no AI. **Dep:** none. **Scope:** MEDIUM.
  **Priority: MED** (HIGH for static estates; the current VM estate uploads rarely, so it is
  live there).

- [ ] **G-AI-1 — On-demand "fresh-CVE" gathering: the AI asks, the feeds gather.**
  **✅ HALF (a) LANDED 2026-08-23 (T5 chain): the on-demand gather exists.**
  `POST /faultlines/gather {cve}` on Knowledge consults the wired per-CVE sources (NVD today,
  via the same `VulnsForCVE` + fold path as the backfill sweep) and folds ordinary source
  Proposals — same ACL, same precedence, "Gathering Is Not Knowing" intact. Needs no enable
  flag: the scheduled watch's opt-in guards SILENT outbound calls, and an authenticated
  write-scoped POST is never silent. Withdrawn CVEs retire the card; found-nothing is an honest
  200. **Half (b) — the AI automatically emitting "need more data on CVE-X" and pushing here —
  remains the Δ4-class push seam** **✅ THE PUSH SEAM NOW EXISTS (Δ4b, 2026-08-25): `readapi.ProposalWriter` raises advisory `ai` proposals to Governance; the AI-emits-need-more-data path can reuse the same outbound-write seam to POST a gather request to Knowledge as a follow-on.**; until then the loop is a human/script reading an
  `insufficient` whose `decline_class=thin_grounding` detail says what is missing, and POSTing. _(Gap surfaced in the
  M4 Δ2 grill, 2026-07-24.)_ When `recommend_position` runs against a CVE our feeds have **not yet ingested**,
  there is no _Information_ to reason over — and without an affected range even the version-range step can't
  run — so the capability returns a safe **"insufficient data — no recommendation"** (the Δ2 decision, Option
  A). The interesting gap: **today there is no on-demand path to go fetch a brand-new CVE's facts.** Go-forward
  design (from the grill): the AI may emit a structured **"need more data on CVE-X"** flag — itself
  _Information_, never a write — that the **Knowledge/feeds side** consumes to gather (a web-intel **crawler =
  a new feed source**, producing source Proposals like any other feed). This keeps the **Information vs
  Enterprise Knowledge** boundary intact (**Domain Invariant 3 — "Gathering Is Not Knowing"**,
  `Book-II-Domain-Chapter-02`): the AI only _asks_; only Knowledge reconciliation (or a feed) turns gathered
  Information into the CVE card. **Why open:** needs (a) a crawler / on-demand feed source on the Knowledge
  side (feeds are scheduled OSV/NVD _pull_ today — no on-demand or web-intel source) and (b) the Intelligence
  "need-more-data" capability output + its push seam (Δ4-class). **Where it plugs in:** `internal/knowledge/
  adapters/feed` (new on-demand/crawler source behind the existing Proposal machinery) + an Intelligence
  capability output + a Knowledge proposal-intake push. **Dep:** builds on the Δ2 two-step `recommend_position`
  together with the M7 feed ACL/Proposal machinery; the AI push seam is the same one deferred to Δ4. **Scope:** design in
  the Δ2 EDR addendum, build Δ3+.

- [ ] **G-AI-2 — "Can't determine" is a first-class improvement signal, not just a safe answer.** _(Gap
  surfaced in the M4 Δ2 grill, 2026-07-24.)_ Per the **deterministic-first + honest** principle, when neither
  the rules nor the LLM can settle a question the capability returns an explicit **"can't determine — no
  recommendation"** (a valid outcome, never an error). Δ2 only _returns_ it. The gap: this honest non-answer
  is a **high-value signal** that later stages should act on — (a) **track it as a metric** (can't-determine
  rate per capability / model / CVE class), (b) **escalate** (retry with a larger or different model, or a
  stronger engine — the _upgrade_ counterpart to D4's degrade-not-fail model routing), and (c) **feed the
  evaluation loop** (INT-0065 / D9) so a capability that says "can't tell" too often gets its model/prompt
  version tuned. None of that machinery exists yet (Δ1/Δ2 are stateless — no metrics store, no eval loop, no
  multi-model escalation). **Why open:** needs OTel metrics (§D), the Δ4 evaluation / LLMOps plane, and
  model-escalation routing (D6 / INT-0062). **Where it plugs in:** Intelligence telemetry (OTel metrics) + the
  eval loop + the model router. **Dep:** builds on the Δ2 "can't determine" outcome; needs §D observability
  metrics together with the Δ4 eval/LLMOps plane. **Scope:** define the outcome in Δ2; build the
  metric/escalation/feedback in Δ3–Δ4.
  **✅ (a) LANDED 2026-08-07 — the can't-determine RATE is now observable.**
  `themis_ai_invocations_total{capability,reason,produced}` is recorded on every invocation, so
  `reason="insufficient"` over total is a live query with no new machinery.
  **✅ (b) ESCALATION LANDED 2026-08-13 (phase3-intelligence-router):** an honest `insufficient`
  on a Decision capability retries ONCE on `THEMIS_INTELLIGENCE_MODEL_ESCALATION` (when set and
  distinct and the budget still admits); the escalated answer stands, and an escalated decline
  carries `Tier=escalation` in telemetry — "the bigger model could not tell either" versus "we
  never tried" is now observable. Deliberately narrow: never fires on schema/business failures
  (contract problems — escalating would mask which lever to pull, the distinction this very
  entry's (c) needs), never on timeouts, never while degraded, never for Information
  capabilities. **✅ (c)'s CLASSIFICATION half LANDED 2026-08-23 (T5 chain):** every honest
  insufficient now carries a `DeclineClass` — `thin_grounding` (the backend knew: AI-204-2's
  taxonomy) vs `model_undetermined` (grounding fine, model couldn't) — in the journal
  (`decline_class`) and as `themis_ai_declines_total{capability,class,tier}`. "The model can't
  reason" and "there was nothing to reason about" are now separable rates with separate owners.
  **(c)'s TUNING half** (the loop that acts on those rates — prompt/model versioning) remains
  open and is Δ4's eval-harness work. **✅ THE HARNESS LANDED 2026-08-24 (Δ4a): `make eval-llm` / `cmd/intelligence-eval` replays a curated golden set and scores by (capability, prompt_version, model). The ACTING half — a loop that auto-tunes — stays deferred (promotion is human-gated by decision, D-Δ4a-4); the harness gives a human the numbers to tune by.**

- [x] **AI-TEL-1 — `Outcome.TokensUsed` reports only the LAST attempt's tokens; a multi-attempt
  invocation under-reports its cost in telemetry.** ✅ **CLOSED 2026-08-23 (T4 delivery).**
  Accumulates across attempts AND tiers; the proposal metadata's figure becomes the invocation
  TOTAL (the honest number for both, as filed). Regression: `TestInvokeTokensAccumulateAcrossAttempts`. **LIVE-VERIFIED 2026-08-24 (VM):** journal `tokens:3212` = invocation total on a real CyberPal compare. _(Surfaced 2026-08-13 during the router's live
  escalation test.)_ The Gateway overwrites `oc.TokensUsed` per attempt, so an invocation with a
  schema retry or an escalation logs only the final call's tokens (measured: an escalated
  invocation whose two calls cost ~1900 + 2116 tokens logged `tokens:2116`). The BUDGET is
  unaffected — it debits every attempt — so this is a telemetry/provenance imprecision, not a
  spend leak. **Fix shape:** accumulate (`oc.TokensUsed += res.TokensUsed`); note the proposal
  metadata's `TokensUsed` inherits the same field, so its meaning changes from "final call" to
  "invocation total" — the total is the honest number for both. **Dep:** none. **Scope:** SMALL.
  **Priority: LOW.**

- [x] **AI-204-2 — an honest decline could state its DETERMINISTIC sub-cause when the backend already
  knows it.** ✅ **CLOSED 2026-08-23 (T4 delivery, exactly the filed shape).**
  `domain.GroundingThinness` names the deterministic why (all-scope components — zero carriers —
  or zero version evidence) computed BEFORE the LLM step and stamped into `Outcome.Detail` on the
  insufficient exits only; the 204 header stays opaque (AI-204-1's invariant). The readapi client
  now decodes `claim_class` (it was on the wire and dropped). Feeds G-AI-2c's decline taxonomy. _(Observed live 2026-08-12 diagnosing CVE-2026-42496; filed 2026-08-13.)_ That decline
  was fully explainable BEFORE the model ran: all 37 matched components were `claim_class=scope`
  (zero carriers), so the grounding could not support a stance — a fact the deterministic backend
  holds, no model needed. Today the 204's `X-Themis-AI-Reason: insufficient` and the journal's
  `llm:insufficient` say only that the model declined; an operator re-derives the why by hand (the
  2026-08-12 session took a three-part diagnostic to get there). **Fix shape:** when the projection
  is deterministically thin — zero carrier components, or no attributed fixes and no ranges — stamp
  that fact into `Outcome.Detail` (telemetry only; the 204 stays opaque per AI-204-1's invariant)
  BEFORE the LLM step, so a decline's journal line carries "grounding: 37 components all
  scope-class" alongside `llm:insufficient`. Composes with G-AI-2c: the eval loop needs exactly
  this signal to tell "model can't reason" from "grounding had nothing to reason about".
  **Dep:** none. **Scope:** SMALL-MEDIUM. **Priority: LOW-MED.**

- [x] **AI-CMP-1 — `compare_releases@v1`: an Information capability narrating the comparison read
  (filed 2026-08-21 with the tier roadmap, EDR-ENHANCE-T5).** MED as the T5 entry point. ✅ **CLOSED 2026-08-23 (first T5/R1 delivery; EDR-INTELLIGENCE-01 realization note).** Shipped exactly as filed: ordered two-release Selection, `NeedReleaseComparison` grounding received verbatim, buckets capped 15/bucket with counted omissions, guard refusals → `no_grounding`, empty diff → `rule:empty-comparison` (zero tokens), Grounding Verification the only gate; GUI "Ask the advisor" on the Compare tab (read-scope, statelessPosts). **LIVE-VERIFIED 2026-08-24 (VM):** grounded 200 vs CyberPal via curl + GUI; e2e-llm compare_releases PASS on a real-delta fixture (fixed/new/persisting all read correctly); truncation-honesty disclosed ("worst 15 shown, 95 omitted"). IDEA-1's
  consumer 3, unblocked by EDR-GOVERNANCE-01 D16: the deterministic
  `GET /releases/{id}/compare/{candidate}` now exists, so the capability is an overlay — the model
  is handed the `{fixed,new,persisting}` buckets verbatim and narrates what the fix achieved,
  missed, and what to do next, citing only rows it was given (the Grounding Verification gate
  applies unchanged). Information class (T7): ephemeral, proposes no stance, nothing reaches
  Governance — the worst outcome is a human disagreeing with prose. 204 semantics per
  AI-204-1/AI-204-2. **Dep:** none (D16 shipped in v0.4.2); composes with [[G-AI-3]], which reuses
  the same delta machinery for precedent ranking. **Scope:** MEDIUM.
- [x] **G-AI-3 — Rank precedent decisions by release-to-release delta.** ✅ **CLOSED 2026-08-23
  (EDR-INTELLIGENCE-01 realization note; second T5/R1 delivery).** **LIVE-VERIFIED 2026-08-24 (VM):** /similar returned 4 baseline precedents at release_overlap 1.0 — correct, the two releases share 100% of their open surface (0 fixed/0 new/110 persisting). The remainder shipped on the
  D16 comparison read: posture-overlap delta (`persisting/(fixed+new+persisting)`), weight
  `0.5+0.5×overlap`, ranked inside the ONE PrecedentService seam (Gateway grounding and
  `/findings/{id}/similar` re-rank identically), overlap exposed in the prompt and as additive
  `release_overlap` on the wire; unknown/failed comparisons leave precedent unweighted.
  Original filing kept below. _(Gap surfaced in the M4 Δ2 grill,
  2026-07-24.)_ Δ2 grounds `recommend_position` with our own past Enterprise Positions on the **same CVE** from
  other releases, handed to the AI **clearly labeled** (which release, component version, decision + rationale)
  so the AI and the human weigh relevance themselves — a cheap on-demand read-API pull, done only when
  reasoning reaches the LLM step. The gap: **automatically rank or filter that precedent by how close each past
  release is to the one under judgment** (the release-to-release _delta_) — a decision on a near-identical
  release (same component version + usage) should carry weight; one on a very different release should be
  down-weighted or dropped, not blindly trusted. This needs real **release-comparison machinery** (component /
  usage deltas across Releases) that does not exist yet, and it overlaps the semantic "similar findings"
  retrieval (RAG, Δ3). **✅ Δ3a delivered the semantic-retrieval half** (RC-1, 2026-08-04): `recommend_position`
  now embeds the Finding and retrieves cosine-similar past Positions — possibly a *different* CVE on the same
  component — cosine-ranked into the grounding (`internal/intelligence/adapters/{index,engine}`; plan is
  `[Rule → Knowledge → LLM]`). **What remains:** rank/weight that precedent by the **release-to-release delta**
  (down-weight a decision on a very different release), which still needs a Registry/Evidence
  release-comparison read-API that does not exist. **Where it plugs in:** the Knowledge engine's ranking, given
  a release-diff signal. **Scope:** cosine-similarity ranking is done; delta-aware ranking is the open remainder.
  *(The missing machinery is captured as **IDEA-1** in [`backlog-ideas/ideas.md`](backlog-ideas/ideas.md),
  2026-08-14 — the operator fix-verification use case joined this AI one as its second consumer.)*

- [ ] **G-AI-4 — Budget enforcement policy deferred; Δ2 measures only.**
  **PARTIALLY CLOSED 2026-08-09 — the per-capability window ceiling is enforced.** `app.Budget`
  (fixed window, anchored to first use), pre-checked immediately before the provider call and
  debited with the provider's ACTUAL token count. Every attempt debits, including one whose output
  fails schema validation — a retry consumes the model exactly as a success does, and a ledger that
  counted only successes would let a schema-thrashing capability spend without limit.
  Config: `THEMIS_INTELLIGENCE_BUDGET_TOKENS` / `_WINDOW`; unset = unlimited, and that default is
  load-bearing (a budget switched on by accident is indistinguishable downstream from an AI outage).
  Exhaustion is its own reason, `budget_exhausted`, never `insufficient`.
  **✅ DEGRADE-NOT-FAIL LANDED 2026-08-13 (phase3-intelligence-router):** the downgrade has
  somewhere to go — `THEMIS_INTELLIGENCE_MODEL_ECONOMY`. Below the low-water mark
  (`THEMIS_INTELLIGENCE_BUDGET_DEGRADE_PCT`, default 0.20 of the window ceiling) invocations
  route to the smaller model instead of refusing; full exhaustion still answers
  `budget_exhausted`, because the economy model's tokens are real tokens too. A degraded
  invocation never escalates.
  **✅ PER-RUN CEILING LANDED 2026-08-23 (T5 chain):** `THEMIS_INTELLIGENCE_MAX_RUN_TOKENS` —
  once ONE invocation's accumulated spend (retries + escalation, honest since AI-TEL-1) reaches
  it, no further attempt runs (`budget_exhausted`, `guard:run-budget`); escalation respects it
  too. Unset = unlimited, same load-bearing default as the window.
  **Still open, both blocked on planes that do not exist yet:** the autonomous pool (needs Δ4
  autonomy — there is nothing to pool for) and the global enterprise ceiling (with ONE
  Intelligence node the window ceiling IS the global ceiling; the scope becomes real when a
  second AI node exists).
 _(Gap surfaced in the M4 Δ2 grill,
  2026-07-24.)_ Δ2 builds the **meter** (per-call time / input-size / token count recorded via telemetry) plus
  one **runaway guard** (a per-request timeout + a cap on prompt input size) — nothing more. The actual
  **budget-enforcement logic** — the four EDR scopes (per-run / per-context / autonomous-pool / global,
  D4/INT-0064), the _degrade-not-fail_ model-downgrade behavior (D4/INT-0062), and where the thresholds sit —
  is **postponed as a later decision**, because Δ2 runs a **free local model** where hard caps are not yet
  meaningful. The point of Δ2 is that the **metrics are ready** so the enforcement decision has real data the
  moment paid/cloud models arrive. **Why open:** enforcement only bites with paid providers (Δ3+); needs the
  operational store + Governance-owned budget policy config (D4) that the stateless Δ2 gateway does not have.
  **Where it plugs in:** the Intelligence pre-invocation admission step (the "gate") together with telemetry
  (§D metrics) and config (R2). **Dep:** builds on the Δ2 meter + runaway guard; needs paid-provider routing
  together with the operational store and budget-policy config. **Scope:** meter + runaway guard in Δ2; full
  budget enforcement/policy Δ3+.

- [ ] **G-AI-5 — Data-classification / provider-clearance admission deferred; Δ2 is a minimal local-only
  gate.** **RE-EVALUATED 2026-08-23 (T5 chain): the deferral is CONFIRMED CORRECT and now
  GUARDED.** No non-local provider exists, so classification still has no routing effect —
  building the machinery now would be dead code misrepresenting a live control. What changed:
  `TestEveryShippedCapabilityIsLocalOnly` is the R4-style tripwire — the moment any capability
  declares a non-local/non-internal route, the build fails and forces this decision BEFORE the
  route exists. This item graduates to real work when a cloud/paid provider is proposed.** _(Gap surfaced in the M4 Δ2 grill, 2026-07-24.)_ Δ2's pre-invocation gate is deliberately minimal
  because the model is **local / on-prem — nothing leaves the building**, so INT-0069's strongest rule ("the
  most sensitive data stays local-only") is satisfied by default. Δ2 does: (1) **authorize** the
  caller/capability request (authn/authz), (2) **scrub secrets / PII** from both the prompt and the telemetry
  (the same redaction discipline as Communication), and (3) **hard-mark the path "local-only"** so nothing can
  accidentally reach a cloud provider. The gap: the **full data-classification → provider-clearance machinery**
  (D10 / INT-0069) — classify each assembled context by sensitivity, route each class only to providers cleared
  for it, honor regulatory / residency limits, and output-filter provider responses before validation — is
  **deferred to when cloud/paid providers exist** (Δ3+), because classification only changes routing once there
  is a non-local destination. **Why open:** no cloud provider in Δ2 → classification has no routing effect yet;
  needs provider-clearance policy config (Governance-owned) together with multiple providers. **Where it plugs
  in:** the Intelligence pre-invocation admission step (the same "gate" as G-AI-4 budget) together with
  provider-clearance config (R2) and the model router (D6). **Dep:** builds on the Δ2 minimal gate; needs
  multiple providers together with clearance policy. **Scope:** minimal local-only gate in Δ2; full
  classification / clearance Δ3+.

- [x] **G-AI-6 — `NeedFinding` is declared but never consulted; the grounding root is hardcoded.** ✅ **CLOSED 2026-08-06** (phase3-trust-model group 9): `app.AssembleContext` is deleted outright — the runtime receives a Domain Projection and gathers nothing (T10), so the half-wired `ContextNeed` mechanism it lived in is gone with it. _(Found in
  the capability-surface audit, 2026-08-06.)_ `domain.NeedFinding` is defined (`domain/capability.go`), listed
  in `RecommendPositionV1().Needs`, and asserted in tests — but `app.AssembleContext` fetches the subject
  Finding **unconditionally** and only branches on `NeedFaultline`. The `ContextNeed` mechanism therefore
  governs the *expansion* but not the *root*, so a capability cannot truthfully declare its grounding. Harmless
  today (every capability needs the Finding), but it is dead code that misrepresents the contract and it is
  precisely what blocks a non-Finding subject. **Where it plugs in:** `internal/intelligence/app/context.go` +
  `domain/capability.go`. **Dep:** overtaken by **`EDR-TRUST-01` T10** — the owning context produces
  authoritative **Domain Projections** and the runtime gathers nothing, which deletes `AssembleContext` and
  this defect with it. (It was first filed against `EDR-INTELLIGENCE-01` Revision 5 / S3, now superseded.) Filed here so
  the defect is not lost if the trust-model line is deferred. **Scope:** LOW on its own; free under T10.

- [ ] **TRUST-1 — Applicability statements carry no per-statement trust class.** _(Surfaced implementing
  `phase3-trust-model` group 2, 2026-08-06.)_ `EnterpriseView` now tracks trust per field-group (headline /
  ranges / signals), but **applicabilities are excluded**: `domain.Applicability{Package, Status,
  Justification}` is used as the **dedup map key** in `Reconcile`, so adding a source field would change
  dedup semantics (two vendors stating the same thing would stop collapsing) and would ripple into the frozen
  `knowledge.faultline_enriched.v1` schema. **Why it is not urgent:** every applicability today originates
  from vendor VEX or an uploaded VEX document, so all of them are uniformly **Asserted** — a per-statement
  class would carry no information yet. **It becomes load-bearing** when a *derivable* applicability source
  appears (e.g. a signed build manifest), because then two statements on one card would deserve different
  classes. **Where it plugs in:** `internal/knowledge/domain/reconcile.go` + a `.v2` payload schema.
  **Scope:** MEDIUM when a mixed-trust applicability source lands; LOW until then.
  **✅ THE DEFERRAL NOW HAS AN EXPIRY (2026-08-07).** `TestApplicabilitySourcesAreUniformlyAsserted`
  fails the build the moment any applicability-producing source (`redhat`, `vexfeed`, `vex`) is
  classified as anything but Asserted — which is precisely when the deferral stops being correct. A
  second test keeps that source list honest against `shippedSources()`, since the guard is only
  sound while the list is complete.
  **Why a guard rather than the fix:** implementing it today would change `Reconcile`'s dedup key
  and require a `.v2` payload schema, to represent a distinction that does not yet exist. What
  needed fixing was not the model but the RISK that the deferral rots silently — and it would have
  failed silently: the dedup key would collapse a derivable statement into an asserted one, and the
  survivor's provenance would be whichever the map happened to keep.

- [x] **TRUST-2 — The shipped-source list for the classification guard is manual.**
  ✅ **CLOSED 2026-08-07.** `shippedSources()` now **derives** the enumeration instead of restating it:
  registering a feed ACL is how a source becomes reachable at all, so `feed.NewRegistry().Sources()` already
  knows every one of them, plus the single non-ACL source — the operator-uploaded VEX path, now named
  `app.VEXDocumentSource` at its definition rather than as a bare literal. Adding a feed therefore cannot
  skip classification: the guard fails the build before the source can fail closed in production.
  **The guard now runs in BOTH directions.** `TestTrustTableClassifiesOnlyShippedSources` catches the
  opposite drift — a table entry for a source nothing produces. That is not cosmetic: a stale entry reads as
  a considered decision about a live source, so the next reviewer answers a question about something that is
  not there, and a genuinely missing classification is easier to miss in a table padded with fiction. Three
  such entries had already accumulated (`epss`, `kev`, `scanner-report` — none is a real source id; the
  sweep records under `epsskev`) and were removed. A calibration test was asserting against one of them.
  Original report follows.
  _(Surfaced implementing `phase3-trust-model` group 2, 2026-08-06.)_
  `TestEveryKnownSourceIsClassified` asserts that every source Knowledge can record a Proposal under is
  present in `trustBySource`, but the "every source" list is **hand-maintained** in the test. Adding a feed
  and forgetting both the table *and* the list would still compile, and the new source would fail closed to
  Asserted silently — safe, but wrong for a feed republishing a public record, whose conclusions would be
  needlessly kept out of policy auto-acceptance. **Fix:** derive the list from a single shipped-source
  registry (source ids as constants, or the feed registry enumerating itself) so classification cannot be
  skipped. **Where it plugs in:** `internal/knowledge/adapters/{feed,wiring}`. **Scope:** LOW.

- [ ] **TRUST-3 — The AI→Knowledge proposal source is unclassified, and the fail-closed default is wrong for
  it.** _(Surfaced implementing `phase3-trust-model` group 2, 2026-08-06.)_ `EDR-INTELLIGENCE-01` D2 allows an
  Intelligence capability to propose **into Knowledge** as a source Proposal; only the Governance path is
  wired today, so no AI source id exists in `trustBySource`. An unregistered source fails closed to
  **Asserted** — deliberately, because labelling an unknown feed `Inferred` would claim a model produced
  something no model touched. But for a genuinely AI-sourced proposal that default **under-classifies** it,
  and `Inferred` is the one class with a constitutional consequence (T4: never auto-acceptable). **This is
  the single case where the fail-closed default is not conservative enough.** **Fix:** when the AI→Knowledge
  path lands, classify its source id as `value.TrustInferred` and delete
  `TestNoShippedSourceIsInferredYet`, which exists to make this impossible to forget. **Where it plugs in:**
  `internal/knowledge/adapters/wiring/trust_sources.go`. **Dep:** the AI→Knowledge proposal-intake path
  (Δ4-class). **Scope:** MEDIUM — a correctness gap the moment that path ships.

- [x] **TRUST-5 — `cmd/intelligence` still reads `THEMIS_KNOWLEDGE_URL` into dead config.**
  ✅ **CLOSED 2026-08-06.** `knowledgeURL` removed from `cmd/intelligence`'s config and `KnowledgeURL` from
  `wiring.Config`, so the knob cannot be set at all rather than being set and ignored. Also swept the places
  that still handed it to the Intelligence node — `deploy/systemd/install-systemd.sh`, `INSTALLATION.md`'s
  run block, and `deploy/node.env.example` (which now states positively that the node reads no Knowledge
  address, and why). Corrected the `cmd/intelligence` package doc, which still described grounding "via the
  Governance + Knowledge read APIs" and a "Rule → Knowledge → LLM plan" — both untrue since T10 and the
  Rule-engine deletion. **Found alongside:** `wiring.KnowledgeReadAPI` in the *Knowledge* context was
  likewise unreachable ("kept for callers that need only the query surface" — there are none); deleted, which
  clears the one `make deadcode` report in the greenfield tree.
  _(Surfaced during the VM verification run, 2026-08-06.)_ `main.go:69` reads the env var into
  `Config.KnowledgeURL` and passes it to `wiring.Config` (`wiring.go:35`), but **nothing consumes it** — the
  runtime stopped reading Knowledge in `phase3-trust-model` group 9 (T10), and Governance composes the
  enrichment into the `FindingAssessment` projection instead. The field is set, threaded, and never used.
  **Why it matters:** `make deadcode` cannot see it (a struct field, not a function), so it will sit there
  looking load-bearing. An operator reading `node.env.example` or the process env reasonably concludes the
  Intelligence node still needs a Knowledge address, and would "fix" a working deployment by adding it back.
  **Fix:** drop `knowledgeURL` from `cmd/intelligence`'s config and `KnowledgeURL` from `wiring.Config`.
  **Where it plugs in:** `cmd/intelligence/main.go` + `internal/intelligence/adapters/wiring/wiring.go`.
  **Scope:** LOW — cosmetic, but it is exactly the kind of stale knob that outlives the code that used it.

- [x] **TRUST-4 — The CVE-withdrawal path carries no trust class, and unset is not safe for it.**
  _(Surfaced implementing `phase3-trust-model` group 3, 2026-08-06.)_ `knowledge.faultline_superseded.v1`
  has no trust field, so `Coordinator.OnFaultlineSuperseded` builds an `EnrichmentSignal` with the classes
  **unset**. A withdrawal is genuinely **Observed** — re-fetch and the CVE is still rejected upstream, which
  is reproducible — but unset reads as `Inferred` under `value.MaxTrust`, and the group-4 constitutional bar
  (T4) would then **block a policy auto-accept that works today**. That is a live regression waiting for
  group 4, not a theoretical one. **Fix (in group 4):** classify the withdrawal path explicitly — either add
  the field to the superseded event additively (as the enriched event just did) or set it at the coordinator
  with a comment. Prefer the event: it keeps the class where the evidence is. **Where it plugs in:**
  `internal/governance/app/coordinator.go` + optionally `knowledge.faultline_superseded.v1`.
  **✅ MITIGATED in group 4 (2026-08-06):** `evidenceTrustFor` now states `value.TrustObserved` for the
  withdrawal path, with `TestReactToEnrichment_WithdrawnPathStillAutoAccepts` guarding the regression — the
  auto-accept that works today keeps working. **What remains:** the class is a **stated assumption in
  Governance** rather than a fact carried from the source. Move it onto
  `knowledge.faultline_superseded.v1` (additively, as `faultline_enriched` did in group 3) so it reflects
  what actually drove the supersession. **Scope:** LOW now the regression is closed.
  **⏸ DEFERRED WITH CAUSE 2026-08-07 — the field would go on an event nobody emits.** Investigating the fix
  found that `Faultline.Supersede()` has **no production caller at all** (`grep '\.Supersede('` returns only
  tests and the unrelated Communication aggregate). The event type is registered in the store's topic map
  and Governance's coordinator handles it, but Knowledge never publishes it — so the whole withdrawal path
  is **consumer-only** and the `Withdrawn` branch in `evidenceTrustFor` is unreachable in production. Adding
  a trust field to an unpublished event is speculative design against an unbuilt producer, which is likely
  to be wrong by the time the producer exists. **The requirement stands and moves to the producer's
  ticket:** whoever wires supersession carries the class on the event rather than restating it in
  Governance. See **KN-WITHDRAW-1** below for the producer gap itself.
  **✅ CLOSED 2026-08-07 — the producer exists, so the deferral expired the same day.** KN-WITHDRAW-1
  built it (`BackfillService` → `SupersedeFaultline` → `Faultline.Supersede()`), and it was watched
  running live on the VM: NVD reports CVE-2021-20095 `vulnStatus: Rejected` → the card is superseded →
  Governance raises a system `not_affected` → policy auto-accepts.
  `knowledge.faultline_superseded.v1` now carries `Trust` (additive + `omitempty`, EVENTBUS D9), set
  from `TrustPolicy.ClassOf(source)` at the point of supersession — so the class states who reported
  the withdrawal instead of Governance assuming. `SupersedeFaultline` takes the source; the DTO,
  `InboundFaultlineSuperseded`, and `EnrichmentSignal.WithdrawnTrust` thread it through.
  **Behaviour change:** a withdrawal from an **Asserted** source no longer clears the shipped D15
  `observed` floor — it raises the proposal and waits for a human, instead of auto-suppressing on a
  vendor's unverifiable word. NVD is Observed, so the live path is unchanged.
  An **absent** class still reads as Observed (the value this code stated unconditionally before), so
  replaying pre-change bus rows behaves identically — deliberately not fail-closed, because failing
  closed here would convert a wire-compatibility gap into a behaviour regression.
  Guarded by `TestSupersedeFaultline_CarriesTheReportingSourcesTrustClass` (Observed + fail-closed
  Asserted), `TestConsumer_FaultlineSupersededCarriesTrustToTheProposal` (all three wire shapes), and
  `TestReactToEnrichment_WithdrawalFromAn{Asserted,Observed}SourceIs…` — the Asserted one verified to
  FAIL against the previous stated-Observed code.

- [x] **TRUST-6 — `business_invalid` discards *which* Grounding Verification check failed.**
  ✅ **CLOSED 2026-08-07.** `app.Outcome` gained a `Detail` field carrying the check's own message, set on
  **both** collapsing branches: `ReasonBusinessInvalid` (from `verr`) and `ReasonSchemaInvalid` (a new
  `lastSchemaErr` kept across the retry loop, so an exhausted budget can say *what* was malformed instead of
  only that something was). Redacted through the same path as the prompt, since the messages quote model
  output verbatim. Surfaced as a `detail` log field, omitted on a clean run. **Deliberately NOT in the HTTP
  response:** the 204 stays opaque, because "AI disabled", "AI unreachable" and "AI declined" are one
  outcome by design and leaking which occurred would put the Gateway's operational state into a business
  API that treats AI as optional. **Found while testing:** only **two** of the four `ValidateBusiness`
  checks are reachable — the per-capability output schema bounds `confidence` and constrains
  `recommended_stance`, so those two surface as `schema_invalid` first. They stay in the validator as
  defence-in-depth (the schema is configuration; the invariants are not), and the test records why.
  Original report follows.
  _(Surfaced during the `phase3-trust-model` VM verification run, 2026-08-06.)_
  `domain.Validator.ValidateBusiness` returns a fully-formed error naming the failure — wrong `finding_id`
  echo, confidence outside `[0,1]`, disallowed stance, or ungrounded evidence ref — but
  `app.Gateway` maps every one of them to the single constant `ReasonBusinessInvalid` and drops `verr`
  (`gateway.go:294-297`). The outcome telemetry therefore records *that* the AI output was refused and never
  *why*. On a live VM this made a real 204 undiagnosable from logs: `recommend_position` reached
  `cyberpal20b:latest`, returned 1182 tokens in 40s, and was refused — with no way to tell a hallucinated
  UUID from a hallucinated evidence ref without re-running against different subjects to infer it.
  **Why it matters beyond convenience:** these four checks fail for opposite reasons. A wrong `finding_id`
  is a *model-capability* problem (fix: smaller ids in the prompt, or a stricter response schema); an
  ungrounded ref is a *grounding* problem (fix: the projection is too thin); a disallowed stance is a
  *prompt/capability-contract* problem. Collapsing them hides which lever to pull, and G-AI-2 ("can't
  determine is an improvement signal") depends on exactly this signal being legible.
  **Fix:** carry the validator's error into the outcome as a `detail` field alongside `Reason` — telemetry
  only, never the API response (the 204 must stay opaque, see the advisory-AI invariant). Redact before
  emitting, per R1. **Where it plugs in:** `internal/intelligence/app/gateway.go` (`Outcome`),
  `internal/intelligence/domain/validate.go` (already produces the text). **Dep:** none.
  **Scope:** LOW-MEDIUM — small change, disproportionate diagnostic value.

- [x] **TRUST-7 — No auto-accept policy is wired in any composition root, so the constitutional bar is
  end-to-end unobservable.** ✅ **CLOSED 2026-08-06.** The missing piece was a decision, so the decision was
  written first: **EDR-GOVERNANCE-01 D15** (+ GOV-15), which settles that Themis ships **exactly one**
  auto-accept rule, `auto-not-affected-observed` — open **and** `ActorSystem`-raised **and** stance
  `not_affected` **and** evidence class `observed`. Implemented as
  `domain.AutoAcceptObservedNotAffectedPolicy()`, wired in `cmd/governance` behind
  `THEMIS_GOVERNANCE_AUTOACCEPT` (`observed_not_affected` default | `off`), and **logged either way** —
  the silent-empty-policy state is exactly what made the bar unobservable, so `off` now announces itself.
  **The substance is the `observed` floor, which is stricter than T4 requires.** T4 bars only `Inferred`,
  which would have left `Asserted` — a vendor's word — auto-suppressing Findings, contradicting EDR-VEX-01's
  "Gathering Is Not Knowing". The floor lives on `PolicyRule` itself (`RequiringEvidence`), so a rule that
  omits one is permissive-by-accident rather than strict-by-accident: the failure mode that is loud in
  review instead of invisible at runtime. The comparison reuses `value.MaxTrust` rather than exporting a
  rank — `MaxTrust(actual, required) == required` is exactly "at least as strong as", and an unset class
  folds to `Inferred` so it clears no floor. Tests cover all seven shapes, the case that carries the
  decision being an `Asserted` vendor `not_affected` that **passes** the constitutional bar and is still
  refused. Original report follows. _(Surfaced during the `phase3-trust-model` VM verification run, 2026-08-06.)_
  `cmd/governance/main.go` calls `app.Wire(...)` with **no `policies...`**, so `FindingService.policies` is
  empty on every deployed node. Consequences: stage 2 of `raiseAndMaybeAutoAccept` never fires, so nothing is
  ever auto-accepted; and the T4 constitutional bar in stage 1 — the headline decision of EDR-TRUST-01 —
  produces an outcome **indistinguishable** from "no policy matched" (both leave the proposal open). The bar
  is proven by unit tests and cannot be demonstrated on a running system.
  **Why open rather than a defect:** which stances a policy may auto-accept, and under whose authority, is a
  Governance-owned business decision that no EDR has taken yet — shipping a default would be inventing
  enterprise policy in a composition root. `PolicyRule` already restricts auto-accept to open,
  system-raised proposals (the authority axis, T12), so the mechanism is ready; only the configuration is
  absent. **Fix:** decide the default policy set (candidate: auto-accept `system`-raised `not_affected`
  resting on non-Inferred evidence, matching the EDR-VEX-01 Phase 2 suppression overlay), express it as R2
  self-documented config rather than a hardcoded literal, and wire it in `cmd/governance`.
  **Where it plugs in:** `cmd/governance/main.go` + `deploy/node.env.example`.
  **Dep:** needs a policy decision before code. **Scope:** MEDIUM — blocks demonstrating T4/T6 on a
  live system and leaves the VEX auto-suppression path dormant.

- [x] **TRUST-8 — The AI rationale a human reads is the least-verified field in the proposal.**
  ✅ **CLOSED 2026-08-07** via candidate **(b)**, the deterministic option — chosen over prompt-engineering
  because it is verifiable rather than hopeful, and cannot itself hallucinate.
  `domain.UngroundedMentions(text, ac)` scans free text for identifier-shaped tokens (UUID / CVE id / PURL)
  that the authoritative grounding does not contain, deduped, sorted for stable telemetry, and capped at 5.
  It flags **false precision, not bad writing**: prose, version numbers and package names never trip it.
  Carried as `Proposal.RationaleWarnings` → `rationale_warnings` on the v1 API (additive, omitted when
  empty) → the Governance seam → **embedded in the recorded proposal rationale** as an `UNVERIFIED MENTIONS`
  caveat. Embedded rather than stored beside it on purpose: the rationale is what the deciding human reads,
  so a caveat kept anywhere else is one a reviewer can miss, and it is preserved verbatim in the immutable
  Position inputs if the proposal is ever accepted. The original narrative is never edited — annotating
  preserves the audit trail that model output *is*.
  **It warns, never blocks.** The structured evidence already passed Grounding Verification, so the proposal
  is well-formed; prose is not verifiable and refusing on it would reject correct recommendations for style.
  An empty result does **not** certify the narrative — it only means no ids were invented, and that
  asymmetry is stated in the code.
  **Found by its own test:** `FindingAssessment.Grounds` did not accept `Finding.ReleaseID`, though the
  projection carries it and hands it to the model — so Grounding Verification would have **refused an
  evidence ref naming the very release the Finding is scoped to**, and the scan reported a correctly-cited
  release as invented. Fixed. Original report follows.
  _(Observed on a live model during the `phase3-trust-model` VM verification run, 2026-08-06.)_
  T8 Grounding Verification checks the **structured** `evidence[].ref` array by set membership against the
  `AssembledContext` (`ac.Grounds(ev.Ref)`), and Governance's Business Verification checks the same refs with
  `f.Vouches(ref)`. Neither examines the free-text `reasoning` field — correctly, since prose cannot be
  set-membership-checked. **Observed instance:** `cyberpal20b:latest` produced a valid proposal for
  `CVE-2026-41842` on finding `3c4c08b3…` whose two evidence refs both correctly cited faultline
  `a38d9c32…` and passed every stage — while its `reasoning` stated the component was "included in the
  release ee006ff7-f278-496e-8b31-ff0aba181db3". The Finding's actual release is `007de00e…`; `ee006ff7…` is
  an unrelated release from a prior day that the model was never given. **Why it matters:** the rationale is
  what a human reads when exercising the T4 decision the constitution reserves for them, so the most
  persuasive part of the output carries the weakest guarantee, and nothing distinguishes it from the
  verified refs at the point of decision. **This is not a trust-model defect** — the proposal is `Inferred`,
  barred from auto-acceptance, and a human decided; the safety net held. It is a *presentation* gap.
  **Candidate fixes (not yet chosen):** (a) render `evidence[].ref` as the primary UI/report artifact and the
  narrative as clearly-secondary; (b) post-hoc scan the rationale for identifier-shaped tokens
  (UUIDs, CVE ids, PURLs) not present in the grounding set and attach a warning to the proposal —
  cheap, deterministic, and catches exactly this class; (c) prompt the model to reference only ids it cites
  in `evidence[]`. Option (b) is preferred: it is verifiable rather than hopeful. **Where it plugs in:**
  `internal/intelligence/domain/validate.go` (a rationale-scan alongside `ValidateBusiness`) +
  the Communication serializers that render a rationale. **Dep:** none. **Scope:** MEDIUM — no correctness
  impact today, direct impact on human decision quality.

- [x] **TRUST-9 — The version-range verdict (T5) fires on exactly one transition — "no usable range at
  correlation, usable range later" — and nothing demonstrates it end-to-end.** _(Established during the
  `phase3-trust-model` VM verification run, 2026-08-06.)_ Two independent gates evaluate the same predicate
  at different times, and the first one starves the second:
  1. `knowledge/app/correlate.go:143` — `ApplyCorrelation` **skips `RecordMatch`** when
     `affected.Applicability(version) == RangeOutOfRange`, so no Match, and therefore **no Finding**, is
     ever created for a provably out-of-range component.
  2. `governance/app/service.go` — `reactToVersionRange` raises its system `not_affected` proposal only when
     `domain.ProvablyOutOfRange(f.Components(), sig.AffectedRanges)` holds for **every** matched component
     of an existing Finding.
  Since (1) guarantees each Finding's components were *not* provably out of range at correlation time, (2)
  can only become true via one specific transition. `value.AffectedRange.Applicability` returns
  `RangeUndecidable` when `hasUsableConstraint()` is false, and correlation skips **only** on
  `RangeOutOfRange` — so a card with no usable range still produces a Match and a Finding. When a usable
  range arrives later and excludes the component, the verdict flips `Undecidable → OutOfRange` and the
  proposal is raised. That is precisely the case `ProvablyOutOfRange`'s own doc comment names: "a Finding
  created BEFORE the range was known, which correlation's own gate (which only runs at match time) will
  never revisit."
  **What cannot trigger it — and this is the part that is easy to get wrong:** a range *narrowing*.
  `Reconcile` builds `AffectedRanges` as the **sorted union** across contributing sources, and
  `AffectedRange.Matches` is satisfied by any group. A union only ever widens, so once a usable range
  admitted a component, no later evidence can exclude it. Writing the e2e test around "a higher-precedence
  feed refines an over-broad range" would therefore test a transition the reconciliation model makes
  impossible. **Confirmed on the VM:** across 237
  faultlines, 196 Findings, and successful OSV + EPSS/KEV + NVD enrichment,
  `select count(*) from finding_proposals where proposal_id like 'range:%'` returned **0**. Every system
  `not_affected` came from `vex-applicability` instead.
  **Why this is not simply a defect:** the two gates are complementary by design — Knowledge's is
  *pre-Finding noise suppression*, Governance's is *post-Finding governed retraction* that must travel the
  proposal road rather than silently deleting a Finding a human may already have decided on. Both are
  correct. **What is genuinely open:** (a) there is **no test or demo path** that exercises the Governance
  gate end-to-end, so a regression there would be silent — the unit tests cover `ProvablyOutOfRange` but
  nothing covers the wave that triggers it; (b) it is unverified how often ranges actually narrow in
  practice, so the path's real-world reachability is unmeasured; (c) if narrowing is rare, T5's
  "Deterministic Inference precedes AI" claim rests on a path that seldom runs.
  **Fix:** add an integration/e2e scenario that correlates a Finding while its card carries **no usable
  affected range** (so correlation's gate defers on `RangeUndecidable`), then folds a proposal that supplies
  a usable range excluding the installed version, and asserts a `range:` proposal appears carrying the range
  group's trust class. Land it in `tests/pipeline` (it needs two waves, so it is not a unit test). Then
  instrument how many `range:` proposals real deployments raise — on a deployment where discovery always
  arrives with ranges attached (OSV), the answer may legitimately be zero.
  **Where it plugs in:** `tests/pipeline/`, `internal/governance/app/service.go` (telemetry counter).
  **Dep:** none. **Scope:** MEDIUM — the code is believed correct, the assurance is missing.
  **✅ CORRECTED + PARTLY COVERED 2026-08-07.** The "nothing covers it" claim was **wrong**, and filing it
  without checking was the error: `internal/governance/app/service_trust_test.go` already had six
  `reactToVersionRange` tests (raises, AI-disabled, defers-when-in-range, idempotent, and two error paths).
  Added `service_shipped_policy_test.go`, which closes the part that genuinely was missing — every existing
  policy test built a **floor-less** `NewPolicyRule`, so nothing exercised the rule a real deployment runs.
  It drives `domain.AutoAcceptObservedNotAffectedPolicy()` (D15) through the two system paths side by side:
  the version-range verdict (Observed) auto-accepts to a Position whose **actor is the policy**, while a
  vendor `not_affected` (Asserted) — same stance, same system proposer — is refused and left open for a
  human. Same stance, same proposer, different evidence, opposite outcomes: the sharpest demonstration
  available that trust decides, not the producing component (T1/T2). Also asserts `affected` never
  auto-accepts. **What is still genuinely open:** the *production reachability* question — no deployment has
  yet produced a `range:` proposal, because correlation's own gate means a Finding exists only for a
  component that was in range at match time. The unit tests prove the code; they cannot prove the wave
  occurs in the field. Instrumenting how many `range:` proposals real deployments raise remains the open
  work, and the answer may legitimately be zero for OSV-only estates.

- [x] **NVD-WATCH-1 — The modified-since watch silently examines ~5% of its window and reports success.**
  ✅ **CLOSED 2026-08-07 — the walk it describes was DELETED, not repaired.** EDR-KNOWLEDGE-01 **D5a**
  replaced it with a per-CVE sweep over the carded set, which makes the relevance bound structural:
  only CVEs the enterprise holds are ever requested, so there is no window to truncate and nothing
  fetched to discard. The reporting half is closed too — `backfillLoop` logs on EVERY sweep
  including a zero fold, so "nothing left to enrich" and "the feed stopped working" no longer look
  alike. VM-verified: eight consecutive `folded: 0` sweeps after the estate caught up, and the count
  moves the moment real facts change.
  _(Found on a live VM during the `phase3-trust-model` verification run, 2026-08-06 — a pre-existing feed
  defect, unrelated to the trust model.)_ `NVDClient.ChangedSince` pages with `nvdPageSize = 2000` and
  `nvdMaxPages = 10`, so **one poll reads at most 20,000 records**. Measured against the live NVD API, a
  120-day window currently holds **356,223** modified CVEs — the watch therefore covers **5.6%** of it, takes
  whatever NVD happens to return first, and exits the loop with **no error, no warning, and no log line**
  (`for page := 0; page < nvdMaxPages; page++` simply ends). `watchLoop` then calls `recordFeed(health,
  "nvd", nil, …)`, so `GET /feeds` reports `status: healthy`, and because `watchLoop` logs only `if n > 0`,
  a truncated poll that folded nothing is **completely silent**.
  **Observed consequence:** with 237 carded CVEs and NVD + EPSS/KEV both enabled, the watch folded **0**
  cards across three successful polls (including a full 120-day window after a deliberate watermark reset).
  `CVE-2021-44228` is carded and was modified `2026-06-17` — inside the window — and was still never
  enriched. Every card's headline stayed `severity_source: osv`, so **no card in the deployment has
  authoritative NVD CVSS**, which is the entire purpose of the watch. This is very likely the real mechanism
  behind the older "A2 NVD returns 0" observation (2026-07-31), which was diagnosed as a discovery problem.
  **Worse, the watermark advances anyway:** `WatchService` reads `since` from `feed_health.last_success_at`,
  which is written on any non-error poll. So a truncated poll **advances the watermark past records it never
  read**, and those records are never revisited — the gap is permanent, not eventually-consistent.
  **Fix (in order):** (1) detect the cap — when the loop exits with `startIndex < resp.TotalResults`, that is
  a truncated poll; (2) **do not advance the watermark** on a truncated poll, or advance it only to the
  last-modified timestamp actually consumed, so the next poll resumes rather than skips; (3) log
  `discovered` alongside `folded` and surface truncation in feed health as a distinct state (`healthy` is a
  lie here); (4) reconsider the bound itself — 20,000 is not a meaningful fraction of a 120-day NVD window,
  so either raise it substantially, narrow the default window, or drive the watch from the carded CVE set
  (a per-CVE `cveId` fetch for the ~237 cards is bounded by the estate rather than by NVD's churn, which is
  what D5's relevance bound actually implies).
  Option (4)-by-carded-set is the strongest: it makes the cost proportional to the enterprise, not to the
  internet — and it is already filed independently as **"Knowledge — NVD by-CVE backfill (targeted
  enrichment)"** (§C, surfaced 2026-07-30), which proposed `FetchByCVEID` as an *addition* to the watch.
  This finding upgrades that item from a nice-to-have to the **primary** fix: the watch is not merely
  missing cards outside the window, it is missing 94% of the cards *inside* it.
  **Corrects a neighbouring item:** "(LOW) Feed-health records only *after* a full poll" (§C, 2026-07-31)
  states the first 120-day poll takes "~12 min". Measured 2026-08-06, a full-window poll completed in
  **under 60 seconds** — precisely *because* it truncates at 20,000 records. The slowness that item
  describes was never the real behaviour; the speed is the symptom.
  **Where it plugs in:** `internal/knowledge/adapters/feed/nvd_client.go` (`ChangedSince`),
  `internal/knowledge/app/watch.go` (watermark advance), `cmd/knowledge/main.go` (`watchLoop` logging).
  **Dep:** none. **Scope:** HIGH — the NVD watch is currently non-functional in any deployment whose CVEs
  are not in the first 20,000 records of the window, and it fails silently while reporting healthy.
  **⚠️ TWO CORRECTIONS TO THIS ENTRY, both found on the VM 2026-08-07 — read them before acting on it.**
  **(1) The watermark is `knowledge_watch_state.last_success`, NOT `feed_health.last_success_at`.** This
  entry and its commit message both named the wrong table. I grepped `LastSuccess`, saw feed-health code
  nearby, and did not follow the port to `Store.LastSuccess`. The load-bearing claim survives — a truncated
  poll DID advance the watermark past records it never read, and the fix (truncation → error →
  `SetLastSuccess` never called) works whichever table holds it — but the mechanism narrative pointed at the
  wrong one. It also invalidated a test I thought I had run: the 2026-08-06 `update feed_health …` reset
  never touched the watch, so "a full-window poll completed in under 60 seconds" was measuring a window of
  minutes, not 120 days. That inference is withdrawn.
  **(2) The slicing walk needed request PACING, which the fix omitted — and the bug it replaced was hiding
  the need.** Resetting the real watermark to 120 days and polling produced
  `context deadline exceeded … while reading body`: the walk issues a few hundred requests back to back,
  NVD throttles per rolling 30 seconds (5 unauthenticated, 50 with a key), and a throttled request
  eventually exceeds the client timeout and fails the whole poll. The OLD code was capped at
  `nvdMaxPages`, so it made at most 10 requests per poll — **the truncation that made it wrong was also,
  accidentally, keeping it inside the rate limit.** Fixed by deriving a minimum inter-request gap from the
  API key (700ms keyed, 6.5s unkeyed), applied only to the public endpoint so a mirror or a test server is
  unpaced. A 120-day first poll therefore takes roughly three minutes; subsequent polls are one slice.
  **(3) MEASURED 2026-08-07 — walking the window is not viable at all, and this settles the open
  strategy question below.** One NVD request for a 24-hour slice returned **5.2 MB in 83.6 seconds**; the
  next nine requests answered in ~1.2s each, so this is NVD's server-side generation time, not throttling
  and not our rate limiting. A 120-day cold start is therefore **~2.8 hours** of walking, and no timeout or
  **✅ DECIDED + IMPLEMENTED 2026-08-07 — EDR-KNOWLEDGE-01 D5a: NVD enrichment is per-CVE over the carded
  set.** The measurement settled the open strategy question: 3,207 records fetched to apply 18 (**0.56%**),
  at ~84s per day of window, making a 120-day cold start ~2.8 hours. `NVDClient.VulnsForCVE` fetches one
  CVE by id; `app.BackfillService` sweeps the cards still missing an NVD Proposal, oldest first, capped per
  run (`THEMIS_NVD_BACKFILL_LIMIT`, default 200). The relevance bound is now **structural** — only carded
  CVEs are ever requested, so nothing is fetched that could be discarded — and coverage strictly improves:
  a CVE whose last modification predates the window was unreachable by the walk at any budget.
  **The walk is deleted**, with `WatchService`, `RelevanceFilteredSource`, the `ChangedVulnSource` port and
  the watermark accessors. There is no watermark now, which is the structural point: the **queue is the
  state**, so there is nothing to advance past unread work — the failure mode this entry was about. It also
  aligns NVD with every other feed: OSV is queried by package, Red Hat and CSAF-VEX by CVE; NVD was the
  last window walker.

  pacing constant changes that — the cost is proportional to NVD's record volume. **The per-CVE strategy
  (option 4) is no longer merely preferable; it is the only viable design**, and needs the
  EDR-KNOWLEDGE-01 D5 note.
  **Interim, so the watch works at all:** the client timeout went 60s → 180s (one real page exceeds 60s on
  its own); a cold start reaches back **7 days** rather than 120; and one poll covers at most **3 days**,
  with `ChangedSince` now reporting the instant it actually covered so `WatchService` advances the
  watermark only that far. A long backlog therefore drains over successive polls **losslessly** — advancing
  to "now" after a partial walk would be the original NVD-WATCH-1 defect in a new costume.
  **✅ PARTIALLY FIXED 2026-08-06 — the silence and the skip are gone; the strategy question remains.**
  `NVDClient.ChangedSince` no longer requests the window whole. It **walks it in contiguous slices**
  (`nvdSliceWindow`, 24h), and a slice holding more than the page budget is **halved and retried** — the
  cursor does not advance, so nothing is skipped. Only when narrowing bottoms out at `nvdMinSlice` (1h) does
  it return the new `feed.ErrWindowTruncated` **with** the partial results. Because `WatchService.Poll`
  advances the watermark only on a nil error, an unreadable slice is now retried next poll instead of being
  stepped over permanently, and `recordFeed` degrades feed health — so the feed can no longer report
  `healthy` while blind. `watchLoop` also logs **every** successful poll including a zero fold, since
  suppressing the zero case is what made a 5%-coverage feed look like a quiet one.
  Two regression tests pin the properties that matter rather than the mechanism:
  `TestNVDClient_ChangedSince_WalksTheWindowInContiguousSlices` (starts at the watermark, reaches now, and
  **no gap** between consecutive slices) and
  `TestNVDClient_ChangedSince_OverfullSliceNarrowsThenErrorsNeverTruncates`.
  **What remains open (needs a decision, not code):** whether the watch should keep walking the window at
  all. Covering 120 days now means fetching on the order of 356k records to fold a few hundred — correct, but
  it reads the internet to learn about the estate. The alternative is fix (4): drive enrichment from the
  **carded CVE set** via per-CVE `cveId` fetches, making cost proportional to the enterprise, which is what
  D5's relevance bound actually implies. That is a change to how the feed works and is the same choice as
  the "NVD by-CVE backfill" item; it wants an EDR-KNOWLEDGE-01 D5 note before implementation. Also still
  open: logging `discovered` alongside `folded`, so "the feed returned nothing" and "nothing it returned was
  about us" stop being the same signal — the relevance filter drops records inside
  `RelevanceFilteredSource`, before `Poll` can count them.

- [x] **TRUST-10 — A correct evidence ref was refused because the model LABELLED it.**
  _(Found on the VM 2026-08-07, by TRUST-6's new `detail` field, minutes after deploying it.)_ A live
  `recommend_position` returned `business_invalid`, and the detail read
  `ungrounded evidence "faultline b1be6f86-2ecd-451f-9411-95f1f32fd501"`. That id **is** the Finding's
  faultline — the model cited the right reference and prefixed it with the word "faultline". Grounding
  Verification is exact set membership, so it refused on formatting.
  **Why this matters more than it looks:** a false refusal is not a safe failure. It inflates the AI seam's
  apparent failure rate, and it hides the *real* refusals — a hallucinated id and a correctly-labelled one
  produced the identical outcome, which is precisely the ambiguity TRUST-6 was filed to remove one level up.
  **Fix:** `value.IdentifierTokens` in the kernel extracts identifier-shaped tokens (UUID / CVE / PURL) from
  free text; `groundsRef` (Intelligence) and `vouchesRef` (Governance) try an exact match first and only
  then require **every extracted token** to clear the same exact check. Both sides changed together on
  purpose — had only the runtime been relaxed, the refusal would merely have MOVED to Business
  Verification and become harder to diagnose.
  **The tolerance is deliberately narrow, and substring matching was rejected:** `"CVE-2024-1000"` is a
  substring of `"CVE-2024-10000"`, so a grounded id would vouch for a different one. Whole anchored tokens
  plus exact membership keeps the guarantee — the model still has to name something it was given; it just
  stops being punished for saying so in a sentence. A ref carrying no identifier grounds nothing.
  Also de-duplicates the regexes TRUST-8's rationale scan had defined separately, so the two checks now
  agree by construction on what counts as an identifier.

- [x] **NVD-REFRESH-1 — The per-CVE sweep enriches a card once and never revisits it.**
  ✅ **FIXED 2026-08-07, together with KN-WITHDRAW-1 — they are the same mechanism.**
  `Store.CVEsMissingSource` became `CVEsNeedingRefresh(source, staleAfter, limit)`: never-enriched cards
  first, then any whose newest Proposal from that source is older than `THEMIS_NVD_STALE_AFTER` (default
  7 days). Superseded cards are excluded — the lifecycle is terminal there, so re-fetching them would spend
  requests to learn nothing and keep a retired card in rotation forever. Cost and cap are unchanged; only
  the ordering is. Original report follows.
  _(Surfaced verifying D5a on the VM, 2026-08-07 — a limitation of the change made that day, recorded the
  same day.)_ `Store.CVEsMissingSource` selects cards with **no** Proposal from the source, so once a card
  carries an NVD Proposal it is never fetched again. First enrichment is now complete and fast (236 of 239
  cards, 2m45s); **updates are not covered at all**.
  **This is a real trade, not an oversight to hide.** The modified-since walk it replaced was *designed* to
  catch changes — badly, seeing ~5% of its window, but it was the mechanism. The sweep covers
  first-enrichment completely and change-detection not at all. NVD data does change: scores get revised,
  severities corrected, and CVEs **rejected** (see KN-WITHDRAW-1, with a live instance).
  **Fix:** sweep by **staleness** rather than by absence — order by "never enriched first, then
  oldest-enriched", and include a card whose newest Proposal from that source is older than a configurable
  interval. `faultline_proposals.observed_at` already carries what is needed, so it is a query change plus
  one knob, not new state. Cost stays bounded and estate-proportional: the same cap per sweep, just a
  different ordering. It also makes withdrawal detection reachable for every card rather than only for
  never-enriched ones.
  **Where it plugs in:** `internal/knowledge/adapters/store/store.go` (`CVEsMissingSource` becomes
  `CVEsNeedingRefresh`), `internal/knowledge/app/backfill.go`, one env knob.
  **Dep:** none. **Scope:** MEDIUM — first enrichment works today, so this is about staying correct over
  time rather than getting correct now.

- [x] **DASH-1 — There is no way to reach a release's posture without already knowing its UUID.**
  ✅ **CLOSED 2026-08-07.** Registry gains `GET /products[?name=]`, `GET /products/{id}/projects[?name=]`
  and `GET /projects/{id}/releases[?version=]` — the product → project → release traversal a human
  actually has. Lookups are EXACT, not prefix: the caller knows the product they mean, and a fuzzy
  match returns a set they then have to disambiguate, which is the problem this removes rather than
  a smaller version of it.
  **A missing parent is a 404, not an empty 200.** "This product has no projects" and "there is no
  such product" are different answers, and collapsing them sends a caller hunting for a typo that is
  not there. `GET /releases?project=` was fixed to match — it used to return an empty list for a
  project that does not exist.
  _(Surfaced answering "how do I get a release dashboard?", 2026-08-07.)_ Governance's
  `GET /releases/{id}/posture` is a good rollup and is sorted-by-`residual_priority` away from being a
  triage dashboard. What is missing is everything *before* it: Registry exposes only `POST /products`,
  `POST /projects`, `POST /releases` and `GET /releases/{id}` — **no list, no lookup by name, no
  product→projects→releases traversal**. So an operator who knows "product mrf, release 20.1.0" cannot get
  to the posture at all without querying Postgres directly, which is exactly the coupling the read APIs
  exist to avoid. Every runbook in the repo works around it by capturing the id `gf-upload-sbom.sh` prints.
  **Fix:** read endpoints on Registry — `GET /products`, `GET /products/{id}/projects`,
  `GET /projects/{id}/releases`, and lookup-by-name query params. Spec-first, so the handlers are
  generated. **Where it plugs in:** `api/registry.openapi.yaml` + `internal/registry/adapters/http`.
  **Dep:** none. **Scope:** MEDIUM — small surface, and it is the difference between an API a human can
  navigate and one only a script that just created the objects can use.

- [x] **DASH-2 — Posture exists per release only; there is no product or project rollup.**
  ✅ **THE ENTRY-ROW HALF CLOSED 2026-08-07.** `PostureEntry` now carries `band` (Knowledge's
  exploitability band), `components` (with the source package) and `fixes` (the per-component
  selection), all materialized at enrichment like `base_score` before them.
  **Measured effect:** rendering one posture table cost **~460 API calls** — one Knowledge read per
  Faultline for the band, one Governance assessment per Finding for the component. It is now ONE
  read plus one Knowledge call per displayed row for KEV/EPSS. A rollup whose cost is linear in its
  own length cannot serve a dashboard.
  **Still open:** the product/project ROLLUP itself. DASH-1 now makes the traversal possible, so a
  caller can enumerate releases and merge client-side; a server-side rollup is a separate endpoint.
  _(Same conversation.)_ "Show me everything critical across product `mrf`" has no answer: `posture` is
  keyed by a single release id, so a caller must enumerate releases (which DASH-1 makes impossible over
  the API) and merge client-side. The estate graph for the *blast* direction already exists (C1:
  Product→Microservice→Deployment→Customer), so the model supports the traversal — the read surface does
  not.
  **Also missing from the entry rows themselves:** `PostureEntry` carries `base_score` but **no severity
  band**, so "which are critical?" needs one Knowledge call per faultline. Knowledge already computes
  `view.priority` (critical | high+ | high | elevated | informational) and it is exploitability-aware
  rather than raw CVSS — carrying it onto the posture entry (additively, as `residual_priority` was)
  would make the rollup self-sufficient.

- [x] **DASH-3 — "What do I upgrade this to?" cannot be answered from the Governance read surface.**
  ✅ **CLOSED 2026-08-07 by AI-GROUND-1.** `component.source` now rides end-to-end (event → store →
  API), and `GET /findings/{id}/assessment` returns `fixes` (package-attributed) +
  `unattributed_fixes`. `GET /releases/{id}/posture` carries components with `source` too, so the
  join no longer has to be re-implemented per caller. Verified on the VM: 6 attributed fixes
  returned where the flat union previously returned 94.
  _(Measured on the VM 2026-08-07, after KN-FIX-1 landed.)_ A Finding's components carry only the PURL,
  which holds the **binary** package name (`pkg:rpm/rocky/python3-pyyaml@…`). Fix versions on the
  Faultline are keyed by the **source** package name (`PyYAML`), because that is what distro
  vulnerability feeds publish. The two are not derivable from each other — `python3-pyyaml → PyYAML`
  and `python3-ply → python-ply` follow no shared rule. Only Evidence's inventory holds the mapping
  (`component.source`).
  Consequence: every client that wants to show a fix must fetch the release's evidence documents, pull
  each inventory, and build a purl→source map before it can call `FixesFor`. `scripts/release-posture.sh`
  now does exactly that (measured: without it, 16 of the top 20 rows read "N unattributed" for cards
  that held the right answer). A GUI would have to re-implement the same join.
  **Fix:** either carry `source` onto the Governance Finding component (it is already on the Knowledge
  `FaultlineMatched` event's inventory view, so no new truth — but it is a domain + event + store +
  API change), or expose the resolved fix directly on the finding assessment. The second is smaller and
  answers the question the caller actually has.
  **Dep:** none — KN-FIX-1 is the enabler and has landed. **Scope:** MEDIUM.

- [x] **KN-FIX-3 — fix attribution is ecosystem- and stream-blind, and version normalization is
  inconsistent.** ✅ **CLOSED 2026-08-13 (design: EDR-VEX-01 D8).** `FixedVersion` gained the
  canonical `Ecosystem` (`value.CanonicalEcosystem` — feeds state it: redhat→rpm, alpine→apk,
  OSV per record); a known ecosystem filters, an unknown one never does (fail-open, the
  ClaimUnknown→carrier direction). ONE rpm normalization path: reconciliation runs every
  rpm-class fix through `value.RPMEVR` before folding, so the Red Hat and OSV spellings collapse
  — and because the view is recomputed from all Proposals on every fold, this heals persisted
  cards. The append-only history heals via decode-time SOURCE stamping in the store codec
  (redhat/alpine are single-ecosystem — provenance is evidence; osv/nvd deliberately not
  stamped). Governance's `selectFixesFor` gained the same ecosystem check plus rpm EL-stream
  display scoping (`RPMReleaseMajor`, fail-open) — excluded fixes join `UnattributedFixes`, so
  "held but not yours" stays distinct from "no fix published". The fixed-VERDICT
  (`RPMFixedByStream`) was never at risk and is untouched. The measured perl drawer is the
  regression test at both layers (`TestReconcile_OneNEVRANormalizationAndEcosystemScoping`,
  `TestGetFindingAssessment_ExcludesWrongEcosystemAndWrongStreamFixes`). GUI-2b is now unblocked.
  _Original filing (measured on the VM 2026-08-12):_ — the first live estate carrying
  BOTH ecosystems' bounds on shared cards (the Alpine secdb feed, EDR-VEX-01 D7, landed 78
  proposals via shared CVEs). One Rocky EL8 finding's drawer (CVE-2020-10543, component `perl`)
  then attributed **four** fixes to the one package, three of them wrong for it:
  `4:5.26.3-419.el8` (correct EL8 NEVRA) · **`5.30.3-r0` (an Alpine apk version on an rpm
  component — the cross-ecosystem leak)** · `perl-4:5.16.3-299.el7_9` (an EL7 fix on an EL8
  finding) · `perl-4:5.26.3-419.el8` (the SAME EL8 fix again, name-prefixed — two code paths
  normalize NEVRA versions differently, so one fix renders twice).
  **Root cause:** `FixesFor(package)` keys on the bare package name; `domain.FixedVersion`
  carries no ecosystem and no stream, and nothing dedups across normalization variants.
  **Why it matters beyond the drawer:** the same per-component selection populates
  `FaultlineView.FixedVersions` — the AI grounding — so an apk version can ride into a Rocky
  recommendation or plan as "the published fix": the AI-GROUND-1 failure class returning through
  a new door.
  **Fix shape (a domain-model change — design before code):** `FixedVersion` gains the source
  ecosystem (the feed knows it: redhat=rpm, alpine=apk, NVD/OSV per record); `FixesFor` filters
  by the asking component's ecosystem; NEVRA versions normalize through ONE path (name always
  stripped); stream-scoping for display can reuse `RPMReleaseMajor`. Store codec + event schema
  are additive-optional on v1.
  **Interim operational note:** on an estate with no Alpine SBOMs the Alpine feed currently adds
  only mis-attributable bounds — `THEMIS_ALPINE_ENABLED=0` is the honest setting there until
  this lands or Alpine evidence exists. **Dep:** none. **Scope:** MEDIUM.

- [x] **AI-TIMEOUT-1 — `THEMIS_LLM_TIMEOUT` was inert above 60s, so every slow model reported
  `provider_error`.** _(**Measured** on the VM 2026-08-07; **fixed** the same session.)_
  Three `recommend_position` calls aborted at **59.995s / 59.991s / 59.989s** with
  `reason: "provider_error"` while the Intelligence process had `THEMIS_LLM_TIMEOUT=300s` set. An
  earlier call the same day had *succeeded* in 48.9s, so the model worked — it had simply grown past
  60s.
  **Cause:** two independent deadlines on one invocation. `cmd/intelligence/main.go` applied
  `THEMIS_LLM_TIMEOUT` to the provider **HTTP client**, but `wiring.Wire` built `GatewayConfig`
  **without** `ProviderTimeout`, so the Gateway fell back to the hard-coded `defaultProviderTimeout
  = 60s`. The shorter deadline always wins, so the documented knob could only ever be *lowered*.
  CLAUDE.md's stated remedy ("raise it for a slower/larger local model") therefore did nothing.
  **Fix:** `wiring.Config` gains `ProviderTimeout`, threaded from the same `cfg.llmTimeout` that
  builds the HTTP client. Guarded by `TestWireHonoursTheConfiguredProviderTimeout` — verified to FAIL
  (2.00s elapsed vs a 150ms configured deadline) with the field unwired.
  **Surfaced by:** the `--ai` path of `scripts/release-posture.sh` returning 204 for every Finding.
  **INSUFFICIENT — a THIRD deadline was found on re-test (same session).** With both the HTTP client
  and the Gateway deadline at 300s, calls STILL died at 59.994s / 59.992s. `cmd/governance/main.go`
  built the Intelligence client with a **hard-coded `60 * time.Second` and no env var at all**. When
  it fires, Governance cancels the request, the Gateway sees its context cancelled mid-provider-call,
  and logs `provider_error` — so the Intelligence log line was Intelligence *observing Governance
  hang up*, not an Intelligence fault. Added `THEMIS_INTELLIGENCE_TIMEOUT` (default 60s, unchanged
  behaviour) and documented in `deploy/node.env.example` that **three** deadlines govern one
  recommendation and the shortest decides — raising one alone changes nothing.
  **Left open (see AI-204-1):** the 204 collapses *disabled*, *unreachable* and *declined* into one
  status, which is why this looked like the AI declining rather than a timeout.

- [x] **AI-GROUND-1 — the AI is grounded on the cross-package fix union KN-FIX-1 removed from the
  display, and reasons from another package's version.** ✅ **CLOSED 2026-08-07.** _(**Measured** on the VM 2026-08-07 — a real
  `recommend_position` on `CVE-2007-4559` / `python3-ply 3.9-9.el8`.)_
  The model returned `affected` at **confidence 0.99** with this reasoning: *"The fixed versions for
  this vulnerability are `0:0.1.7-16.module+el8.9.0+1418+f0d66789` and `0:0.10.1-2.module+…`… Since
  the component version (3.9-9.el8) falls within the affected range (<`0:0.1.7-16…`), it is confirmed
  to be vulnerable."* Neither version belongs to `python-ply`. They come from the **flat
  `fixed_versions` union** across every package the CVE touches — precisely the hazard KN-FIX-1
  fixed for the posture view and did **not** fix here.
  **Cause:** `readapi`'s assessment DTO carries `fixed_versions []string` and has no `fixes` field, so
  Governance's `FindingAssessment` projection — the Gateway's ONLY business read (T10) — ships the
  union. The attributed data exists on the card and never reaches the model.
  **Second consequence, same root: prompt bloat.** The assessment measured **9,788 bytes** carrying
  **95 affected ranges + 94 fix versions**, nearly all irrelevant to this component. Inference for one
  Finding went from **48.9s → ~100s** the same day, which is what pushed it past the 60s ceiling in
  AI-TIMEOUT-1. Improving the knowledge base **degraded** the AI seam, because the projection hands
  the Knowledge view over wholesale and nothing makes card size visible as an Intelligence cost.
  **Fix:** carry `fixes` (package-attributed) into the projection and **select** only the entries
  matching the Finding's component before rendering — 94 entries become ~3. That is EDR-TRUST-01 **T9
  (Selection)** applied to grounding: choosing what evidence to put in front of the model is a design
  decision, and "pass everything we hold" is a default that stops working as the data improves.
  It fixes the correctness bug and the latency together.
  **Note the constitutional layer held:** the output was recorded as `evidence=inferred`, barred from
  auto-accept by T4, and TRUST-8 flagged `[UNVERIFIED MENTIONS]` for a release UUID the model invented.
  A wrong answer stayed advisory — but a human reading a 0.99-confidence rationale citing a real-looking
  version string is being actively misled. **Dep:** KN-FIX-1 (landed). **Scope:** MEDIUM. **P1** — this
  is the AI seam producing confidently wrong security advice.
  **✅ FIX (2026-08-07):** `source` now rides end-to-end — `knowledge.component_matched.v1` carries it
  (additive/omitempty; it was already on the inventory component and was being dropped at the event
  boundary), Governance persists it (`000006_component_source`), and `GetFindingAssessment` **selects**
  the card's fixes down to the ones published for the Finding's own components before the projection
  leaves Governance. Matching runs over `MatchedComponent.FixKeys()` — source package, then
  `namespace:name` (Maven's groupId:artifactId), then bare name — because one component has several
  names across naming authorities.
  **Honest-absence contract:** when nothing matches, the fix list is left EMPTY and
  `unattributed_fixes` reports the count. The prompt states it explicitly ("the record lists N fix
  version(s), but for OTHER packages … do NOT compare this component's version against them"), so an
  empty list cannot be read as "no fix exists" and the model is steered to `insufficient` rather than
  to a confident wrong answer. Saying less beats saying something wrong when the output is a security
  decision.
  Guarded by `TestGetFindingAssessment_{SelectsOnlyThisComponentsFixes,MatchesMavenByNamespace,
  ReportsRatherThanGuessesWhenNothingMatches}` + `TestMatchedComponentFixKeys` — all verified to FAIL
  against the pass-the-union behaviour, reproducing the VM defect in the failure message.
  **Also closes DASH-3** (the resolved fix is now on the Governance read surface: `fixes` +
  `unattributed_fixes` on the assessment), and cuts the prompt from 94 fix versions to the handful
  that apply, which is the latency half of AI-TIMEOUT-1.
  **✅ VM-VERIFIED 2026-08-07** on the same Finding that produced the defect. The assessment now
  returns **6** fix versions — 3 attributed to `python-ply`, 3 to `PyYAML`, the two source packages
  of this Finding's `python3-ply` + `python3-pyyaml` components — with **177 withheld** as
  `unattributed_fixes`. 6 + 177 = 183, exactly the card's attributed total measured independently,
  so the selection drops nothing and invents nothing. The re-run recommendation cites
  `0:3.11-10.module+el8…` and `0:5.4.1-1.module+el8…` instead of Cython's `0:0.1.7-16`: same
  `affected` verdict, now reached from the right evidence rather than by coincidence.
  **Still open, unrelated to this fix:** TRUST-8 flagged `[UNVERIFIED MENTIONS]` on both runs — this
  model reliably fabricates a UUID-shaped token when narrating, even with the real release id in the
  prompt. The guardrail catches it every time; the observation belongs to G-AI-2 (narrative quality),
  and it argues that a UI must render the stance and cited versions as DATA and the reasoning as
  commentary — never let an operator copy an identifier out of the prose.
  Note the division of labour: TRUST-8 could **not** have caught the original defect, because the
  versions cited were real strings present in the grounding — just from other packages. Grounding
  verification asks "were you given this identifier", not "does it mean what you think". Only the
  selection fix could close that gap; guardrail and data quality are complementary.

- [x] **PLAN-1 — a merged plan step can list 33 packages inline, and the step becomes unreadable.**
  ✅ **CLOSED 2026-08-07.** The prompt renders the first three package names plus `+N more`, and the
  step states how many packages it really covers. The collapse was right; only the rendering needed
  bounding — the same lesson as the FIX column.
  _(**Measured** on the VM 2026-08-07, first working `plan_remediation@v1` run, step 8.)_
  The sibling merge (KN-MODULE-1 / same-CVE-set collapse) worked — arguably too well. One step read:
  `upgrade perl-Carp, perl-Data-Dumper, perl-Digest, … perl-threads-shared – closes 165 findings`,
  wrapping over five terminal lines with 33 package names. The COLLAPSE is right (it is one
  `dnf module update`); the RENDERING is not. It is also the largest step in the plan by a factor of
  two and the hardest to read, which is the wrong way round.
  **Fix:** cap the rendered list (`perl-Carp, perl-Data-Dumper, perl-Digest +30 more`) in the prompt
  template AND in the CLI, and say what the step actually is — "one perl module-stream update".
  The data is fine; only the presentation needs bounding, exactly as the FIX column did.
  **Dep:** none. **Scope:** SMALL.

- [x] **PLAN-2 — plan ordering is triage-ordering, and a remediation plan may want impact-ordering.**
  ✅ **DECIDED 2026-08-07: order by RISK REMOVED** — the SUM of residual priorities an action
  closes — with the single worst item, findings-closed and package name as tiebreaks.
  Neither obvious answer was right. `TopPriority` is triage order ("what is most dangerous?") and
  put a step closing 6 findings above one closing 165; count alone ignores severity and promotes a
  pile of trivia. The sum answers what a PLAN is actually asked — "what does this buy me?" — by
  weighting each finding by how much of a problem it still is, and it degenerates to triage order
  when every action closes exactly one finding. Merging now happens BEFORE ordering, since a merged
  step's risk is the sum of its members'.
  _(**Measured** on the same run; **design question**, not a defect.)_ `PlanActions` sorts by
  `TopPriority` desc, then by findings-closed. The result: step 8 closes **165** findings, step 14
  (`openssh`) closes **40**, while step 3 (`samba`) closes **6** and sits near the top. Every number
  is correct and the order follows the stated rule — but for someone SCHEDULING work, "one update
  closes 165" is a stronger argument than "this one is 2 points more severe".
  Triage order (what is most dangerous?) and plan order (what buys the most?) are genuinely
  different questions, and `residual_priority` answers the first. Options: (a) leave it and document
  that a plan inherits triage order; (b) sort the plan by an impact score such as
  `TopPriority × log(findings)`; (c) offer both and let the caller pick. **Do not** change it
  silently — the ordering is currently reproducible and explainable, which is worth more than being
  marginally better ordered.
  **Dep:** none. **Scope:** SMALL for (b); the DECISION is the work, and it belongs in an EDR.

- [x] **PLAN-3 — the plan says what to upgrade but not what to upgrade TO.**
  ✅ **CLOSED 2026-08-07 together with DASH-2.** `knowledge.faultline_enriched.v1` now carries the
  package-attributed `Fixes`; Governance selects the ones matching each Finding's own components and
  stamps them (migration `000008`), and they ride the posture row. The selection logic is SHARED
  with the read-time projection (`selectFixesFor`), because two implementations of "which fix is
  mine?" would eventually disagree — and the disagreement would show up as a dashboard and a plan
  recommending different versions for the same component.
  _(Known and accepted at build time; recorded so it is not mistaken for an oversight.)_
  `PostureEntry` carries components but not their selected fix versions, so a step reads
  `upgrade PyYAML` rather than `upgrade PyYAML to 0:5.4.1-1.module+el8.10.0+1582`. The per-Finding
  assessment HAS the answer (AI-GROUND-1 selected it); the release-scoped projection does not.
  Deliberate: carrying it needs a new field on `knowledge.faultline_enriched.v1`, a Governance
  migration, and a stamping path — the same shape as `base_score` (C6/BUG-3). Until then the exact
  version is one drill-down away.
  **Fix:** stamp the selected fixes onto the Finding at enrichment, exactly as `base_score` is, then
  surface them on `PostureEntry`. **Dep:** AI-GROUND-1 (landed). **Scope:** MEDIUM.

- [x] **🔴 RANGE-PARSE-1 (P1) — an UNPARSEABLE affected range read as "provably not affected", and
  the shipped policy auto-accepted it.** _(Found 2026-08-07 writing the TRUST-9 demonstration; fixed
  the same hour.)_
  `AffectedRange.hasUsableConstraint` accepted any non-empty token that was not the `none` sentinel,
  so a malformed range — `"garbage"`, `"affected"`, a stray prose fragment from a feed — counted as
  a usable constraint. `matchConstraint` then returned false for it (no grammar rule matched),
  `Matches` returned false, and `Applicability` read a failed match as **`RangeOutOfRange`**.
  **The full chain:** malformed range → `ProvablyOutOfRange` true → Governance raises a system
  `not_affected` proposal on `observed` evidence → the shipped **D15 `auto-not-affected-observed`
  policy AUTO-ACCEPTS it** → `residual_priority` drops to 0 → the Finding leaves the queue. A feed
  emitting one bad range would have silently suppressed a live vulnerability, with a governed
  Position recording it as decided.
  **What makes it the worst class:** every layer behaved as written. The range rule is documented as
  "certain in one direction only… a parse gap must never drop a real vulnerability", and
  `ProvablyOutOfRange` implements that correctly — it defers unless the verdict is `OutOfRange`. The
  defect was one layer below, in what COUNTS as a verdict.
  **Fix:** `parsableConstraint` mirrors `matchConstraint`'s cases, so the two agree on what the
  grammar accepts — a token one accepts and the other rejects is precisely how a parse gap becomes a
  verdict. A bare token must additionally LOOK like a version (starts with a digit, no whitespace);
  the cost of rejecting an odd-but-real version is a deferred verdict, the cost of accepting a
  non-version is a silent suppression.
  Guarded by `TestApplicability_UnparseableRangeIsUndecidable` (7 malformed shapes),
  `..._RealRangesStayDecidable` (the narrowing must not trade a silent suppression for a silent
  deferral) and `..._MixedGroupUsesTheParsableComparator`.
  **How it was found is the point:** by writing the test TRUST-9 asked for. The assertion was
  "an undecidable range must suppress nothing" — and it suppressed.

- [x] **PLAN-4 — `plan_remediation` has no real-model e2e; three live refusals were found by hand.**
  ✅ **CLOSED 2026-08-07 — and it was worse than filed.** The repository's ONLY real-model test
  (`llm_e2e_test.go`) had **not compiled since the T10 refactor** renamed the read seam
  (`readapi.NewFindingClient` → `NewAssessmentClient`). `make e2e-llm` was dead code, silently, for
  days — because no gate ever set `-tags=llm`, so nothing type-checked it.
  **Fix, in two parts:** (1) the test is rewritten against the current seam and now covers BOTH
  capabilities, with `plan_remediation` fixtured on a MERGED step whose heading renders as a package
  list — the exact citation form refused live. A 204 whose reason is `business_invalid` now FAILS
  the test: a declined recommendation is the seam working, but an ungrounded citation means our
  prompt and our gate disagree. (2) `make vet-tags` type-checks `integration`, `e2e`, `llm` and
  `postgres`, and is wired into `check` and `check-ci`, so no tagged file can rot unnoticed again.
  _(Surfaced 2026-08-07 building the capability.)_ Every test uses a fake provider, and all of them
  passed while the live capability was refused **three times running** — `PyYAML (rpm)`, then the
  bare heading, then `httpd, mod_http2`. Each was a disagreement between the PROMPT and the
  GROUNDING GATE, which have no compiler between them and cannot be reconciled by a fake that
  returns whatever the test author already believes.
  `make e2e-llm` exists for exactly this (`//go:build llm`, opt-in, skips when unreachable) and does
  not cover the release path. **Fix:** add a `plan_remediation` case to it that asserts the outcome
  is OK rather than `business_invalid` — a regression here is invisible to `make check-ci` by
  construction. **Dep:** none. **Scope:** SMALL. **Priority: this is the only class of defect in the
  AI seam that the normal gate cannot see.**

- [x] **AI-204-1 — a 204 from `/recommend` cannot be told apart from a correct refusal.** ✅ **CLOSED 2026-08-07.**
  **Fix:** the reason rides the 204 as `X-Themis-AI-Reason` (headers, not a body — 204 means no content, and a payload would be non-conforming; an older caller that ignores it behaves exactly as before). Intelligence sets its `Outcome.Reason`/`Detail`; Governance's client reads it and its own `/recommend` re-emits one of `disabled` · `unreachable` · `declined` · `business_verification_failed` · the Gateway's own reason. `release-posture.sh` now prints what to DO about each instead of one guess covering all three.
  _(Surfaced 2026-08-07 diagnosing AI-TIMEOUT-1.)_ `recommend` returns a bare 204 for at least three
  causes with opposite responses: AI disabled (config gap), provider unreachable/timed out (outage),
  and the model correctly declining for want of grounding (`insufficient` — the Δ2 fourth outcome,
  and the seam working as designed). The script's own message admits it: *"AI disabled, unreachable,
  or it declined"*. Diagnosing the timeout above required reading the Intelligence node's log.
  TRUST-6 already closed the producer half — `app.Outcome.Detail` carries the reason inside the
  Gateway (the log line shows `reason: "provider_error"`) — but Governance's `/recommend` discards it
  at the last hop. **Fix:** carry the reason outward, additively (a response body on the 204, or a
  distinct status for the config/outage cases). A correct refusal is the AI's most valuable
  behaviour and currently looks identical to an outage. **Dep:** none. **Scope:** SMALL.

- [x] **KN-FIX-2 — existing cards never gain package attribution; they heal only on re-upload.** ✅ **CLOSED 2026-08-07 (option a).**
  _(**Measured** on the VM 2026-08-07: `CVE-2021-44228`'s card reports `with_pkg: 0` of 80 fixes,
  while `CVE-2007-4559` — whose release was re-uploaded after KN-FIX-1 — reports 89.)_
  Only **OSV** and **Red Hat** attribute a fix to a package; **NVD** (CPE-keyed) and the scanner ACL
  genuinely cannot, and correctly record `unattributedFixes`. OSV is queried during **correlation**,
  which runs on **upload** — so a card whose releases are not re-uploaded keeps its pre-KN-FIX-1 flat
  list indefinitely, and its FIX column stays `N unattributed` forever. Meanwhile the per-CVE NVD
  backfill keeps appending *unattributed* fixes to it, so the ratio gets worse, not better.
  Consequence: on a real deployment the feature appears not to work for most of the estate, because
  most releases are uploaded once. Content-addressing makes it worse — a re-upload of identical bytes
  **dedups** and does not re-correlate, so "just upload it again" is not a workaround without changing
  the SBOM.
  **Options:** (a) a one-off re-attribution sweep that re-queries OSV per carded component and folds
  the attributed proposals (append-only, so it is additive and safe to re-run); (b) accept and document
  that attribution arrives with the next genuinely-new SBOM. **(a) is preferable** — it is the same
  shape as the existing `BackfillService` and needs no new concepts. **Dep:** KN-FIX-1 (landed).
  **Scope:** MEDIUM.
  **Fix (a):** `app.ReattributeService` + `THEMIS_REATTRIBUTE_INTERVAL` (default 6h), riding the
  same always-on OSV discovery fan-out correlation uses — one path to the feeds, not two. Migration
  `000005_match_component_detail` persists the full matched component (name/version/ecosystem/source)
  on `faultline_matches`, because a PURL alone cannot be re-queried: a feed lookup needs the
  ecosystem and, for distro packages, the source name. Rows predating it are SKIPPED rather than
  guessed at. The sweep folds only proposals for the CVE it asked about — folding everything a
  component query returns would turn re-attribution into an undeclared discovery pass. Bounded per
  run, per-card failures skipped, self-terminating (once everything is attributed it finds nothing
  and writes nothing), and idempotent for free now that the aggregate drops verbatim restatements.
  **⚠ CAVEAT, VM-observed 2026-08-07:** the first sweep reported `folded: 0`, correctly — every
  EXISTING `faultline_matches` row predates migration 000005 and carries a PURL alone, which cannot
  be re-queried, so all of them are skipped. The sweep therefore does nothing for the current estate
  and only starts acting on matches recorded from now on. That is the intended safe behaviour (a
  component we cannot re-query is one we must not guess about), but it means **KN-FIX-2 is not yet
  delivering value on this deployment** — it will as releases are re-correlated. A backfill that
  reconstructs the missing component detail from Evidence's inventory would close the gap sooner;
  not attempted, because it is a second, different sweep.

- [x] **KN-EPSS-BAND-1 — a CVE with 99% exploitation probability is labelled `informational`.** ✅ **CLOSED 2026-08-07.**
  **✅ VM-VERIFIED 2026-08-07:** `CVE-2021-45105` (CVSS 5.9, EPSS 99.999%) and `CVE-2021-44832`
  (CVSS 6.6, EPSS 97.9%) now band **`high`**; `CVE-2021-44228` (CVSS 10) and `CVE-2021-45046`
  (CVSS 9) stay **`critical`**, untouched — exactly the scope intended. Note the RANKING is
  unchanged: `residual_priority` comes from `Score()`, whose EPSS lift is still capped at 30% of the
  severity baseline, so 45105 remains at 52. That is option (b), deliberately still open.
  **Fix (option a, the minimum):** EPSS gets its own band arm mirroring KEV's — `EPSS >= 0.9 && CVSS < 7 → high`. Scoped tightly to what was MISLABELLED: the 0.9 floor is far above `elevated`'s 0.5 (this arm is for "already being exploited", not elevated probability), and `< 7` leaves every CVE the `elevated` rule already handles exactly where it was. A first attempt used `< 9` and silently re-banded high-CVSS cases that already had a sensible label — caught by its own test, then narrowed. KEV still wins: it is a CONFIRMED exploitation record where EPSS is a prediction. **Option (b) — raising the score's 30% lift cap so likelihood can overtake severity — remains open and needs an EDR decision.**
  _(**Measured** on the VM 2026-08-07 — release `ee006ff7`, posture rows 2 and 3 — with the formula
  **read from code** in `internal/knowledge/domain/priority.go`.)_
  Observed: `CVE-2021-45105` (log4j, CVSS 5.9, **EPSS 99%**) scores **52**, band `informational`, and
  ranks **below** `CVE-2026-34480` (**EPSS 0%**) at **70**. The arithmetic checks out — `40 + 40×0.99×0.3
  = 52` vs `70 + 70×0×0.3 = 70` — so this is the design working as written, not a computation bug.
  Two distinct consequences, and only the first is clearly wrong:
  1. **The label is a false statement.** `Priority()` admits EPSS only through the `elevated` rule,
     which also demands `effectiveCVSS() >= 7`. A medium-CVSS CVE therefore falls to the `default`
     arm and is reported as `informational` **however certain its exploitation is**. "Informational"
     is a claim, not a neutral fallback: it tells an operator this needs no action, about a
     vulnerability EPSS rates near-certain to be attacked. Compare KEV, which *does* get its own arm
     (`v.KEV && c < 9 → high`) precisely so a low-CVSS KEV entry cannot be buried.
  2. **EPSS can never promote across a severity tier.** The lift is `base × EPSS × 0.3`, so medium
     (40) caps at 52 and can never reach high (70). Severity strictly dominates likelihood. That is a
     defensible position — impact over probability — but it is currently implicit, and it means the
     ranking answers "how bad if exploited" rather than the "what do I fix first" the posture view
     claims to answer.
  **Options:** (a) give EPSS its own band arm mirroring KEV's (`EPSS >= 0.9 → high`, say), which fixes
  the false label without touching the score; (b) raise the lift cap so a near-certain medium can
  overtake a dormant high; (c) keep both and document severity-dominance explicitly in the EDR so the
  band is read correctly. **(a) is the minimum** — the label is wrong today regardless of the ranking
  philosophy. **Dep:** none. **Scope:** SMALL for (a); (b) needs an EDR decision (D-series, Knowledge).

- [x] **KN-PROPOSAL-BLOAT-1 — the EPSS/KEV sweep re-folds byte-identical signals, so 99.2% of the
  proposal log records no new information.** ✅ **CLOSED 2026-08-07.** _(**Measured** on the VM 2026-08-07.)_
  `faultline_proposals` holds **28,128** rows from source `epsskev` across **239** cards — ~118 per
  card — of which only **221 payloads are distinct**. Every sweep appends a fresh Proposal per card
  whether or not EPSS moved, so a card typically carries one real observation and ~117 copies of it.
  Cross-check: `nvd` (2,636) and `osv` (3,609) are ~11–15 per card, so this is specific to the
  exploit-signal path, not to folding in general.
  **This is not an argument against append-only** (Domain Invariant 1 — the audit trail is why the
  reconciled view is defensible). It is the difference between recording *history* and recording the
  same fact 118 times: an EPSS move 0.27→0.29 is a new observation and belongs in the log; ten polls
  reporting 0.27 are one observation and nine timestamps.
  **Why it matters beyond disk:** reconciliation walks every Proposal on a card to recompute the view,
  so per-card proposal count is on the hot path of every fold, and it grows monotonically forever. A
  118× multiplier is invisible at 239 cards and decides p99 at 50,000.
  **Fix:** fold only when the signal differs from the card's latest Proposal from that source (an
  observed-at refresh on the existing row, or simply no-op). Keep the first observation of every
  distinct value — that is the audit trail. **Dep:** none. **Scope:** MEDIUM, Knowledge-local.
  **Fix:** `Faultline.FoldProposal` drops a Proposal whose (source, kind, payload) matches the card's
  LATEST from that source. Comparing against the latest — not against any historical proposal — is
  what preserves a value that changes and changes back (0.27 → 0.29 → 0.27 is three observations);
  observed-at is deliberately excluded from the comparison, since it is the field that differs on
  every poll. Corroboration from a *different* source, and a different *kind* from the same source,
  are never collapsed. Anything that cannot be proven identical compares as different — a dropped
  observation is unrecoverable, a duplicate is merely waste.
  **Two tests asserted the old behaviour** ("duplicate not recorded", "both proposals are recorded
  (append-only)") and were rewritten; that reading is what produced the 118× multiplier.
  **Cost, taken deliberately:** a card no longer records "we re-confirmed this at T2".
  `feed_health.last_success_at` answers it per source, and since feeds are relevance-bounded (D5 — a
  sweep visits every carded CVE together) per-source is a faithful proxy for per-card.
  **✅ VM-VERIFIED 2026-08-07:** the 18:12 sweep ran on the new binary and `faultline_proposals`
  stayed at **31,196** where the old behaviour would have added ~236. The 28k existing rows remain —
  append-only means never deleting — so what is fixed is the *growth*, not the history.
  **A follow-on defect, found by that same check and fixed in the same commit:** the sweep still
  logged `folded: 236` while writing zero rows, because it counted cards VISITED. A stalled feed and
  a fully-caught-up one reported the same number — the precise failure mode NVD-WATCH-1 exists to
  prevent. `FoldResult` gained `Recorded`, `FaultlineService.FoldProposal` now returns it, and the
  three sweeps (signals, NVD backfill, re-attribution) count only what was actually appended.
  **✅ BOTH VM-VERIFIED 2026-08-07 19:15.** Over ~45 minutes on the new binary: the NVD backfill
  logged `folded: 0` on **eight consecutive** sweeps (it reported `198` every run before), and the
  exploit-signal sweep logged `folded: 5`. `faultline_proposals` moved **31,196 → 31,201** — the row
  count matches the reported folds exactly, where the old behaviour would have written 236 rows to
  carry those same 5 facts (a 47× reduction on this estate).
  The `0` is the point: that line was previously a constant, which reads as health and carries no
  signal — a broken parser, a dead feed and a settled estate all printed `198`. It now makes a real
  claim ("nothing upstream changed") and will move the moment that stops being true.

- [x] **KN-MODULE-1 — RHEL/Rocky *module stream* advisories inflate the affected set, and the posture
  view now makes it visible.** ✅ **CLOSED 2026-08-07 (option b).** _(Measured on the VM 2026-08-07, top-15 posture for release 20.3.0.)_
  Five of the top fifteen rows pin **Python interpreter** CVEs onto unrelated packages:
  `CVE-2019-9636` (urlsplit) and `CVE-2007-4559` (tarfile) appear against `python3-pyyaml` and
  `python3-ply`, with fixes of `PyYAML 3.12-16` / `python-ply 3.11-10`. Those fix versions are **not**
  a correlation error on our side — OSV genuinely attributes them, because a RHSA for a module stream
  (`python38`, `python39`) lists *every* RPM rebuilt in that stream as affected-and-fixed, not only the
  package carrying the flaw. Our ACL records what the feed published; the feed publishes the module.
  Consequence: an operator reading the top of the list is told to upgrade `python3-ply` for a tarfile
  bug. The instruction is not wrong (upgrading the module does resolve it) but the attribution is
  misleading, and it pushes genuinely package-specific findings down the ranking.
  **Options:** (a) detect the `module+elX` marker in the fixed version and label the row as a
  stream-level rebuild rather than a package fix; (b) prefer a non-module fix when the card holds both
  (rows 11/13 show `5.3.1-1` — the real PyYAML fix — alongside stream rebuilds); (c) leave as-is and
  document. **Do not** drop module entries: they are the correct remediation on a modular system.
  **Dep:** none. **Scope:** MEDIUM — display/precedence, no new truth. Revisit with DASH-3.
  **Fix (b):** `value.IsRPMModuleStream` detects the `.module+el` marker, and `EnterpriseView.FixesFor`
  returns package-specific fixes BEFORE module-stream rebuilds. Nothing is dropped — upgrading the
  module IS correct remediation on a modular system, and the fixed-verdict engine needs the full set
  to reason about backports — only the ORDER changes, which is what a consumer showing the first N
  reads. Option (a), labelling the row as a stream rebuild in the UI, is now one call away.
  **Fix:** `GET /products/{id}/posture` and/or `GET /projects/{id}/posture` aggregating across releases,
  plus `priority` on `PostureEntry`. **Dep:** DASH-1 for the traversal. **Scope:** MEDIUM.

- [x] **🔴 KN-FIX-1 (HIGH) — Fixed versions carry no package, so a card's fix list is a cross-package
  union — and `RPMFixedByStream` can silently DROP a real match because of it.**
  ✅ **THE DANGEROUS HALF FIXED 2026-08-07 — and by one line, not the domain change this entry proposed.**
  `ApplyCorrelation` already holds `item.Proposal`: the Proposal that discovered *this* component. It now
  passes that Proposal's own `FixedVersions` to the verdict instead of the card's reconciled union. OSV is
  queried **by package**, so its record is about this component and nothing else — the association the
  domain model lacks is already present at the call site, and reading it there is *more* correct than
  filtering a union would be.
  It also narrows the verdict: a fix known only to another source is no longer applied at correlation time.
  That is the safe direction — keeping a match costs triage time, dropping one costs a breach.
  **Reproduced before fixing, which mattered.** The first regression test PASSED against the broken code:
  the card accumulates the union *as items fold*, so the trap only springs for a component processed AFTER
  another package's fix has landed. With the order corrected the old behaviour records **1 match where 2
  are due** — the glibc finding genuinely disappears. That ordering dependence is also why it was never
  seen in production: it needs a multi-package RPM card whose lower-versioned fix folds first.
  **🔬 MEASURED ON THE VM, 2026-08-07 — the bug WAS firing.** A/B on identical SBOM content: the release
  correlated by the old code recorded **537** matches, the one correlated by the fixed code **568** —
  **+31 restored, 0 lost** (both diffs run). The restored set names the mechanism exactly: 29 of 31 are
  `python3-ply@3.9-9.el8` and `python3-pyyaml@3.12-12.el8`, whose version numbers sit ABOVE the CPython
  fix versions (`0:3.6.8-…el8`) sharing their cards — so `3.9 >= 3.6.8` satisfied the verdict using a
  different package's fix and the occurrence vanished. `libtiff@4.0.9-36.el8_10` accounts for the other 2.
  **Exposure across the estate:** **165 of 239 cards** carry more than one fix version, the worst holding
  **303**; at least 10 carry 4 fixes with a parseable `.elN` marker, which is the comparable — and
  therefore dangerous — subset.
  The +31 is a **lower bound**: the fixed run also had a more NVD-enriched card set, and richer cards carry
  more fix versions, which under the old code would have dropped *more*.
  **✅ FULLY CLOSED 2026-08-07 — the model now carries the package.** The dashboard made the case: **16 of
  the top 20 rows** could not say what to upgrade to, showing "94 candidates", "302 candidates". A tool that
  ranks problems and cannot answer *what do I do about it* is half a tool, so the remaining half was not
  cosmetic after all.
  `domain.FixedVersion{Package, Version}` replaces the bare string; `VulnFacts.Fixes` and
  `EnterpriseView.Fixes` carry it, with `FixedVersions` retained as the derived flat union for
  "is a fix published?". **`EnterpriseView.FixesFor(pkg)` is the only way to decide about a component** —
  exact match, and an unattributed fix (Package "") is deliberately NOT a wildcard, because "the source did
  not say which package" is not evidence about any of them.
  **The loss began at the ACL, not the model.** `osvAffected` decoded `ranges` and threw away
  `package.name` — OSV states the association and Themis discarded it at parse time. OSV now pairs each fix
  with its package; Red Hat extracts it from the NEVRA (`value.RPMPackageName`); NVD's CPE data and scanner
  reports state fixes without a package and are recorded **unattributed** rather than guessed.
  Correlation's fixed-verdict now reads `FixesFor(componentPackage(...))`, which is *better* than the
  interim fix: it aggregates every source's fix for that package instead of only the discovering one.
  Migration-free — the codec decodes a pre-KN-FIX-1 card's flat list as unattributed fixes, so old rows
  load and degrade to "published, package unknown" rather than to a wrong decision. `fixes` is additive on
  the v1 API, omitted when empty. `EnterpriseView.FixedVersions` is still a
  package-less union, so `GET /faultlines/{id}`, the FindingAssessment projection and any dashboard cannot
  say "the fix for YOUR component" — `scripts/release-posture.sh` now prints a candidate count rather than
  a confident wrong version. Fixing that properly still wants `VulnFacts` to carry
  `[]FixedVersion{Package, Version}` plus an additive `knowledge.faultline_enriched.v1` field, which is a
  domain model change and a decision. **No longer a correctness risk** — only a presentation gap.
  Original report follows.
  _(Found 2026-08-07 building the release-posture view, from wrong output on live data.)_
  `domain.VulnFacts.FixedVersions` is a bare `[]string`. `Reconcile` unions them across every Proposal on
  the card (`fixSet`, reconcile.go), and OSV emits one Proposal per (CVE, package) — so a CVE affecting N
  packages produces ONE list of N unrelated fix versions with nothing saying which belongs to which.
  **Visible symptom (live, release 47cc2043):** the posture rendered `python3-ply@3.9-9.el8 → fix
  0:0.1.7-16.module+el8.9.0`, `python3-pyyaml@3.12 → 0:0.29.14-4.module`, `perl-Carp@1.42-396 → 0:0.001-10`,
  and `jetty-http@12.0.27 → 10.0.28` (a downgrade). Every one is another package's fix.
  **The dangerous consequence is not display.** `correlate.go:150` calls
  `value.RPMFixedByStream(ecosystem, installedVersion, f.View().FixedVersions)` and **drops the match** when
  it returns true. That function walks the flat list and returns true if the installed version is `>=` ANY
  fix sharing its EL major — with no check that the fix is for the same package. Worked example: a card
  affecting both `glibc` and `perl-Carp` carries `["0:2.28-251.el8_10.38", "0:1.42-397.el8"]`; the installed
  `glibc 2.28-251.el8_10.31` compares against perl-Carp's `1.42-397.el8`, `2.28 >= 1.42`, and the **glibc
  finding is silently dropped** although the installed build is vulnerable.
  That is a **false negative in vulnerability detection** — the defect class the codebase elsewhere calls
  "the most dangerous". `RPMFixedByStream`'s own doc claims it is "conservative (any uncertainty stays
  affected), so it never hides a live vulnerability"; that claim holds for a single-package fix list and is
  **untrue** for a cross-package union.
  **Not yet observed firing** — the live cards that would show it happen not to carry a lower-versioned
  same-stream fix from another package. The mechanism is present regardless, and it fails silently: a
  dropped match produces no Finding, no log line and no metric.
  **Fix:** associate the package with the fix. `VulnFacts` gains per-package fixed versions (e.g.
  `[]FixedVersion{Package, Version}`), the OSV/NVD/Red Hat ACLs populate it (OSV already knows the package —
  it is queried by package), `Reconcile` keys the set by package, and `RPMFixedByStream` filters to the
  component's own package before comparing. This is a **domain model change** plus an additive change to
  `knowledge.faultline_enriched.v1`, so it needs a decision before code.
  **Interim mitigation to consider:** gate the RPM fixed-verdict on the card having exactly one distinct
  fixed version, or disable it (`correlate.go:150`) until the association exists. Dropping a true match is
  strictly worse than keeping a false one — a redundant Finding costs triage time, a missing one costs a
  breach. **Where it plugs in:** `internal/knowledge/domain/{proposal,reconcile}.go`,
  `internal/knowledge/adapters/feed/*`, `internal/kernel/value/rpmstream.go`,
  `internal/knowledge/app/correlate.go`. **Scope:** HIGH.

- [x] **GOV-14b — Disposition re-evaluation watcher: "decided for now, watched for change".**
  ✅ **CLOSED 2026-08-07 — the safety net under a live suppression mechanism now exists.**
  `residual_priority` zeroed a not_affected / accepted_risk Finding from 2026-08-06, removing it
  from the queue with nothing to bring it back. `domain.DetectDispositionDrift` compares the
  exploitability picture a decision was TAKEN WITH against the picture now, and
  `FindingService.watchDispositions` emits `governance.disposition_stale.v1` on material drift.
  **It never changes the Position** (D6/D11) — it re-opens the QUESTION, so an acceptance does not
  vanish, it EXPIRES when its premise changes.
  **Deterministic rules:** a CVE entering KEV · a newly public exploit · EPSS rising by
  `THEMIS_EPSS_DRIFT_THRESHOLD` (default 0.20, ABSOLUTE — a relative threshold fires constantly in
  the noise near zero, where EPSS is least stable and a re-surfaced Finding least likely to be real).
  **One-directional:** signals getting BETTER never re-open a suppression; re-surfacing a Finding
  for getting safer trains people to ignore the signal.
  **The premise had to be recorded to be compared.** `Finding.signals` is refreshed on every
  enrichment (beside `base_score`, same denormalization and the same reason) and `AcceptProposal`
  snapshots it into `PositionInputs.DecidedWith` — so the human triage path records it exactly as
  the policy path does. Migration `000007_position_signals`. A pre-existing row reads as "decided
  knowing nothing", which is CONSERVATIVE: any positive signal now looks like drift, and a redundant
  review costs attention where a missed one costs a breach.
  _(The second half of GOV-14 / EDR-GOVERNANCE-01 D14; split out 2026-08-06 when the `residual_priority`
  half landed.)_ `residual_priority` zeroes a `not_affected` or `accepted_risk` Finding's triage number —
  which is only **safe** because D14 pairs it with a watcher that re-surfaces the Finding when the premise
  of the decision drifts. Without it, an acceptance is permanent in practice: the Finding leaves the queue
  and nothing brings it back. **That is the live risk today** — the zeroing shipped, the watcher did not.
  **What D14 specifies:** on each `FaultlineEnriched` signal change (or a scheduled sweep), re-test terminal
  dispositions with a **deterministic rule** — a **KEV listing**, **EPSS crossing a configurable threshold**,
  a **newly-public exploit**, or a **reversing vendor VEX**. On material drift, emit a **"disposition-stale"
  completed-fact event** (push, not pull). It **never** auto-changes the Position (D6/D11): it re-opens the
  decision for a human or a governed policy. So an acceptance does not vanish — it **expires** when its
  premise changes. AI is the optional upgrade on the deterministic core: reasoning whether a drift actually
  invalidates the original justification before re-surfacing, and rendering the "why re-surfaced"
  explanation. **Why it was not done with the first half:** it needs a new event type on the Governance
  outbox and a worker, where `residual_priority` was a pure read projection with no new state — different
  size, different risk. **Where it plugs in:** `internal/governance/app` (rule + worker),
  `internal/governance/adapters/store` (the new event), the Knowledge `FaultlineEnriched` consumer that
  already carries the drift signals. **Dep:** none — the EPSS/KEV/exploit signals it needs are already on
  the Faultline and already reach Governance. **Scope:** MEDIUM-HIGH — it is the safety net under a
  suppression mechanism that is already live.

- [x] **KN-WITHDRAW-1 — The CVE-withdrawal path is consumer-only: Knowledge never supersedes a Faultline.**
  ✅ **FIXED 2026-08-07.** `app.CVEFacts` gives the per-CVE port a **third outcome** — facts, absence, or
  **withdrawn** — because collapsing withdrawal into absence is what left rejected CVEs alive: "we have no
  data" leaves the card alone, "this was rejected upstream" retires it. `NVDClient.VulnsForCVE` now reads
  `vulnStatus` (matched on a contained `rejected` token, since NVD has used both "Rejected" and "Rejected
  by CNA"), and `FaultlineService.SupersedeFaultline` closes the producer half of a path whose consumer
  half was already complete.
  **Withdrawal is checked BEFORE facts and short-circuits:** a rejected record may still carry old metrics,
  and folding them would refresh a card that should be retired. Idempotent, since the lifecycle is
  forward-only — a repeated sweep changes nothing and announces nothing.
  **It only works because of NVD-REFRESH-1.** An enrich-once queue would have caught `CVE-2021-20095` (which
  has no NVD Proposal) and missed every card rejected *after* it was enriched. Withdrawal detection is
  exactly as good as the refresh policy, which is why the two shipped together. Original report follows.
  **🔴 LIVE INSTANCE FOUND 2026-08-07.** `CVE-2021-20095` is carded in the VM deployment; NVD reports
  `vulnStatus: "Rejected"`. Nothing reads that field, so the card is alive, its Finding is open, and it will
  demand triage forever. This is no longer hypothetical.
  **The per-CVE sweep (D5a) makes the fix nearly free** — it already fetches each carded CVE's full NVD
  record, `vulnStatus` is in the response, and `Faultline.Supersede()`, the event, its frozen v1 schema and
  Governance's consumer all exist. What is missing is a handful of lines to read the status and call the
  aggregate, plus the trust class TRUST-4 wants on the event (a withdrawal is genuinely Observed).
  **But see NVD-REFRESH-1 below:** the sweep only visits cards with NO NVD proposal, so it would catch this
  one (which has none) and miss any card rejected *after* it was enriched. Withdrawal detection is only as
  good as the refresh policy.

  _(Found 2026-08-07 while investigating TRUST-4.)_ The forward-only lifecycle ends at **Superseded** — "a
  card is never deleted, only superseded" is a stated key invariant — and the *consuming* half is fully
  built: `app.EventFaultlineSuperseded` is registered in the store's topic map as
  `knowledge.faultline_superseded.v1`, the payload has a frozen v1 schema, and Governance's coordinator
  turns it into an `EnrichmentSignal{Withdrawn: true}` that raises a re-evaluation proposal. But
  **`Faultline.Supersede()` is never called outside tests**, so the event is never emitted and none of that
  runs.
  **What is missing is the trigger, not the machinery.** A CVE gets **REJECTED** or **withdrawn** upstream
  (NVD publishes `vulnStatus: "Rejected"`; OSV marks a record withdrawn), and nothing in the feed ACLs reads
  either signal. So a withdrawn CVE keeps its card, keeps its Findings, and keeps demanding triage
  attention forever — the exact case D11 cites as the motivating example for governed auto-accept ("CVE
  withdrawn upstream → auto-accept Not-Affected"), which therefore cannot fire today.
  **Fix:** read the withdrawal signal in the NVD and OSV ACLs, carry it to a `SupersedeFaultline` use case
  that calls `Supersede()` and emits the event, and — per TRUST-4 — put the **evidence trust class on the
  event** at that point, since a withdrawal is genuinely Observed (re-fetch and the CVE is still rejected)
  and Governance currently has to assume it. **Where it plugs in:**
  `internal/knowledge/adapters/feed/{nvd,osv}.go` (detect), `internal/knowledge/app` (a supersede use case),
  `knowledge.faultline_superseded.v1` (additive trust field). **Dep:** none. **Scope:** MEDIUM — a stated
  key invariant with no code path to reach it, and it strands the one auto-accept case the EDRs name.

---

### D. Observability (R1) — remaining signals

- [x] **Metrics (the second R1 signal).** ✅ **DONE 2026-08-07.** `internal/platform/observability` now owns
  a service-scoped Prometheus registry alongside the logger, initialized in `Setup` and served at
  **`/metrics` on all six nodes** — mounted OUTSIDE the authenticated `/api/v1` group, because it is data
  for the platform's own scraper, carries no business content, and gating it would mean handing scrape
  credentials to monitoring.
  **The counters are the ones this session's defects needed**, not a generic starter set. Every gap found
  on 2026-08-06 was a question about a RATE or a TOTAL that logs answer badly — "is this feed enriching
  anything?", "how often is the AI refused, and by which check?" — and you cannot alert on the absence of a
  log line. `themis_feed_polls_total{source,outcome}` makes `truncated` its own series so "healthy" can
  never again mean "saw 5% of the window" (NVD-WATCH-1); `themis_feed_records_total{source,stage}` splits
  **discovered** from **folded**, disambiguating "the feed returned nothing" from "it returned plenty, none
  of it about us"; `themis_ai_invocations_total{capability,reason,produced}` turns TRUST-6 into a dashboard
  question. Plus request rate and latency by **route template** — never the concrete path, since a per-id
  label is unbounded cardinality.
  Every recorder is **nil-safe**, so a unit test that never called `Setup` records nothing rather than
  panicking: instrumentation must never be able to break the code it observes.
  Uses `prometheus/client_golang`, already a chosen dependency (STACK.md) and previously used only in the
  frozen legacy tree — the greenfield had **no metrics at all**. Metric names are exporter-agnostic, so
  moving onto an OTel pipeline later is wiring, not a rename.

- [x] **OTel traces (the third R1 signal), and the OTLP metric/trace exporters.**
  ✅ **CLOSED 2026-08-07.** **Egress decision: Prometheus-SCRAPE for metrics, OTLP for traces** —
  one new dependency (`otlptracehttp`) instead of two, and metrics keep working on a node with no
  collector at all, which is the deployment `INSTALLATION.md` actually documents. A trace has no
  pull model, so it needs egress; a counter does not.
  `Setup` now builds a `TracerProvider` gated on the SAME `THEMIS_OTLP_ENDPOINT` as logs — a
  deployment with somewhere to send logs has somewhere to send traces, and two knobs for one
  collector is a configuration people get wrong in exactly one direction. Both providers are
  flushed on shutdown (chained, not replaced: dropping the log shutdown would have silently lost
  the last batch of logs on every clean exit).
  `RequestLogger` starts a server span per request, **unconditionally** — with no endpoint the
  global provider is a no-op costing nanoseconds, and instrumentation added later never gets added.
  The span carries the **correlation id**, which is what makes traces and logs joinable: a trace
  nobody can line up against a log answers "where did the time go" but not "what happened to MY
  request", and today's debugging needed the second.
  **One subtlety worth keeping:** the span is named provisionally and RENAMED after the handler
  returns, because chi fills its RouteContext as the request descends the tree. Naming it up front
  produced `GET other` for every request — every endpoint collapsed into one span name, which is
  exactly the cardinality mistake the metric labels avoid, inverted.
  **Still open (split out 2026-08-07, LOW):** OTLP **metric** export (`otlpmetrichttp`), and **DB spans**
  on the pgx pool. Neither is needed by the egress decision above — metrics are scraped, and the server
  span already attributes latency to a route. Revisit if a deployment asks for push-model metrics, or when
  a slow request needs the query broken out from the handler. **Where:** `observability.Setup` + the pgx
  pool constructor.

- [x] **BUG-3b — a Finding opened after its card's last enrichment never gets a band or a fix
  list.** ✅ **CLOSED 2026-08-08.** Found on a clean-slate VM run: of 120 Findings, exactly one
  (`CVE-2026-59949`) showed a blank `band` on the posture while its Faultline card carried
  `informational`. The bus made it unambiguous — `knowledge.faultline_enriched` at **seq 12**,
  `governance.finding_opened` at **seq 205**. Governance handled the enrichment when the Finding
  did not yet exist, `materializeBandAndFixes` found no Findings for that card, and stamped
  nothing.

  **Why nothing repaired it.** The obvious answer — "the next enrichment stamps it" — does not
  hold, and the reason is a fix that is itself correct: enrichment is **relevance-bounded**
  (D5), and **KN-PROPOSAL-BLOAT-1** now drops a source's verbatim restatement, so a card that
  no feed says anything new about emits **no further event**. The 119 Findings that were fine
  were fine only because later Red Hat/NVD sweeps happened to touch their cards. A 2026 CVE that
  no vendor feed carries yet gets exactly one enrichment, and it fires before the Finding exists.

  **This is BUG-3 one field later.** `ComponentMatched.Score` already carries the card's score to
  the birth path for exactly this reason — its comment says so verbatim: *"otherwise a Finding
  born on an already-enriched card is stranded at 0 until the next enrichment event"*. DASH-2
  then added `band` and `fixes` on the **enrichment event alone** and reintroduced the same
  defect. **Fix:** `Priority` + `Fixes` now ride `ComponentMatched` (additive/omitempty, EVENTBUS
  D9) and are stamped at finding-open, with the per-Finding fix selection running there too so
  the union never reaches a Finding (AI-GROUND-1).

  **The lesson worth keeping is about the shape, not the field:** a value delivered only by an
  event is invisible to anything created after that event. Every derived field on a Finding needs
  an answer to "what if the Finding is born late?" — and the answer cannot be "another event will
  come".

- [x] **PLAN-4 — a remediation plan claimed to close more Findings than the release has.**
  ✅ **CLOSED 2026-08-08.** On a live release of **120** Findings, `plan_remediation` reported a
  merged perl step closing **160**, and its fifteen steps claimed **367** between them. Two
  compounding double counts, both specific to Findings — `CVEs` and `InstalledVersions` were
  deduped in the very same loop, which is why it went unseen: every *other* number in the action
  was right.

  1. `PlanActions` appended `FindingIDs` and added `RiskRemoved` **once per component**. A CVE
     hitting 37 perl subpackages that share a source package counted its Finding 37 times.
  2. `mergeSiblings` concatenated id lists and **summed** `RiskRemoved` across merged packages —
     and siblings are merged precisely because they close the SAME CVE set, so they close largely
     the same Findings.

  **Fix:** a per-action `findSeen` set, and a merge that dedupes ids and RECOMPUTES risk from the
  deduped set via a `findingID → residual_priority` map. Regression tests verified against the
  unfixed source (they report `[f1 f1 f1]`/210 and `[f1 f2 f1 f2]`/200 without it).

  **Why it mattered more than the arithmetic:** `RiskRemoved` is what `sortPlan` ORDERS by
  (PLAN-2), so an inflated sum did not merely misreport a step — it could place the wrong step
  first. And a plan whose numbers exceed the thing it plans over does not read to a human as an
  off-by-N; it reads as a reason to disbelieve the plan, including the parts that were correct.

- [x] **PLAN-6 — the plan prompt invited a citation the grounding gate refuses.**
  ✅ **CLOSED 2026-08-08.** Live: `plan_remediation` returned `204` /
  `business_invalid — ungrounded evidence "perl-Carp, perl-constant, perl-Data-Dumper +29 more"`.
  That string is not a package — it is the merged action's DISPLAY heading, capped at three names
  by PLAN-1 for readability. The citation rule still read *"a package name copied verbatim from an
  `upgrade ...` heading"*, so the model copied the heading verbatim, exactly as instructed, and
  `Grounds()` correctly refused it (it anchors to the PROJECTION, never to the shaped
  `UpgradeAction` view — T10 rule 4). **The model obeyed; the prompt was wrong.**

  **Fix:** a `packages (citable)` line carrying the FULL list, with the citation rule pointing at
  it and explicitly warning off the truncated heading. Readability of the human-facing line and
  completeness of the machine-facing citation list are separate requirements; PLAN-1 satisfied the
  first by breaking the second.

  **The first attempt was wrong, and the way it was wrong is the lesson.** I tightened the PROMPT.
  It failed byte-identically on the next live run — because `groundsRef`'s own comment already
  recorded that this citation behaviour had survived *two* earlier rounds of prompt-tightening and
  concluded it should be "accommodated rather than fought". I did a third round without reading
  the note that said the first two had not worked. Two live runs producing an IDENTICAL ungrounded
  ref should also have been the tell: a model varies, generated text does not.

  **The actual fix is a normalisation in the gate:** strip the `+N more` suffix before judging the
  citation, because the RENDERER wrote that suffix, not the model. This is not leniency — every
  remaining name is still matched against the projection, so a list containing one invented package
  fails exactly as before (asserted). A gate that rejects a string its own renderer produced is a
  defect on our side of the interface, not the model's.

  **THIRD occurrence 2026-08-09, and it closes the class.** The response-format example read
  `{"subject_id":"…","evidence":[{"kind":"...","ref":"..."}],…}` and a live model cited the literal
  string `"..."` — ungrounded, whole plan discarded. Three refusals now, each for something the
  PROMPT displayed: the truncated `upgrade` heading, the `<--` annotations, and this placeholder.
  **A placeholder is indistinguishable from content to a model filling in a shape.**

  Fixed by making the example **self-grounding**: it is built from this request's own plan
  (`sampleCVE`), so a model copying it verbatim still emits a ref that passes. An empty plan omits
  the example entirely rather than falling back to a placeholder by another name.
  `TestPlanPromptShowsNoUngroundableRef` generalises the guard from "what the prompt LISTS as
  citable" to "what the prompt SHOWS" — which is the surface a model actually copies from.

  **The durable part is the test, not the fix.** `TestPlanPromptOnlyOffersGroundableCitations`
  asserts that every identifier the prompt OFFERS as citable satisfies `Grounds()`. The prompt and
  the gate are an interface with no compiler between them, and a fake provider returns whatever the
  test author already believed — so nothing else in the suite could catch a disagreement. It
  asserts the INSTRUCTIONS are satisfiable, not that the model behaves: a rule no compliant answer
  can obey is a defect in the rule. This is the third time this capability has been refused for an
  invited citation form (see CLAUDE.md on `make e2e-llm`); it is the first time something guards it.

- [x] **AI-REDACT-1 — the PII redactor masked package names out of the middle of their own PURLs,
  silently disabling `recommend_position`.** ✅ **CLOSED 2026-08-09. P1.**

  First live invocation of the Decision capability, and it was refused:
  `business_invalid — ungrounded evidence "pkg:rpm/rocky/[REDACTED]%2Bel8.3.0%2B125%2B5da1ae29?…"`.

  **Mechanism.** A purl is `pkg:type/namespace/name@version`, and the email pattern
  `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}` reads
  `javapackages-filesystem@5.3.0-2.module` as local-part + domain `5.3.0-2` + TLD `module`. Any
  purl whose version ends in `.<letters>` is destroyed — the RPM **module-stream** form that
  dominates this estate, and Maven's `5.3.0.RELEASE` too (verified against the unfixed code).

  **Two harms, and the second is the serious one.** (1) The model cites the mangled purl and
  Grounding Verification correctly rejects it, discarding the recommendation. (2) The redaction
  runs on the OUTBOUND prompt, so **the model never learns which package it is assessing** — a
  control meant to stop data leaving instead removed the subject of the question. And the whole
  thing surfaced as `X-Themis-AI-Reason: business_invalid`, i.e. as "the AI declined".

  **Fix:** purls are protected from the PII patterns and restored afterwards. Recorded trade: a
  secret embedded inside a purl is no longer masked — a purl is a package coordinate, credentials
  do not live there, so the exposure is theoretical while the breakage was total.

  **Worth keeping:** this is the fourth defect this week where a recogniser was looser than the
  thing it recognises (RANGE-PARSE-1, the CVSS v2 vector, the module `name:stream` regex, this).
  A pattern that "looks like" an email, a version, or a stream will eventually meet a string that
  looks like one and is not.

- [x] **AI-CTX-1 — an unbounded projection field exhausted the model's budget, and the failure read
  as a bad model.** ✅ **CLOSED 2026-08-09. P1 for the Decision capability.**

  First `recommend_position` run after Δ3a was enabled returned `204` /
  `schema_invalid: unexpected end of JSON input`, after **164 seconds** and **8192 tokens**. The
  recommendation was not wrong — it was never finished.

  **Cause:** the prompt printed `affected_ranges` as the card's FULL union. A module-stream card
  carries one range per rebuilt package per EL minor: measured live, ~100 ranges plus 266
  unattributed fixes on one card. The context filled and the model stopped mid-JSON.

  It fails on exactly the cards this estate is made of, so the Decision capability was effectively
  unusable — and the symptom (`schema_invalid`) points at the model, not at the prompt that caused
  it.

  **Fix:** `capList` bounds the sample at 12 and states `+N more (not shown)`. Silent truncation
  would be WORSE than the overflow — the model would reason from a subset believing it had the
  whole set — so the honest tail is the load-bearing part, and the test asserts both halves.

  The prompt now also says the deterministic range engine has already evaluated the full set and
  did not settle it. That is T5 stated to the model: ranges are the RULE step's input, and asking
  the LLM to redo a comparison the rule engine already lost is spending context on nothing.

  **Second fix in the same file:** `recommend_position` still showed `"ref":"..."` — the exact
  placeholder that caused three `plan_remediation` refusals (PLAN-6). It was fixed in one template
  and not the other. Now a real CVE from the Finding, plus an explicit prohibition.

- [x] **GOV-15 — at a large estate the blast multiplier destroys the triage order it exists to
  improve.** ✅ **CLOSED 2026-08-23 (EDR-GOVERNANCE-01 D17, the first T2 delivery).** **LIVE-VERIFIED 2026-08-24 (VM):** 12-customer estate → mult 2.0×, CVE-2019-10086 at eff 152 leading the queue (the very CVE the clamp dropped from the top three on 2026-08-08); order preserved AND amplified. The decision
  went to option (a)+: **remove the output clamp** — `effective_priority`/`residual_priority` are
  unclamped ranking numbers, range 0–200 (the bound moved to the input: `BlastMultiplier` already
  saturates at 2.0×). Option (c) (blast as secondary key) was REJECTED with reasons in D17: it
  would silently delete C2's cross-release amplification intent. Regression test
  `TestEffectivePriority_SaturatedEstatePreservesOrder`; the GUI's priority bar now spans the full
  0–200 track. Original filing kept below for the record.
  **MED.** Measured on the VM 2026-08-08 with a 12-customer estate: multiplier 2.0x,
  and **every one of the release's 120 Findings reported `effective_priority` 100**. The worst item
  on the release (`CVE-2019-10086`, base 76) dropped out of the top three, because with every value
  equal the order among them is arbitrary.

  **Why it is structural, not a tuning problem.** The multiplier is per-release CONSTANT — the same
  2.0x applies to every Finding on the release. Multiplying a set by a constant cannot change its
  relative order, so within a release the multiplier is by construction a no-op for ranking; its
  only legitimate job is comparison ACROSS releases. But `EffectivePriority` CLAMPS to 100, and a
  clamp is not order-preserving: at 2.0x everything with base >= 50 pins there. Net effect inside a
  release is therefore strictly negative — no ordering gained, all ordering lost — and it degrades
  exactly when the estate is largest, which is when triage matters most.

  **It is not only display.** `--ai N` selects "the top N undecided" through the same sort, so on a
  saturated release the Gateway is handed an ARBITRARY N Findings rather than the worst N.

  **Done 2026-08-08:** `release-posture.sh` now sorts `residual_priority` then `base_score`, at both
  sort sites, which restores the ranking the clamp erased for CLI users.

  **Still open — needs a decision, not a patch.** The API has the same defect and a GUI would hit it
  unchanged. Options: (a) stop clamping, letting `effective_priority` exceed 100 — it is "effective",
  not a percentage; (b) keep the clamp for display but return an unclamped ordering value; (c) make
  the multiplier a secondary sort key rather than a factor, which matches what it actually means.
  **(c) is probably right** — a release-scoped amplifier expressed as a per-Finding multiplier is a
  category error, and it is the clamp that exposed it. **Where:** `domain.EffectivePriority`,
  `app.ReleasePosture`, `api/governance.openapi.yaml`.

- [x] **CORR-1 — a distro advisory's package list is recorded as a per-package vulnerability claim,
  so a CPython flaw is attributed to PyYAML.** **✅ CLOSED — both steps implemented and verified live
  2026-08-09** ([`EDR-CORRELATION-01`](engineering/decisions/EDR-CORRELATION-01.md), design decided
  2026-08-08). Step 1 (module-stream grouping, D8.1) landed 2026-08-08; step 2 (carrier attribution —
  `claim_class` ∈ `carrier` / `scope` / `unknown`, with **unknown treated as `carrier` everywhere**, plus
  D5a re-classification when attribution arrives late) landed 2026-08-09. **The narrative below is kept
  verbatim as the reasoning of record** — the measurement that started it, the two candidate readings, and
  the recommendation — because it is why the fix took the shape it did. Read the STEP 1 / STEP 2 markers
  inside it for what actually shipped; the "Recommendation" and "Blast radius if left" passages are
  historical, not open work.

  **Title corrected.** This entry first said "becomes one Finding PER PACKAGE". That was wrong. The
  Finding count is RIGHT — 120 Faultlines, 120 Findings, one per CVE, and a release running the
  superseded `python38` stream genuinely IS exposed to every CVE that stream's advisory fixes. What
  is wrong is narrower: **each Finding names every package in the advisory as its matched
  components**, so 78 of 120 Findings list `PyYAML` for CVEs in CPython, urllib3 and lxml.

  Found on a clean-slate VM run 2026-08-08.

  **What was observed.** Of 120 outstanding Findings on one release, **78** named `PyYAML` as a
  component source and **51** named `python-ply` — and MOST of the CVEs attributed to PyYAML are not
  PyYAML CVEs: `CVE-2023-24329` (CPython `urllib.parse`), `CVE-2020-26137` (urllib3),
  `CVE-2024-4032` (CPython `ipaddress`), `CVE-2021-43818` (lxml), `CVE-2019-16935`
  (CPython `DocXMLRPCServer`). 50 Findings carry exactly 2 components; 4 carry 37.

  **The mechanism.** Rocky/RHEL ship these as MODULE STREAMS. One advisory rebuilds every RPM in
  the stream, so the advisory (via OSV's Rocky feed — 11 of this card's proposals — and via Red Hat
  CSAF) lists `python3-pyyaml`, `python3-ply`, `python3-libs` … as affected. Correlation records a
  match on each. The card's own fix list says it outright: the fix version is
  `python38:3.8-8080020230531142020.a822e92f` — a stream id, not a package version.

  **Everything above it is working correctly, which is why it hid.** Correlation faithfully
  recorded what the feed said; reconciliation, the band, fix attribution, plan grouping and the
  grounding gate all did their jobs on the data handed to them. PLAN-4 and PLAN-6 were real, and
  fixing them only made the plan state its wrong premise more clearly.

  **It is the half of A1 that stayed open.** A1 wired the version-range gate into correlation so a
  match is dropped when a component is *provably out of range*, failing open on
  `RangeUndecidable`. For a module-stream advisory the range is decidable and SATISFIED for every
  RPM in the stream, so A1 passes them all. The gate answers "is this version affected?" when the
  missing question is "is this package the one that carries the flaw?"

  **MEASURED 2026-08-08 — and it refuted the obvious discriminator.** The first hypothesis was
  "genuine CVEs name one package, artifacts name many". The data says otherwise:

  | CVE | osv packages named | nvd | note |
  | --- | --- | --- | --- |
  | CVE-2023-24329 (CPython urllib) | **62** | 0 | artifact |
  | CVE-2020-26137 (urllib3) | **42** | 0 | artifact |
  | CVE-2020-1747 (**a real PyYAML CVE**) | **23** | 0 | genuine — and STILL names 23 |
  | CVE-2017-18342 (real PyYAML CVE) | 1 | 0 | upstream PyPI entry, not a distro advisory |

  A genuine PyYAML CVE pulls in babel, Cython, mod_wsgi, numpy, scipy and 18 more, because the
  advisory rebuilds the stream. **Breadth does not separate genuine from artifact**, so no
  threshold on package count can work.

  **NVD names ZERO packages in every case** — as `VulnFacts.Fixes` already documents ("NVD reports
  fixes without naming the package"). So there is no upstream package identity stored ANYWHERE, and
  the discrimination cannot be made from data Themis currently holds. That is the finding that
  decides the EDR's shape: this is a GATHERING question before it is a filtering one.

  **Scale — it is not a pyyaml problem.** Cards by how many packages their fixes name: 27 cards name
  1; ~85 name 23–66; 5 name 112–113; **3 name 183**. Only 27 of 120 cards carry a single-package
  advisory, so nearly every distro card on this release is a whole-stream advisory recorded as N
  package claims.

  **Two defensible readings, and the decision is which one Themis makes:**
  * *Distro-faithful* — the old `python3-pyyaml` build IS part of a superseded stream and does need
    updating, so 78 Findings is correct and the package name is merely poor labelling.
  * *Flaw-faithful* — the flaw is in CPython; only `python3-libs` is affected and the other 77 are
    packaging scope recorded as vulnerability claims.

  **STEP 1 REFINED 2026-08-09 after the first live run.** Keying on the module BUILD marker alone
  was too conservative and produced the defect it was meant to avoid: `PyYAML` labelled FOUR
  separate plan steps and `python-ply` a fifth, because one stream is rebuilt many times over its
  life and every advisory leaves a different marker (`+el8.4.0+570+c2eaf144`,
  `+el8.5.0+672+ab6eb015`, …). To an operator that reads as "upgrade PyYAML" five times with
  nothing to tell the steps apart. The original reasoning — "merging el8.4 with el8.5 would claim
  one command covers work it does not" — is BACKWARDS for a stream: from an old build, one
  `dnf module update` moves you past all of them. Sibling builds now fold on the PACKAGE SET (an
  identical rebuild scope is the same stream), still exact-match, so {PyYAML} and
  {PyYAML, python-ply} stay separate.

  **STEP 1 IMPLEMENTED 2026-08-08** (`EDR-CORRELATION-01` D8.1): the plan now groups a module-stream
  rebuild into ONE action. The Intelligence read seam did not decode `fixes` at all — so the planner
  had never seen a fix version — and that was the whole gap: the build marker
  (`.module+el8.4.0+570+c2eaf144`) rides on the fix, and every RPM from one rebuild carries the same
  one. Grouping is keyed per (Finding, COMPONENT) rather than per package, because a package can be
  fixed by a module rebuild for one CVE and an ordinary upgrade for another (PyYAML: the python38
  stream for CVE-2020-1747, plain 5.1 for CVE-2017-18342) — keying on the package would claim one
  command closes both. No new gathering, no wire change. **Step 2 (carrier attribution) remains
  open.**

  **Recommendation — both, in this order.**
  1. **Scope-faithful, needs no new data.** Model a module advisory as ONE claim with a package
     SCOPE rather than N claims. The stream id is already on the fix version
     (`python38:3.8-8030020200818121840.4190259b`, `.module+el8.4.0+570+c2eaf144`), so the signal
     is in hand today. This is the direct reading of EDR-VEX-01's "gathering is not knowing": a
     vendor statement is evidence about a shipping unit, and treating its package list as N
     independent assertions is obeying it in a shape it never made. It fixes the plan headline
     immediately ("update the python38 stream", not "upgrade PyYAML").
  **STEP 2 IMPLEMENTED 2026-08-09.** Carrier attribution end to end:
  * **Gather** — `nvdVulnerableProducts` keeps the CPE products the client already parsed for the
    A2 gate and threw away; a NON-distro OSV record's package name is a carrier, a distro one is
    not (that is what `isDistroEcosystem` decides, and it is the whole discrimination — breadth
    could not do it).
  * **Reconcile** — `EnterpriseView.CarrierProducts`, a union across sources, blank-free and sorted.
  * **Classify** — `domain.ClassifyClaim` at correlation, riding `ComponentMatched.ClaimClass`.
  * **Carry** — governance migration `000010`, `claim_class` on `finding_components`, exposed on
    the posture's components.
  * **Consume** — `PlanActions` names only carriers (D6). The AI is no longer handed a component
    the flaw does not live in.

  **The comparison errs toward CARRIER on purpose.** The first implementation demanded exact
  normalized equality and classified `apache-commons-beanutils` as `scope` for its own CVE, because
  NVD names it `commons-beanutils`. Under-matching would mark a genuinely vulnerable package as
  scope, which a consumer could then drop; over-matching only costs precision. Only one of those
  hides a vulnerability, so equality-or-containment it is.

  **Migration is a no-op by construction:** `claim_class DEFAULT ''` is unknown, every consumer
  treats unknown as carrier, so existing rows keep exactly their present behaviour and nothing
  needs backfilling.

  2. **Flaw-faithful, needs new gathering.** Capture which package actually CARRIES the flaw —
     NVD's CPE product is the obvious source and is currently discarded. Only this can say
     "python3-libs is vulnerable, the other 22 are along for the rebuild", and only this reduces
     the Finding count rather than merely relabelling it.

  **Blast radius if left:** the plan's headline step is not actionable ("upgrade PyYAML" fixes
  almost none of its 78); the posture over-counts; and `recommend_position` reasons about a Finding
  whose component list says PyYAML for a urllib3 CVE — which the grounding gate will VERIFY, because
  grounding checks consistency with our record, not whether our record is right. **That is the
  sharpest lesson here: Grounding Verification cannot catch a well-formed wrong premise.**

  **Where it plugs in:** `internal/knowledge/app/correlate.go` (the A1 gate), the feed ACLs that
  flatten an advisory's package list, and `mergeSiblings`. **Note the premise has changed for the
  latter:** its comment says detecting `.module+el` "lives on the FIX VERSION, which the posture
  deliberately does not carry yet" — PLAN-3/DASH-2 means it carries it now, so stream-aware
  grouping is available without new data. **Dep:** an EDR settling the two readings above.

- [ ] **PLAN-5 — one Finding can be claimed by several upgrade steps, and it is unclear whether
  that is right.** LOW — **largely ANSWERED by CORR-1, and not the way this entry guessed.** After PLAN-4 no single step double counts, but a Finding
  whose components span several packages still appears in each of their steps, so the plan's
  steps can still sum to more than the release's outstanding count. That may be correct — a
  CVE-2024-6345 Finding matching `setuptools`, `python3-ply` and `python3-pyyaml` probably IS
  closed by the setuptools upgrade alone, and the other two are co-listed packages rather than
  independent requirements. But "probably" is doing real work in that sentence, and the plan
  currently states it as fact in three places. Deciding this needs the correlation question
  answered first: when a card lists ranges for several packages, is a match on each of them a
  separate claim or one claim seen three times? Until then the numbers are per-step honest and
  the total is not meaningful — which is worth saying in the rendered output.

- [x] **F5 — a node that cannot start is indistinguishable from a healthy one.** ✅ **CLOSED
  2026-08-23 (EDR-ENHANCE-T2, second T2 delivery — both missing halves).** **LIVE-VERIFIED 2026-08-24 (VM):** /readyz ready on all six nodes; vm-verify Readiness section green. (a) Every node now
  serves `/healthz` (liveness) + `/readyz` (readiness: DB ping, migrations-table probe,
  credential freshness) from the new business-agnostic `internal/platform/health` package
  (depguard `platform-health-infra-only` + `TestPlatformHealthIsBusinessAgnostic` fence it like
  eventbus/auth), mounted outside `/api/v1` like `/metrics`; `vm-verify.sh` gained a Readiness
  section probing all six. (b) The outside-the-node signal: the systemd template now sets
  `StartLimitIntervalSec=300` + `StartLimitBurst=5`, so a crash loop becomes a **failed unit**
  visible to `systemctl --failed` and vm-verify's unit-state check instead of 81 silent restarts.
  Migration failure stays fatal, as required — the failure is now loud, not soft. Filing below
  kept for the record.
  **MED.** Found on the VM
  2026-08-08: `themis@governance` had been crash-looping for **81 restarts** — it could not authenticate to
  run its migrations, so it exited, and `Restart=always` restarted it forever. Nothing surfaced that. The
  only reason it was caught is that someone read `schema_migrations.version` by hand and noticed it was 6
  where it should have been 9. The exit itself is CORRECT — a node must refuse to serve on a schema it
  could not verify — so the gap is not the behaviour but the silence around it.
  **Two things are missing and they are different.** (a) `/healthz` + `/readyz` (already tracked as **F5**
  in `PARITY-GAP.md`), so an orchestrator or a check script can see "never became ready". (b) A **startup
  failure counter or log-once-at-error that a scrape can catch** — note that `/metrics` cannot help here,
  because a node that exits before binding its port serves no metrics at all. Whatever watches for this
  must live outside the node.
  **Do not fix by making migration failure non-fatal.** Serving on an unverified schema is the worse
  outcome; the fix is making the failure loud, not soft.

- [x] **Rotating the DB password silently arms a fleet-wide outage — DETECTION half.** ✅ **CLOSED
  2026-08-23 (EDR-ENHANCE-T2: detection first, orchestration later).** Every DB-owning node now
  runs a `health.CredentialWatch`: every 60s it opens a **fresh** connection (the only operation
  that exercises the stored credential — pooled connections survive a rotation) and a failure
  flips `/readyz` to 503 naming `db-credentials`, plus one ERROR log at the transition. The armed
  fleet-wide outage is now visible within a minute of rotation instead of at the next restart.
  **Residual (open below): the orchestration half** — a fleet env-rewrite + restart verb.
- [ ] **DB-password rotation orchestration — rewrite the fleet's env files as one operation.**
  **LOW-MED, operability** (was the "still open" tail of the entry above). A `themisctl`-style
  verb or an `install-systemd.sh` flag that rewrites `/etc/themis/*.env` and restarts the fleet
  atomically, plus the friendlier startup error ("DSN in /etc/themis/<svc>.env is not accepted by
  the server"). Original filing kept below for the record.
  **MED, operability.** Same VM
  incident. `install-systemd.sh` bakes `THEMIS_PGPW` into six `/etc/themis/*.env` files and nothing
  reconciles them afterwards, so the `themis` role's password and the DSNs had drifted apart (the role held
  the literal example password from `INSTALLATION.md`, the env files held a different one).
  **Why it stayed hidden for so long is the interesting part:** `pgx` pools keep serving on connections
  opened BEFORE the password changed. Every node reports healthy — not because the credential works, but
  because nothing has asked it to prove it since. They then all fail together at the next restart, at a
  moment nobody chose. Governance failed first and loudest only because it is the one that must
  authenticate at startup to migrate.
  **Done so far (2026-08-08):** `INSTALLATION.md` now GENERATES the password instead of naming one (a
  literal credential in a runbook becomes a real one the first time somebody follows it), and documents the
  rotation procedure beside the installer.
  **Still open:** a `themisctl`-style verb, or a flag on `install-systemd.sh`, that rewrites the env files
  and restarts the fleet as one operation — plus a startup-time credential check that fails with
  "DSN in /etc/themis/<svc>.env is not accepted by the server" rather than a bare driver error.

---

### E. Process / optional refinements

- [ ] **Record the GUI's vanilla-JS-no-framework choice as an explicit decision (LOW, docs-only).**
  Surfaced 2026-08-17: EDR-GUI-01 fixes D1 (a view, one static binary), D7 (a `node --check` JS
  syntax gate — meaningful only because there is no build step), and D8 (`go:embed` assets), and
  STACK.md rejects heavy frameworks on the Go side — but nowhere is "hand-written vanilla JS, no
  React/Vue/htmx, no npm/bundler" stated as a decision with named alternatives, per the
  component-grounding practice. The rationale exists (single-binary deliverable, zero JS
  supply-chain surface, no Node toolchain in a `go build`-only repo, app is stateless
  render-functions-of-JSON); it just lives implicitly across D1/D7/D8. One paragraph in
  EDR-GUI-01 (or a STACK.md row) closes it — worth writing before the GUI grows enough that a
  framework question gets re-litigated from scratch.

- [x] **Tracer-bullet reslice for Evidence** (optional). ✅ **CLOSED 2026-08-07 as MOOT.** The slices
  were a re-scaffolding aid for `phase3-evidence/tasks.md`; that change shipped (M6, 7/7, with a
  5-scenario e2e) and is archived. Re-slicing delivered work would produce a plan for something that
  already exists. Kept below only as the reasoning trail for how the vertical was sequenced.
  **Original (optional) note follows.** Fold these demoable vertical slices into
  `phase3-evidence/tasks.md` if it is re-scaffolded (pre-scaffold draft archived at
  `openspec/changes/archive/2026-07-15-phase3-evidence-prescaffold/`):
  1. Kernel registry vertical (register/lookup Release) — root.
  2. Walking skeleton: `POST` CycloneDX SBOM → Evidence ID (blocked by 1).
  3. Idempotent re-upload → same ID (2).
  4. Read back facts + inventory by ID (2).
  5. SPDX upload (2, 4).
  6. Helpful rejections — unknown release / non-standard format (1, 2).
  7. `EvidenceRegistered` via outbox + relay (2).
  8. List by release (2, 4); dev-only purge (2).

- [x] **Domain glossary upkeep.** ✅ **CLOSED 2026-08-07 — recorded as a PRACTICE, not a task.**
  It has no completion state: a glossary is maintained or it is not, and an open checkbox for
  "keep doing a thing" is a checkbox that stays open forever and dilutes the list around it.
  **The practice:** an EDR that introduces a term defines it in its own Glossary section
  (`EDR-INTELLIGENCE-01` has one; it is the model). Terms that cross contexts belong in the
  architecture book's ubiquitous-language chapter, not in a per-EDR glossary — a term with two
  definitions in two EDRs is exactly the drift a glossary exists to prevent.
  **Re-open only** if a concrete term is found carrying two meanings, which is a defect with a
  name rather than a standing chore.

- [x] **Extend CI with the pipeline e2e (post-M5).** ✅ **DONE** (verified 2026-08-07): `make e2e-pipeline`
  runs on **both** `pr.yml` (pre-merge gate) and `main.yml`, alongside `make check-ci`. It remains outside
  `make check-ci` deliberately, as planned. Original note follows. CI is **live on `main`** (PR #53):
  `.github/workflows/{pr,main}.yml` run a greenfield-scoped **`make check-ci`** (+ `make e2e-evidence` on
  `main`). When M5 lands `make e2e-pipeline` (`phase3-event-infrastructure` tasks 9.1 / 10.4), add an
  `e2e-pipeline` step to `main.yml` (mirroring `e2e-evidence`), and to `pr.yml` if pre-merge pipeline proof is
  wanted. Kept **out of `make check-ci`** deliberately (e2e is slow; consistent with `e2e-evidence`). Optional:
  a `make e2e` / `make ci` aggregate target.

- [x] **Close the PR-gate e2e blind spot (LOW).** ✅ **CLOSED 2026-08-07.** Both halves are done:
  `make e2e-evidence` is now a `pr.yml` step beside `make e2e-pipeline`, so neither e2e suite can
  merge green and redden `main` afterwards; and the "cheap guard" this entry asked for shipped as
  **`make vet-tags`**, wired into `check` and `check-ci`, which type-checks `integration`, `e2e`,
  `llm` and `postgres` in seconds. That guard immediately earned itself twice: it caught two tagged
  callers of `wiring.Wire` the untagged build cannot see, and it revealed that `llm_e2e_test.go` had
  not compiled since the T10 refactor (PLAN-4). **Update:** `pr.yml` now runs
  `make e2e-pipeline`, so the *pipeline* e2e is a pre-merge gate and the original failure mode (a change
  that breaks e2e merging green) is largely closed. Confirmed live the same day: the D14/D15 `Wire`
  signature changes broke `tests/pipeline` compilation, which `make check-ci` **cannot** see because the
  file carries `//go:build e2e` — `go build ./...` skips tagged files entirely. The PR gate would have
  caught it. **What remains:** `make e2e-evidence` still runs only on `main.yml`, so the Evidence-specific
  e2e keeps the old blind spot. Also worth a cheap guard: a `go vet -tags=e2e ./tests/...` step (or folding
  the tag into the lint pass) would surface a *compilation* break in seconds instead of after a full
  embedded-Postgres e2e run. Original note follows. `make e2e-evidence` runs only on the
  post-merge `main.yml`, not on `pr.yml` (it carries the `e2e` build tag, excluded from `check`/`check-ci`), so
  a change that breaks e2e merges **green** and only reddens `main` afterward. This bit us: PR #55 renamed
  `evidence_outbox.evidence_id` → `subject` (M5 migration `000002`) without updating the e2e `outboxCount`
  helper; the PR passed, `main`'s Main run went red, fixed in PR #56 (`8c6a7c3`). **Decision:** stays
  backlogged at low priority — revisit **after M5**; implement only if it recurs or a green gate ends up with a
  straight dependency on pre-merge e2e proof. Natural fix is to run e2e on `pr.yml` too (folds into the
  pipeline-e2e item above once `make e2e-pipeline` exists).

- [x] **CI-PROP-1 — CI fails intermittently on a FROZEN-tree defect.** ✅ **FIXED 2026-08-07 via option
  (a).** **Severity was understated when filed:** it is not nightly-only. `make check-ci` — the *pre-merge*
  gate — ran `go test ./...` across the whole repo, so the flaky property could redden the main gate at
  rapid's default check count, and did, roughly ten minutes after the entry claimed otherwise. The earlier
  green runs were luck.
  **Fix, mirroring the `coverage` / `coverage-greenfield` pair that already existed:** `test-greenfield` and
  `test-property-greenfield`, with `check-ci` and the property workflow switched to them. `make check` and
  `make test-property` still run the whole repo. The exclusion is expressed as a regex over
  `go list ./...` rather than an allow-list, so a newly scaffolded greenfield package is gated the moment it
  exists — an allow-list silently omits whatever nobody remembered to add. `GREENFIELD_DIRS` is *derived*
  from `COVERAGE_PKGS_GREENFIELD` for the same reason. Verified with three consecutive green `check-ci`
  runs.
  **Found while fixing it — a second, worse hole.** `make test-property` selects with
  `-run 'Property|Prop_'`, and `TestReconcile_OrderIndependent` — the **D2 determinism guarantee, the
  single most important invariant in Knowledge** — did not match. It had therefore run only at rapid's
  built-in 100 examples under `make test`, and had been excluded from **every** 1000-, 5000- and
  20000-example sweep the project has ever done, while appearing to be covered by the property gate.
  Renamed, swept at 20000 (passes), and the convention is now **enforced** by
  `TestRapidPropertiesAreNamedForTheDeepRun` in `tests/architecture`, which parses each greenfield test
  file and fails on any rapid test whose name the filter would skip. A convention enforced by nothing is
  one that has already been broken somewhere nobody has looked.
  **What is NOT fixed:** the redactor itself. `internal/adapter/notify` is reference-only under the freeze,
  the mechanism is recorded below, and the defect is now simply out of the gate's scope rather than
  suppressed. Original report follows.
- [x] **CI-PROP-1 (original report) — The scheduled Property Tests job fails intermittently on a FROZEN-tree defect.**
  ✅ **CLOSED 2026-08-07 via option (a).** `property-tests.yml` runs `make test-property-greenfield`,
  scoping the gate to the go-forward tree exactly as `check-ci` already scopes coverage. The UNDERLYING
  non-idempotence in `internal/adapter/notify` is unfixed and stays that way — the tree is frozen and
  this is not the one sanctioned exception. What mattered was the SIGNAL: a scheduled job red a
  quarter of the time trains everyone to ignore it, and would then hide a real greenfield property
  failure. `make test-property` still runs the whole repo for anyone who wants it. Original report follows.
  _(Found 2026-08-07 while verifying the post-merge CI on `main`.)_ The nightly `Property Tests` workflow
  runs `make test-property RAPID_CHECKS=20000`; the same tests run at the default 1000 checks in `make
  check`, which is why this is invisible pre-merge. `TestRedactLogMessageIdempotentProperty` in
  **`internal/adapter/notify`** — the frozen v0.3.x tree — fails roughly **1 run in 4** at 20k checks.
  **Mechanism (isolated, not inferred):** `redactLogMessage` rewrites `password <secret>` to
  `password=****`, INSERTING an `=`. Its own output then matches its own keyword-with-`=` pattern, so a
  second pass yields `password==****`, a third `password===****`:

      in    = "authpassword !!!!!! https://h.example/webhook/!!!!!!"
      once  = "authpassword=**** https://****/webhook/****"
      twice = "authpassword==**** https://****/webhook/****"

  **Not a leak** — the secret is gone after the first pass, and `TestRedactLogMessageNoLeakProperty`
  passes. It is a non-idempotence bug that only bites when a message is redacted twice (two layers both
  scrubbing, or a re-log of an already-scrubbed line).
  **The fix is BARRED:** `internal/adapter/notify` is the frozen v0.3.x tree, reference-only, and the one
  sanctioned exception on record is the NVD CVSS-4.0 maintenance fix. This is not that.
  **The real cost is the CI signal, not the bug.** A scheduled job that is red a quarter of the time trains
  everyone to ignore it, and it will then hide a *greenfield* property failure when one appears. Options,
  none taken here because each is a process decision: (a) scope `test-property` to the greenfield tree the
  way `check-ci` already scopes coverage — the cleanest, and consistent with the frozen-tree policy;
  (b) skip this one test under a build tag with a pointer to this entry; (c) take the fix as a second
  sanctioned exception. **Where it plugs in:** `Makefile` (`test-property` package selection) or
  `.github/workflows/property-tests.yml`. **Scope:** LOW to fix, MEDIUM if left — a permanently-noisy gate
  is a gate nobody reads.

- [x] **Bump GitHub Actions off Node 20 (LOW).** ✅ **CLOSED 2026-08-07** — done while the workflows
  were open anyway for the e2e-evidence gate, which is exactly the "next time they are touched" this
  entry was waiting for. `actions/checkout@v4 → v5`, `actions/setup-go@v5 → v6` across all four
  workflows, clearing the runner deprecation warning on every run.

---

### Not in scope (recorded so they are not mistaken for pending)

- The legacy `internal/` PoC tree is **reference only** and frozen at v0.3.x — not modified, not part of this
  backlog.
- `themis-ai-1` / `themis-phase-2` are archived as superseded (fold into M4 / reference).

---

## Part 2 — Legacy PoC history (frozen — reference only)

All deferred proposals and unimplemented items, organised by phase. Each entry records:
what it is, why it was deferred, which Phase 1 hooks or interfaces are already in place,
and the target phase.

---

### Phase decision log

The original `proposal-initial.md` defined:

- Phase 2 = Native React SPA (Web UI)
- Phase 3 = Full-Featured Platform (Docker, RBAC, HA)

**These boundaries were changed during Phase 1 design, then refined further before Phase 2
started.** The current plan:

- Phase 2 = AI enrichment, EPSS/KEV, upstream VEX feeds, VEX export — split into three
  sub-phases (2a, 2b, 2c) because the full scope is too large to implement reliably as one
  change and the AI layer depends on signals being healthy before meaningful testing is possible
- Phase 3 = Rate limiting + runtime observability + cosign/sigstore + CI/CD ingestion +
  deployment + UI + enterprise features

Rationale for sub-phase split: Phase 2a (signals + graph + VEX export) delivers standalone
value and validates the data foundation. Phase 2b (AI workers + RAG + pgvector) can only be
meaningfully tested after EPSS/KEV/ExploitDB are healthy. Phase 2c (auto-apply thresholds)
requires the KB to be seeded with real analyst decisions before confidence thresholds are
tunable. Splitting also lets each sub-phase be tagged as a release (v0.2.0, v0.3.0, v0.4.0).

---

### Intelligence Source Tiers — Reference

**Canonical classification of all Themis intelligence sources by importance tier.**
Reference document: `openspec/intel-source-tiers.md`.
All feed adapters and schedulers must emit errors at the tier level defined there.

| Tier | Name | Failure behaviour |
| ---- | ---- | ----------------- |
| 1 | Critical — Mandatory | `ERROR` + `signals_stale=true` + operator notification |
| 2 | Strongly Recommended | `WARN` + `degraded_feeds[]` in status API |
| 3 | AI Enrichment Gold | `INFO` + metric counter, no status API impact |
| 4 | Future / Planned | `DEBUG` only — not yet implemented |

See `openspec/intel-source-tiers.md` for the complete source list, Prometheus metric
convention, status API response shape, and Go code conventions per tier.

---

### HIGHEST PRIORITY (schema work) — Core Data Model Restructure (`themis-core-model`)

**Decided: 2026-06-16. All decisions confirmed. This is the next breaking change and ships as
`v0.3.0` together with Phase 2b.**

It gates everything that depends on the schema: the artifact/version registration endpoints
(Group 16.4 / 16.10), the G3 "VEX export without SQL" fix, and Phase 2b planning. It does
**not** gate the `v0.2.1` maintenance release — Group 31 feed fixes and the Group 16 hardening
remainder (16.1–16.3, 16.5–16.8) touch no schema and ship first, ahead of this restructure.
See "Release versioning — reconciliation" below.

#### Why now

The current model conflates two distinct concerns inside `sbom_documents`:

- **Composition** — what is in the artifact (stable; determined by the image digest)
- **Vulnerability scan** — what was found at a point in time by a specific scanner
  (temporal; evolves as CVE databases are updated)

This conflation causes three concrete problems that compound with each phase built on top:

1. **Silent triage loss on rescan.** `risk_context` keys off
   `component_vulnerability_id`, which is tied to a specific scan document row. Every
   rescan creates new `component_vulnerabilities` rows → new `risk_context` rows →
   all previous `accepted_risk` / `false_positive` decisions are silently orphaned.
2. **`is_latest` / `supersedes_id` anti-pattern.** The linked-list chain on
   `sbom_documents` makes it impossible to cleanly answer "how many scans exist for
   this artifact?" and is not used consistently across the codebase.
3. **Phase 2b lock-in.** AI workers in Phase 2b will reference
   `component_vulnerability_id → sbom_document_id`. After Phase 2b ships, fixing
   `risk_context` means migrating all AI enrichment output tables too.

#### Confirmed decisions (no open questions)

| # | Question | Decision |
| - | -------- | -------- |
| Q1 | Does `version` always require a `project` parent? | **Yes — mandatory.** A default project is auto-created on product registration. `version.project_id NOT NULL` always. No optional FK. |
| Q2 | Is `artifact.image_digest` globally UNIQUE? | **Yes — globally.** Same digest = same physical content = same artifact. One artifact can only belong to one version. No join table needed. |

#### New entity hierarchy

> **Refined in the `themis-core-model` design (2026-06-18):** `sbom` is keyed
> `(artifact_id, sbom_checksum)`, not strictly 1-per-artifact — see design decision D9
> (handles multi-tool/corrected SBOMs without orphaning findings). Other refinements there:
> D10 latest-scan invariant, D11 denormalized version-qualified purl+cve, D12 ingest
> idempotency, D13 squashed migration baseline + schema-skew guard.

```text
product
  └── project  (product_id)               ← unchanged
        └── version  (project_id)          ← was: version.product_id
              └── artifact  (version_id,   ← merges current artifact + images tables
                              image_digest TEXT UNIQUE)
                    │
                    ├── sbom         (artifact_id)            1 per artifact
                    │     └── component_versions  (sbom_id)
                    │     └── dependency_relationships (sbom_id)
                    │
                    └── scan_report  (artifact_id, scanner)   N per artifact
                          └── component_vulnerabilities (scan_report_id)
                                └── risk_context  ← PK moves to (artifact_id, purl, cve_id)
```

`sbom` = the bill of materials (what is installed — stable for a given digest; Layer 0
immutable inventory). `scan_report` = one scanner's findings at one point in time
(temporal; ordered by `scanned_at DESC`). "Latest scan" = `ORDER BY scanned_at DESC
LIMIT 1` — no `is_latest` flag needed.

#### Tables replaced / merged

| Old table | New table | Change |
| --------- | --------- | ------ |
| `product_versions` | `versions` | `project_id FK` replaces `product_id FK` |
| `artifacts` + `images` | `artifacts` | Merged into one table; `image_digest` moves here; `images` table dropped |
| `sbom_documents` | `sboms` + `scan_reports` | Split: composition → `sboms`; temporal scan → `scan_reports` |

#### FK column renames (same logic, different target table)

| Column | Was | Now |
| ------ | --- | --- |
| `component_versions.sbom_document_id` | `sbom_documents` | `sboms` |
| `dependency_relationships.sbom_document_id` | `sbom_documents` | `sboms` |
| `component_vulnerabilities.sbom_document_id` | `sbom_documents` | `scan_reports` |
| `vex_documents.sbom_document_id` | `sbom_documents` (nullable since mig 000019) | `artifacts` |

#### `risk_context` key change — the triage persistence fix

```text
Before: UNIQUE component_vulnerability_id   ← tied to one scan document row; lost on rescan
After:  PRIMARY KEY (artifact_id, component_purl, cve_id)   ← identity-based; survives rescans
```

A triage decision means "for CVE-X in component pkg:apk/busybox@1.36 running in this
artifact, we accept the risk." That identity does not change when the artifact is
rescanned. The new PK makes this explicit.

#### Eliminated anti-patterns

- `sbom_documents.is_latest` — **removed.** Latest scan = `ORDER BY scanned_at DESC LIMIT 1`.
- `sbom_documents.supersedes_id` — **removed.** No more linked-list chain.

#### What does NOT change (entire Phase 2a intelligence layer preserved)

All Phase 2a business logic — EPSS/KEV sync, ExploitDB, Layer 1 deterministic rules,
Layer 2 blast-radius, VEX matching algorithms, VEX export — is unchanged. Only the FK
traversal is updated (different column names pointing to new tables).

Tables that survive without structural change: `vulnerabilities`, `epss_kev_signals`,
`exploit_records`, `vex_assertions`, `triage_history`, `audit_log`, `api_keys`,
`notification_rules`, `ingestion_jobs`, `system_state`, `microservices`, `deployments`,
`customers`, `asset_graph_nodes`, `asset_graph_edges`, `intelligence_signals`,
`runtime_exposures`, `remediation_actions`.

#### Implementation scope

- Replace migrations 000001–000004 with new migrations for `versions`, `artifacts`,
  `sboms`, `scan_reports`; adjust FK references in migrations 000005–000019 (additive
  ALTER TABLE changes per affected table — no data mutations)
- ~24 non-test `.go` files updated: domain types, store layer, use cases, adapters,
  API handlers (FK column rename propagation only — no algorithm changes)
- ~30 test files updated: SQL fixture references to `sbom_document_id`, `image_id`
- `risk_context` store queries updated for new PK shape
- Ingestion use case: one ingest call produces one `sboms` row + one `scan_reports` row
  (split from current single `sbom_documents` insert)

#### Impact on Group 16 items

- **16.4** (`POST /api/v1/products/{id}/images`) — replaces with `POST /api/v1/products/{id}/artifacts`
  under the new merged table; same intent, updated path and payload.
- **16.10** (`POST /api/v1/products/{id}/versions`) — `product_versions` becomes `versions`
  with `project_id` FK; endpoint becomes `POST /api/v1/projects/{id}/versions`. The auto-create
  default project on product registration satisfies the single-project case without SQL workarounds.

---

### Release versioning — reconciliation (2026-06-17)

Phase 2a was tagged `v0.2.0` before Phase 1's Group 16 hardening finished, which
stranded the planned `v0.1.0` milestone _below_ an already-published release. This was
reconciled as follows:

- **`v0.1.0`** — created retroactively on the Phase 1 completion commit (`a94f3ba`,
  PR #10), replacing the old `themis-phase-1` tag. Tag history now reads
  `v0.1.0 → v0.2.0`. `v0.1.0` is **done** — it is no longer a future gate.
- **`v0.2.0`** — Phase 2a Signal Foundation (released).
- **`v0.2.1`** — maintenance release: Group 31 feed-reliability fixes + the Group 16
  hardening remainder. No breaking changes. (Released.)
- **`v0.3.0`** — **released 2026-06-24:** `themis-core-model` (breaking schema restructure) **+
  the Layer-0 Correctness & Observability refactor (CR-1…CR-10)**. _(Re-scoped: Phase 2b was
  originally bundled here but moved to `v0.4.0` so the Layer-0 hardening could ship first.)_
- **`v0.3.2`** — correlation correctness (canonical CVE-ID keying + el8/el9 release-stream
  scoping) + post-v0.3.0 feeder resilience. (Released.)
- **`v0.3.3`** — distro-authoritative correlation identity (`PackageIdentityMatch` tightened, fixes
  the empty-ecosystem NVD over-match) + NVD by-CVE backfill robustness (throttle → transient) +
  remediation (`fixed_version`/`installed_version`) surfaced on the findings API. (Released.)
- **`v0.3.4`** — preserve backfilled CVSS in the catalog upsert (conditional `ON CONFLICT`; no
  clobber to `unknown`/0 on re-correlation). (Released.)
- **`v0.3.5`** — Red Hat VEX overlay via on-demand Security Data API (Option B);
  `adapter/redhat` + `usecase/enrichment.RedHatVEXService`. (Released.)
- **`v0.3.6`** — Red Hat VEX minor-stream false-resolution fix: scope verdicts to the main
  `enterprise_linux:N` stream + read the `epoch=` PURL qualifier (stops false `resolved` on
  vulnerable RPMs). (Released; PR #39.)
- **`v0.3.7`** — OSV GIT-range over-match fix: skip `GIT`-type OSV ranges so commit hashes never
  become version bounds or `fixed_version` (Jinja2 CVE-2016-10745 false positive). (Released; PR #41.)
- **`v0.3.8`** — scoped vulnerability-listing endpoints (`GET /products|projects/{id}/vulnerabilities`,
  `.../versions/{v}/vulnerabilities`) reusing the scan-findings shape via `v_latest_findings`.
  (Released; PR #42.)
- **`v0.3.9`** — feed registry: user-defined `vexfeed.feeds` delta list (add / override / disable
  feeds by name) merged over built-in defaults. (Released; PR #44.)
- **`v0.4.0`** — Phase 2b (AI Intelligence).
- **`v0.5.0`** — Phase 2c (AI-Assisted VEX).

Nothing below `v0.2.0` will ever be tagged again.

> The v0.3.x maintenance line (v0.3.2–v0.3.9) is **complete and released** — non-breaking
> correctness/feature patches shipped from `main` on the v0.3.0 schema (no migrations); each has a
> `docs/release-notes/release-notes-v0.3.x.md` and a `CHANGELOG.md` section. `openspec/STATUS.md` and
> `PROJECT_CONTEXT.md` were refreshed to v0.3.9 on 2026-07-02.

---

### Group 16 — Phase 1 hardening remainder (now targets v0.2.1)

These post-completion tasks close gaps found after the main Phase 1 build. The original
"gate before tagging `v0.1.0`" framing is retired (`v0.1.0` is tagged). The hardening
tasks now ship in the **v0.2.1** maintenance release; the two new registration endpoints
moved under `themis-core-model` because that change redefines both.

| # | Task | Status |
| - | ---- | ------ |
| 16.1 | OSV query: normalise Alpine package names before lookup (strip `so:` prefix, map `py3-foo` → `python3-foo`) | **Done** (v0.2.1) |
| 16.2 | Integration test: Alpine SBOM ingest with OSV-matched CVEs | **Done** (`TestV021AlpineSBOMOSVCorrelation`) |
| 16.3 | Integration test: rpm-based SBOM ingest with unsupported ecosystem skipped cleanly | **Done** (`TestV021RPMSBOMIngestSkipsUnsupportedOSV`) |
| 16.4 | REST endpoint to register an artifact before SBOM upload | **Moved → `themis-core-model`** (`POST /api/v1/products/{id}/artifacts`) |
| 16.5 | Upload helper script (curl-based) for local testing and CI pipelines | **Done** (`scripts/upload-sbom.sh`, `scripts/alpine-e2e-gate.sh`) |
| 16.6 | `make check` run clean after all hardening items | **Done** (v0.2.1) |
| 16.7 | Coverage: `adapter/store/` reaches ≥90% | **Done** (91.6%) |
| 16.8 | Coverage: `adapter/osv/` reaches ≥90% | **Done** (93.6%) |
| 16.9 | Git tag `v0.1.0` and Phase 1 release notes | **Done** (retroactive tag, 2026-06-17) |
| 16.10 | REST endpoint to register a version | **Moved → `themis-core-model`** (`POST /api/v1/projects/{id}/versions`) |

---

### Phase 2 backlog

Phase 2 is split into three sub-phases. Master architecture reference:
`openspec/changes/themis-phase-2/proposal.md` and `design.md`.
Current implementation status: `openspec/STATUS.md`.

---

#### KNOWN GAP — Red Hat CSAF VEX overlay never ingests (confirmed 2026-06-28)

**Status:** ✅ RESOLVED via **Option B** (v0.3.5) — on-demand Red Hat Security Data API
(`adapter/redhat` + `usecase/enrichment.RedHatVEXService`), the backlog-recommended approach
below. For each open RPM-family CVE, Themis fetches
`access.redhat.com/hydra/rest/securitydata/cve/{CVE}.json`, resolves the verdict for the
component's exact EL stream (CPE→major), and writes a VEX-overlay assertion keyed to the
finding's PURL so the existing matcher applies it: `fix_state: "Not affected"` →
`effective_state=not_affected` (a visible, human-overridable signal — the ncurses
CVE-2022-29458 case), `affected_release` → the back-ported fix NEVRA, and `threat_severity` +
statement → the justification. Severity is context only (no auto-rescore; the analyst decides).
The exact-PURL approach made the `namespaceAliases` `rocky/alma→redhat` change unnecessary (no
over-suppression risk). The broken `CSAFDirectoryFeedSource` crawler analysis below is retained
for history.

**Severity:** value-add accuracy gap (not a correctness bug). Distinct from, and a
follow-on to, the release-stream fix (PR #30, which removes the el8↔el9 cross-stream
false positives — the actual correctness bug).

**Symptom:** `vex_assertions` is empty (0 rows) on a fully-correlated deployment;
`upstream_vex_coverage` is `not_covered` on every finding; no finding ever carries
`source = rhsa`. So Red Hat's authoritative vendor verdicts never reach findings —
e.g. CVE-2022-29458 / ncurses shows NVD **High** instead of Red Hat **Low /
"Not affected"** (vulnerable code is the build-time `tic`, not `libncurses`).

**Root cause:** `vexfeed.CSAFDirectoryFeedSource.Fetch` (`adapter/vexfeed/csaf_directory.go`)
is a **one-level** crawler: it GETs the index URL and regex-scrapes `href="*.json"`
(`csafAdvisoryLinkRE`). But Red Hat's CSAF repos serve a _fancy-index_ HTML listing of
**year subdirectories** (`1999/` … `2026/`) with **zero** top-level `.json` links, so
`extractCSAFLinks` returns nothing → 0 docs parsed → 0 assertions. Confirmed empirically:
`curl .../data/csaf/v2/vex/ | grep -c 'href="[^"]*\.json"'` → `0`; links are all `YYYY/`.
The **same crawler backs both** `rhel_vex_url` (the VEX overlay) **and** `rhel_csaf_url`
(the RHEL-advisory rpm correlation source in `api_wiring.go`), so **both have always been
empty**. (Recursing per-file is infeasible: the tree is hundreds of thousands of docs.)

**Related (downstream, do second):** even once data lands, the `namespaceAliases` table
(`adapter/vexfeed/normalize.go`) only maps `rhel→redhat`, `alma→almalinux`; a Rocky
component (`pkg:rpm/rocky/…`) is `namespacesEquivalent("rocky","redhat") = false`, so
Red Hat verdicts still won't match. Add `rocky→redhat` and `alma→redhat` (RHEL clones are
1:1 rebuilds; same NEVRA = same build) **scoped to the overlay**, after ingestion works.

**Fix options:**

- **Option B — on-demand Red Hat Security Data API (recommended).** Mirror the existing
  CVSS-backfill pattern (`usecase/enrichment/cvss_backfill.go`): for each distinct
  RPM-family CVE in open findings, query `access.redhat.com/hydra/rest/securitydata/cve/{CVE}.json`,
  then apply per EL stream — vendor `threat_severity` (often lower than NVD), `package_state.fix_state`
  (`Not affected` → suppress; `Will not fix`/`Affected` → keep + contextualise), and the
  `affected_release` fixed NEVRA. Bounded by distinct-CVE count (≈363 on the test SBOM),
  rate-limitable, cacheable. Solves the ncurses case directly.
- **Option A — bulk CSAF archive ingestion.** Replace the crawler: download
  `archive_latest.tar.zst`, zstd-decompress + untar, `ParseCSAF` each doc into `vex_assertions`.
  Complete offline overlay but heavy (new zstd+tar dependency, gigabytes, hundreds of
  thousands of docs; needs year/product scoping).

**Hooks already in place:** `ParseCSAF` (single-doc parser), `vexfeed.Service` + `Store`
(`PostgresAssertionStore` → `vex_assertions`/`vex_documents`), `EnrichmentAssertionReader`,
`StartVEXFeedScheduler`. For Option B: the per-CVE enrichment/backfill scheduler pattern.

**Supersedes** the thin "Red Hat CSAF directory crawl" row in the _Post-2a follow-on —
Vendor VEX feed operations_ table below. **Target:** v0.3.x correlation-accuracy follow-on.

---

#### KNOWN GAP — OSV.dev app-ecosystem version-range quirks (found 2026-06-29, during v0.3.3 E2E)

**Status:** GIT-range over-match ✅ **RESOLVED in v0.3.7**; major-line crossing **reclassified**
(not a Themis bug — see Resolution). The OSV `ranges[].type` is now read: `GIT` ranges are
skipped so a commit SHA never becomes a version bound or a `fixed_version`, and a GIT-only entry
fails closed via the existing `none` sentinel (an explicit `versions` list is still honoured).
Verified against the real OSV `/v1/query` records for Jinja2 (`PYSEC-2019-220`) and urllib3.

**Severity:** correctness (over-match) for application ecosystems (pypi/npm/…), **distinct
from** the distro (apk/rpm) work in v0.3.3. Surfaced when the new findings API exposed
`fixed_version` (v0.3.3 item 3): two OSV.dev-correlated pypi findings on the Rocky-8 test
SBOM are wrong, both from version-range handling the unified engine does not cover for the
`OSV.dev live` (`source = osv`) path.

**Symptoms (verified on the fresh v0.3.3 scan):**

- **GIT-range over-match.** `CVE-2016-10745` (Jinja2, fixed upstream in **2.8.1**, 2016) is
  flagged on installed **Jinja2 3.1.6** (2025) — a clear false positive — and its
  `fixed_version` surfaces as a **git commit SHA** (`9b53045c…`), not a semver. The OSV
  record expresses the affected range as a `GIT` range (commit introduced/fixed) rather than
  a `SEMVER`/`ECOSYSTEM` range; the live OSV path does not resolve GIT ranges to versions, so
  the range is mishandled and the commit hash leaks through as the "fix".
- **Major-line crossing.** `CVE-2026-21441` flags urllib3 **1.26.20** with `fixed_version`
  **2.6.3** — the 1.26.x maintenance line is independent of 2.x (same shape as the el8/el9
  stream problem, but for a Python package), so a 2.x fix should not mark a 1.26.x install
  affected unless the OSV record lists a 1.26.x range too.

**Root cause (to verify in code):** the OSV.dev live path (`adapter/osv/client.go` /
`component_fetcher.go`) maps OSV `ranges` to the canonical constraint set assuming
`SEMVER`/`ECOSYSTEM` events; `GIT`-type ranges (and multi-line packages where a fix exists per
major line) are not handled — there is no commit→version resolution and no per-line scoping.
The distro feeds avoid this (NEVRA + the `RPMReleaseMajor` stream guard from v0.3.2); app
ecosystems have no equivalent.

**Resolution (v0.3.7):**

- **GIT-range over-match — fixed.** `osvRange` now carries `type`; `isUnusableRangeType` skips
  `GIT` ranges in both `extractAffectedVersions` and `extractFixVersions` (`adapter/osv/client.go`).
  OSV always attaches a `SEMVER`/`ECOSYSTEM` range or an explicit `versions` list when an
  ecosystem fix exists (Jinja2 `PYSEC-2019-220` carries both a `GIT` range and `ECOSYSTEM < 2.8.1`),
  so this is safe; a GIT-only entry with no versions list fails closed (`none`).
- **Major-line crossing — reclassified as OSV data-faithfulness, not a Themis bug.** Verified on
  the real OSV `/v1/query` records: multi-line packages (urllib3 `CVE-2024-37891`) are published as
  **separate `affected` entries** (`< 1.26.19` and `>= 2.0.0, < 2.2.2`), which the existing code
  already turns into correct OR-groups — `1.26.20` matches neither. A residual over-match only
  arises when OSV itself gives an unbounded `introduced:0 → fixed:X.Y.Z`, i.e. Themis is faithfully
  applying OSV's own range. Adding a "major-line suppression" heuristic was **declined**: it would
  hide real findings, contradicting this file's deliberate recall-first stance ("a false positive
  is safer than hiding a real finding"). If OSV's range is wrong, the fix belongs upstream in OSV.

**Hooks:** the OSV range parse in `adapter/osv/client.go` (`osvRange.Type`, `isUnusableRangeType`,
`extractAffectedVersions`, `extractFixVersions`); `domain.VersionMatches` for the constraint match.

---

#### KNOWN CHARACTERISTIC — RPM module fan-out vs Red Hat per-subpackage VEX (confirmed 2026-06-30, v0.3.5 E2E)

**Status:** expected behavior, **not a bug.** Documented so the `not_covered` state on module
subpackages is not re-investigated as a Red Hat VEX overlay failure. Decision (2026-06-30): keep
`not_covered` as the honest state — do **not** fabricate a vendor verdict from Red Hat's silence.

**Symptom (verified on the live Rocky-8 deployment):** for a module-scoped CVE, every binary
subpackage built from the module shows `upstream_vex_coverage: not_covered`, e.g. CVE-2026-48962
appears on 9 `perl-*` findings (perl-File-Path, perl-HTTP-Tiny, perl-Scalar-List-Utils,
perl-Term-ANSIColor, perl-MIME-Base64, perl-Data-Dumper, perl-Pod-Usage, perl-Pod-Escapes,
perl-constant) all `not_covered`, while `perl-IO-Compress` is `covered`.

**Why (two feeds, two granularities):**

- **Rocky OSV** records the CVE against the perl **module/SRPM**, so the Correlator fans it out to
  _every_ binary subpackage built from that module → findings on all siblings.
- **Red Hat Security Data API** tracks the CVE only under the genuinely-vulnerable subpackage
  (`affected_release` el8: `perl-IO-Compress-0:2.081-2.el8_10`) plus the module stream
  (`perl:5.32-8100020260616084412…`). It publishes **no** `package_state`/`affected_release` for
  the other subpackages.
- `domain.RedHatCVEReport.VerdictForStream` does an **exact** package-name match
  (`internal/domain/redhat_vex.go`), so the fanned-out siblings get `Covered=false` → no overlay
  assertion → `not_covered`. The exact-match path is correct; `perl-IO-Compress` is `covered`.

**Why we don't "fix" it by inferring a verdict:** Red Hat's _silence_ on a subpackage is not a
"Not affected" statement — inferring one would be a fabricated suppression, exactly the false-positive
risk the overlay design avoids (Themis surfaces vendor signals; it never auto-rescopes severity).
`not_covered` is the truthful state: the vendor made no per-subpackage statement.

**Verify the cycle ran (discriminating check):** `perl-IO-Compress` must be `covered` with a
`Red Hat: … on RHEL-8 …` justification:

```sh
psql "$THEMIS_DATABASE_DSN" -c "
SELECT rc.component_purl, rc.upstream_vex_coverage, va.status
FROM risk_context rc
LEFT JOIN vex_assertions va ON va.component_purl = rc.component_purl AND va.cve_id = rc.cve_id
WHERE rc.cve_id = 'CVE-2026-48962' AND rc.component_purl LIKE '%perl-IO-Compress%';"
```

**Deferred enhancements (not scheduled; both were considered and declined on 2026-06-30):**

- _Module-aware overlay_ — when Red Hat's CVE doc carries a _module_ `affected_release` for the
  stream (e.g. `perl:5.32`), attach an informational, context-only overlay to module-member
  siblings pointing at the module RHSA. Flips `not_covered → covered` as a breadcrumb but cannot
  reliably prove "fixed" (the component NEVRA's `.module+elN.M.0+<build>+<hash>` token is not
  directly comparable to the module context build `8100020260616084412`), so it adds little over
  honest `not_covered`. Hooks: `VerdictForStream` + `RedHatVEXService.buildAssertion`.
- _Distro-layer fix_ — stop the Correlator propagating a module-scoped CVE to siblings that don't
  contain the vulnerable code. Most correct but highest regression risk (touches the Correlator and
  distro-OSV mapping across all RPM modules: perl, httpd, …).

---

#### DEFECT (RESOLVED v0.3.6) — Red Hat VEX overlay falsely "resolved" RPM findings via minor-stream backports

**Status:** ✅ RESOLVED in v0.3.6 (PR #39). Security-critical correctness bug in the v0.3.5 Red Hat
VEX overlay: genuinely-vulnerable RPM findings were marked `fixed` → `effective_state=resolved`
(risk 0), **hiding live vulnerabilities** — the dangerous (under-reporting) failure direction.

**Symptom (live Rocky-8 deployment, 2026-06-30):** **25 findings** falsely resolved — 11 `python3`,
6 `openssh`, `libtiff`/`compat-libtiff3`, `glib2`, `libxml2`, … — each an `el8_10` install exactly
one release below the correct main-stream fix (e.g. libtiff `4.0.9-36.el8_10` vs fix
`4.0.9-37.el8_10`). Metric read `themis_redhat_vex_total{status="fixed"}=25, affected=7,
not_affected=0`; every `resolved` row had `installed < source_fixed_version`.

**Root cause:** `RedHatCVEReport.VerdictForStream` collapsed every `el8.*` CPE to major `"8"` (the
old `redHatCPEMajor` matched `enterprise_linux:` and `rhel_aus/eus/e4s/tus:` alike) and kept the
**last** `affected_release` it iterated — almost always an older minor-version-locked backport (e.g.
`4.0.9-29.el8_8.2`, the 8.8 E4S line). Comparing a rolling `el8_10` install (release 36) against
that backport (release 29) gave `installed >= fixed` → false `fixed`. A latent second bug masked it
for epoch-bearing packages: the `epoch=` PURL qualifier was dropped by `rpmInstalledVersion`, so an
epoch-2 install read as epoch 0 (libpng accidentally read "affected" for the wrong reason). The
minor-locked AUS/EUS/E4S/TUS streams are independent maintenance lines whose release numbers are not
comparable to a rolling install — the same class as the el8↔el9 cross-stream guard, one level deeper.

**Fix (v0.3.6):** `VerdictForStream` resolves against the **main `enterprise_linux:N` stream only**
(new `redHatMainStreamMajor`, excluding AUS/EUS/E4S/TUS and `enterprise_linux_eus`) and keeps the
**highest** main-stream fix EVR (order-independent, conservative — an install must clear every
published main-stream fix). `rpmInstalledVersion` folds the `epoch=` qualifier back into the EVR.
After the fix the main-stream fix EVR equals the distro feed's `source_fixed_version` (Rocky/Alma
rebuild RHEL 1:1), so the 25 resolve to `affected` → `confirmed`. Tests use real Red Hat fixtures
(libtiff false-resolution, el9 multi-z-stream max-fix, libpng epoch path). **Deploy:** rebuild +
restart; `UpsertAssertions` deletes-and-replaces the Red Hat feed's assertions on the next cycle, so
the stale `fixed` auto-correct (no manual SQL). See `docs/release-notes/release-notes-v0.3.6.md`. **Hooks:**
`domain/redhat_vex.go` (`VerdictForStream`, `redHatMainStreamMajor`),
`usecase/enrichment/redhat_vex.go` (`rpmInstalledVersion`).

---

#### ENHANCEMENT — Scoped vulnerability-listing endpoints (product / project / version) (v0.3.8)

**Status:** ✅ **DONE in v0.3.8.** Added `GET /api/v1/products/{id}/vulnerabilities`,
`GET /api/v1/projects/{id}/vulnerabilities`, and `GET /api/v1/products/{id}/versions/{v}/vulnerabilities`
(manual routes in `internal/adapter/api/mount.go`, alongside the vex/blast-radius endpoints),
returning the existing `ScanVulnerabilityList` shape with the same `severity`/`effective_state`/`cve_id`
filters + cursor pagination. Store: `PostgresScanQueryRepository.ListScopedVulnerabilities` drives off
`v_latest_findings` (latest scan per artifact) with a one-line scope predicate
(`proj.product_id` / `ver.project_id` / `proj.product_id + ver.version`); the SELECT/joins/row-scan are
shared with `ListScanVulnerabilities` (`scanVulnerabilitySelect`/`scanVulnerabilityJoins`/
`collectScanVulnerabilities`/`appendVulnerabilityFilters`). Per-artifact rows (the risk_context
identity); an optional `?dedupe=true` to collapse to unique CVEs is a deferred follow-on. Original
proposal below.

**Status (original):** proposed (2026-06-30). Today the only raw per-finding list is **scan-scoped**
(`GET /api/v1/scans/{id}/vulnerabilities`). There is no endpoint returning the rich findings list
for a product, project, or version — callers must resolve the latest scan first (via
`GET /projects/{id}/scans` → `.items[0]`), or use the VEX-format export
(`GET /products/{id}/versions/{v}/vex`, different shape).

**Proposed:** add `GET /products/{id}/vulnerabilities`, `GET /projects/{id}/vulnerabilities`, and
`GET /products/{id}/versions/{v}/vulnerabilities`, all returning the existing
`ScanVulnerabilityList` shape with the same `severity` / `effective_state` / `cve_id` filters +
cursor pagination.

**Why it is small:** `PostgresScanQueryRepository.ListScanVulnerabilities` (`adapter/store/catalog.go`)
already joins `component_vulnerabilities → scan_reports → vulnerabilities → risk_context →
component_versions → components → artifacts → versions → projects` and already maps the rich DTO.
The only scope restriction is one line — `WHERE cv.scan_report_id = $1`. Scoping by level is a
one-line WHERE swap (`a.version_id` / `ver.project_id` / `proj.product_id`) plus a
latest-scan-per-artifact filter, which the `v_latest_findings` view already encodes. Work: generalize
the store query to a scope param, 3 thin handlers + routes (`mount.go`), OpenAPI + `make
generate-api`, handler/store tests. **Non-breaking, no schema change** (~half-day with gates).

**Decision:** product/project span multiple artifacts, so the same `(component_purl, cve_id)` can
appear per-artifact (each a distinct deployment). Default to per-artifact rows (truthful — that is
the `risk_context` identity); optional `?dedupe=true` collapses to unique CVEs. For a version
(usually one artifact) it is moot. **Hooks:**
`PostgresScanQueryRepository.ListScanVulnerabilities`, `v_latest_findings`, `api.Handler`,
`internal/adapter/api/mount.go`, `api/openapi.yaml`.

---

#### Phase 2a — Signal Foundation (`themis-phase-2a`) — Complete (Archived 2026-06-17)

**Gate:** none outstanding (shipped ahead of the Group 16 hardening; see Release
versioning reconciliation above).
**Released as:** v0.2.0 (merged to `main` 2026-06-17; PR #16)
**OpenSpec change:** `openspec/changes/archive/2026-06-17-themis-phase-2a/`
**Progress:** 140/140 tasks complete (Groups 17–30). Archived.

**Implemented (Groups 17–29):**

- Domain types, migrations 000014–000019, Phase 2a config structs + env overrides
- **EPSS/KEV sync** — daily FIRST.org EPSS + CISA KEV fetch; `epss_kev_signals` table;
  retroactive `ReEnrichJob`; stale flag after 25h; `signals_stale` on status API
- **ExploitDB CSV** — `files_exploits.csv`; `exploit_records`; Layer 1 `ExploitPublic` rule
- **Layer 1 deterministic rules** — CVSS/KEV/EPSS/ExploitPublic → `deterministic_level`
- **Asset graph** — Microservice / Deployment / Customer entities + registration APIs
- **Layer 2 blast-radius** — graph traversal, score multiplier, team notifications,
  `GET /api/v1/products/{id}/blast-radius`
- **Composite risk score V2** — EPSS +30%, KEV +15, blast-radius multiplier, Critical override
  (**BREAKING** vs Phase 1 score thresholds)
- **Upstream VEX feeds** — Red Hat (CSAF), Alpine / Rocky / Wolfi (OSV); four-phase PURL
  matcher (apk + RPM); `upstream_vex_coverage` on `risk_context`; daily poll scheduler
- **VEX export** — `GET .../versions/{v}/vex` (CycloneDX 1.5+ / OpenVEX 0.2+);
  `GET .../vex-coverage`; precedence human > user > AI > upstream vendor
- **System status API** — `GET /api/v1/status?top=N` (live counts, top-N, `signals_stale`)
- **SBOM management** — `GET /api/v1/sboms`, `GET /api/v1/products/{id}/sboms`,
  `DELETE /api/v1/sboms/{id}?force=true` (soft-delete + audit log)
- **Error UX** — `{error: {code, message, hint}}` envelope on all endpoints; 12 catalogue codes
- **Acceptance gates** — AC-16..AC-24 integration tests; feed resilience FR1–FR8 mapped
- **Group 30 complete** — coverage gates, Prometheus metrics wiring, `verification.md` sync,
  `AGENTS.md` update, release notes, merge to `main`, `v0.2.0` tag

**Deferred from Phase 2a scope (see follow-ons below):**

- **GHSA integration** — config key `THEMIS_GITHUB_TOKEN` wired; adapter ships in Phase 2b
- **Debian/Ubuntu VEX feed matching** — separate matchers; apk/RPM path first

**What (original scope reference):**

- **EPSS/KEV sync** — daily CISA KEV + FIRST.org EPSS fetch; updates
  `intelligence_signals` with TTL; incorporates into risk score formula
- **ExploitDB CSV** — ingests `files_exploits.csv` from public GitHub mirror;
  CVE-to-EDB-ID lookup; feeds Layer 1 `ExploitPublic` rule
- **GHSA integration** — GitHub Security Advisories for ecosystem-precise fix
  versions (npm, Go, PyPI, Maven, etc.); extends the Phase 1 correlator
- **Upstream VEX feeds** — scheduled fetch from Red Hat, Alpine, Rocky Linux, Wolfi;
  applied as `vex_documents` with `source=upstream_vendor`; four-phase PURL normalisation
  for apk + RPM ecosystems (see Decision 15); Debian/Ubuntu deferred to follow-on (see below)
- **Layer 1 deterministic rules** — CVSS ≥ 9 ∧ KEV → Critical; CVSS ≥ 9 ∧
  ExploitPublic → High+; EPSS ≥ 0.5 ∧ CVSS ≥ 7 → Elevated; etc.
- **Microservice / Deployment / Customer entities** — new domain entities; registration
  APIs; resolves OQ-9 (registration workflow)
- **Layer 2 graph reasoning** — SQL traversal CVE → Package → Product → Microservice
  → Deployment → Customer; blast-radius scoring; team-level notifications
- **VEX export** — `GET /api/v1/products/{id}/versions/{v}/vex` CycloneDX or OpenVEX
- **System status API** — `GET /api/v1/status?top=N`: total components, CVE counts by
  severity/state, top-N components with most open vulnerabilities (name, product, CVE
  count, highest CVSS); answers "what is in Themis and what's most urgent?" in one call
- **SBOM management APIs** — `GET /api/v1/sboms`, `GET /api/v1/products/{id}/sboms`
  (paginated listings); `DELETE /api/v1/sboms/{id}` (soft-delete with force flag for
  latest SBOM; `deleted_at` tombstone; audit log entry)
- **Layman-friendly error responses** — three-field error envelope (`code`, `message`,
  `hint`) across all API endpoints; no raw DB errors or Go strings in responses
- **Cold-start fixes** — G2 (EPSS/KEV retroactive score update), G6 (NVD warmup)

**Why deferred from Phase 1:** risk score formula change and graph entity additions
are breaking changes that require the Phase 1 pipeline to be stable first.

**Phase 1 hooks:**

- `intelligence_signals` table has `signal_type`, `score`, `expires_at` columns
- `vex_documents.source` column distinguishes source tiers
- `watch/` scheduler pattern cloneable for EPSS/KEV + vendor VEX sync
- `JobQueue` interface for async tasks already in place
- `risk_context` has `epss_score`, `kev_listed` columns (populated NULL today)

**Database migrations:** 000014–000019 (graph entities, `epss_kev_signals`, Phase 2a
`risk_context` columns, indexes, SBOM soft-delete, vendor VEX feed tables)

**Post-2a follow-on — Vendor VEX feed operations:**

| Item | Why deferred | Phase 1 / 2a hooks |
| ---- | ------------ | -------------------- |
| Per-feed enable/disable (`vexfeed.rhel_enabled`, etc.) — **now folded into `themis-feed-registry`** (see Candidate change below) | Phase 2a wires all four feeds; operators may want to disable Wolfi/Rocky in non-RHEL shops | `VEXFeedConfig` URLs already per-feed; add bool flags in config + skip in `api_wiring.go` |
| Red Hat CSAF directory crawl | Default `rhel_url` points at the CSAF advisories _directory_; production may need a manifest/bundle URL or crawler over individual `.json` files | `URLFeedSource` + `ParseCSAF` accept single-document bodies today |
| Alpine vendor OSV feed URL returns 302 | Default `alpine_osv_url` (`gitlab.alpinelinux.org/.../v1/`) redirects to GitLab sign-in (HTTP 302), not public JSON. Observed: `themis_vexfeed_sync_total{feed="alpine",status="error"}` while Wolfi succeeds. `vex-coverage` stays `{covered:0, not_covered:N}` for Alpine SBOMs. | `URLFeedSource` in `api_wiring.go`; `themis.yaml.example` `alpine_osv_url` |
| Rocky vendor OSV feed URL 404 | Default `rocky_osv_url` (`apollo.build.resf.org/vulns/rocky-linux-osv.json`) returns HTTP 404. Working sources exist elsewhere (see fix below). | `rocky_osv_url` default in `config.go` / `themis.yaml.example` |
| `ParseOSVFeed` skips `ALPINE-CVE-*` advisory IDs | `firstCVE()` only accepts `aliases` or `id` starting with `CVE-`. Alpine OSV records use `id: ALPINE-CVE-YYYY-NNNN` with empty `aliases` — assertions are dropped even when feed body parses. Companion to OSV ingestion CVE normalization. | `adapter/vexfeed/osv.go` `firstCVE()` |
| Cron-style `sync_schedule` (vs poll interval) | Schedulers use `time.NewTicker` + `poll_interval` (same as EPSS/ExploitDB); cron strings not implemented | `StartVEXFeedScheduler`, `StartEPSSKevScheduler` |
| README + `themis.yaml.example` Phase 2a config docs | Operator discoverability | **Done** — see README Configuration and `themis.yaml.example` |

**How to fix vendor VEX feed fetch (Alpine / Rocky / RHEL):**

Themis `URLFeedSource` does one `GET` and expects a single JSON/CSAF document. Default URLs are
directories, login redirects, or dead links — not documents.

| Feed | Broken default | Working source (verified) | Code / config fix |
| ---- | -------------- | ------------------------- | ----------------- |
| **Alpine** | GitLab `.../v1/` → 302 | `https://storage.googleapis.com/osv-vulnerabilities/Alpine/all.zip` (200, zip of OSV JSON) or per-advisory `https://storage.googleapis.com/cve-osv-conversion/alpine/ALPINE-CVE-*.json` | Add `ZipOSVFeedSource` (download + unzip + `ParseOSVFeed` each file) **or** periodic sync from GCS; update default `alpine_osv_url` / env `THEMIS_VEXFEED_ALPINE_OSV_URL`. GitLab raw tree is not a public unauthenticated feed. |
| **Rocky** | `apollo.../rocky-linux-osv.json` → 404 | `https://storage.googleapis.com/osv-vulnerabilities/Rocky%20Linux/all.zip` (200) or `https://storage.googleapis.com/resf-osv-data/{RLSA-id}.json` | Same zip/crawl pattern; update default `rocky_osv_url`. Optional: Apollo `GET /api/v3/osv/` list + per-id fetch (needs new `ListFeedSource`). |
| **RHEL** | Directory URL → 301 + HTML index | `https://security.access.redhat.com/data/csaf/v2/advisories/` returns HTML listing of `*.json` files | Add `CSAFDirectoryFeedSource`: fetch index, parse advisory links, fetch each CSAF JSON, merge via existing `ParseCSAF`. Cannot fix with URL override alone. |
| **Wolfi** | — | `https://packages.wolfi.dev/os/security.json` (200) | No change — already works. |

**Operator workaround (until code ships):** none for Alpine/RHEL/Rocky — all require fetch-model
changes. Wolfi-only sync does not cover `apk` SBOMs.

**After feeds load — still required for Alpine SBOM end-to-end:**

1. **`ParseOSVFeed.firstCVE()`** — extract `CVE-*` from `ALPINE-CVE-*` (and use `aliases` when present).
2. **`mapOSVVuln` CVE normalization** — store canonical `CVE-*` in `vulnerabilities.cve_id` (see follow-on below).
3. **OSV CVSS vector parsing** — populate severity + `cvss_score` (see follow-on below).
4. **Re-sync / re-enrich** — restart server or wait for poll; optional backfill SQL for existing rows.

**Verify after fix:**

```sh
curl -s "$BASE_URL/metrics" | grep themis_vexfeed_sync_total
# expect: alpine/rhel/rocky status="success"

curl -s "$BASE_URL/api/v1/products/$PRODUCT_ID/versions/1.0.0/vex-coverage" -H "X-API-Key: $API_KEY" | jq .
# expect: covered + purl_mismatch > 0 (not all not_covered)
```

**Post-2a follow-on — Debian/Ubuntu VEX feed matching:**

Debian (DSA format, dpkg version ordering with tilde rules and epochs) and Ubuntu
(USN format, per-series version ranges per `jammy`/`focal`/`noble`) are excluded from
Phase 2a scope because they use formats and version comparators that differ from
apk/RPM. The four-phase `Matcher` interface defined in Phase 2a supports adding
Debian/Ubuntu as new `Matcher` implementations with no changes to the shared matching
logic or VEX assertion storage. Implement after Phase 2a ships and the apk/RPM path
is validated in production.

**Post-2a follow-on — OSV CVSS vector parsing:**

| Item | Why deferred / impact | Phase 1 / 2a hooks |
| ---- | --------------------- | -------------------- |
| Parse CVSS vector strings from OSV `severity[].score` | OSV (Alpine, npm, GHSA, etc.) returns `CVSS:3.1/AV:N/...` vectors, not numeric scores. `mapOSVVuln` in `adapter/osv/client.go` uses `fmt.Sscanf("%f")` and only accepts plain floats — real feed data leaves `vulnerabilities.cvss_score = 0` and `severity = unknown`. `GET /api/v1/status?top=N` then reports `highest_cvss_score: 0` in `top_components` even when `vulnerability_count` is correct (status reads raw catalog CVSS, not composite `risk_score`). Layer 1 rules and enrichment fallbacks also miss CVSS-derived severity until fixed. | `ComponentFetcher` + `mapOSVVuln`; `vulnerabilities.cvss_score` / `cvss_vector` columns; status query `MAX(v.cvss_score)` in `adapter/store/status.go`; unit test uses simplified numeric `"7.5"` score only |

**Fix:** In `internal/adapter/osv/client.go`, detect vector-form scores (prefix `CVSS:`), compute or
look up the base score (CVSS v3/v4 parser or NVD backfill), store numeric score and vector on
upsert. Optionally accept `CVSS_V4` severity type. Re-upsert or migration backfill for existing
catalog rows.

**Post-2a follow-on — OSV Alpine CVE ID normalization:**

| Item | Why deferred / impact | Phase 1 / 2a hooks |
| ---- | --------------------- | -------------------- |
| Normalize OSV Alpine IDs (`ALPINE-CVE-YYYY-NNNN`) to canonical `CVE-YYYY-NNNN` | Alpine OSV returns vulnerability IDs with an `ALPINE-` prefix. `mapOSVVuln` stores them as-is in `vulnerabilities.cve_id`. EPSS, KEV, and ExploitDB feeds key on standard `CVE-*` IDs — `GetEPSSForCVE` / `IsKEVListed` / `HasPublicExploit` in `ReEnrichSignalsBatch` do exact-match lookup and miss every Alpine finding. Observed on real Alpine SBOM bring-up: 592/592 export IDs prefixed `ALPINE`, `with_epss: 0` and `with_kev: 0` in VEX export despite successful sync metrics (`themis_epsskev_sync_total{status="success"}`, `themis_reenrichjob_batches_total ≥ 1`). Vendor VEX and CVE watch correlation may also fail to join on the same CVE across sources. | `mapOSVVuln` in `adapter/osv/client.go`; `vulnerabilities.cve_id` (unique constraint); `ReEnrichSignalsBatch` + `CombinedSignalReader`; `epss_kev_signals.cve_id`; VEX export `x-themis-epss-score` / `x-themis-kev-listed` via `risk_context` |

**Fix:** In `mapOSVVuln` (or a shared `NormalizeCVEID` helper in `domain/`), strip known OSV
ecosystem prefixes (`ALPINE-`, and similar) when the remainder is a valid `CVE-*` ID; store
canonical `cve_id` on upsert. Optionally retain the OSV-native ID in `description` or a future
alias column. Add lookup fallback in signal readers (`GetEPSSForCVE`) for defence in depth.
Backfill existing `ALPINE-CVE-*` rows via one-off migration or re-ingest. **Companion fix:** CVSS
vector parsing (above) — both gaps must land for Alpine SBOMs to show non-zero risk and EPSS in
VEX export.

**Post-2a follow-on — Operator onboarding (product / image model):**

| Item | Why deferred / impact | Phase 1 / 2a hooks |
| ---- | --------------------- | -------------------- |
| Product version not created on SBOM upload | README walkthrough creates product → project → image → upload but never `product_versions`. `GET /api/v1/products/{id}/versions` returns empty; `GET .../versions/{v}/vex` 404 until operator runs SQL to insert a version and set `artifacts.product_version_id`. SBOM list shows `product_version: ""` until wired. Blocks VEX export and `vex-coverage` without manual DB steps. | `product_versions` table (migration 000001); VEX export join in `adapter/store/vexexport.go`; `ListProductSBOMs` reads `pv.version`; OpenAPI has `listProductVersions` only — no create. **Fix:** Group 16.10 — `POST /products/{id}/versions` plus optional auto-version on upload (e.g. from CI tag or default `1.0.0`) and link `artifacts.product_version_id` from `image_id`. |
| Image registration still SQL-only | Same README path; no REST until Group 16.4. Operators must `INSERT INTO images` before upload or trust gate rejects. | Group 16.4; `images` + `artifacts` tables |

**Post-2a follow-on — Scan findings API (Phase 2a enrichment fields):**

| Item | Why deferred / impact | Phase 1 / 2a hooks |
| ---- | --------------------- | -------------------- |
| `GET /api/v1/scans/{id}/vulnerabilities` omits Phase 2a fields | Response includes only `id`, `cve_id`, `severity`, `effective_state`, `component_purl`, `product_id`. Operators verifying Step 4 (EPSS/KEV/Layer 1) must use SQL on `risk_context`, VEX export (`x-themis-*`), or `/metrics` — not the primary findings API. README testing path ends at scan vulnerabilities list, so Phase 2a value is invisible there. | `domain.ScanVulnerability`; `PostgresScanQueryRepository.ListScanVulnerabilities`; `handlers_catalog.go` + OpenAPI `ScanVulnerability` schema. **Fix:** join `risk_context` in list query; expose `risk_score`, `epss_score`, `kev_listed`, `exploit_public`, `deterministic_level`, `blast_radius_score`, `upstream_vex_coverage` (or a nested `enrichment` object). Update OpenAPI + mapper tests. |

**Post-2a follow-on — ExploitDB signal observability:**

| Item | Why deferred / impact | Phase 1 / 2a hooks |
| ---- | --------------------- | -------------------- |
| ExploitDB sync not visible on JSON APIs; no dedicated metric | ExploitDB CSV sync populates `exploit_records` and drives `exploit_public` + Layer 1 via `ReEnrichSignalsBatch`, but unlike EPSS/KEV there is no `signals_stale`-style flag, no `themis_exploitdb_*` Prometheus counter in Group 30 wiring, and no field on scan or VEX export responses. Operators cannot confirm ExploitDB impact with curl-only Step 4 checks. | `adapter/exploitdb/`; `CombinedSignalReader.HasPublicExploit`; `risk_context.exploit_public`. **Fix:** add `themis_exploitdb_sync_total` metric; optionally include `x-themis-exploit-public` on VEX export and/or scan list field `exploit_public`. |

**Post-2a — Alpine SBOM bring-up release gate (manual E2E checklist):**

Validates the README upload path on real Alpine images before claiming `v0.2.0` is operator-ready.
Integration tests (AC-16..24) use synthetic CVE IDs and stub feeds — they do not catch these gaps.

| # | Check | Pass criteria | Known failure today (Jun 2026 bring-up) |
| - | ----- | ------------- | ---------------------------------------- |
| G1 | EPSS/KEV sync | `themis_epsskev_sync_total` success for `epss` and `kev` feeds; `signals_stale: false` | **Pass** |
| G2 | Vendor VEX sync | `themis_vexfeed_sync_total{feed="alpine",status="success"} ≥ 1` | **Fail** — alpine/rhel/rocky `error`; wolfi only |
| G3 | VEX export reachable | `GET .../versions/{v}/vex` returns `total > 0` without manual SQL | **Fail** until Group 16.10 / SQL wiring |
| G4 | EPSS on findings | VEX export `with_epss > 0` OR scan API shows `epss_score` | **Fail** — `with_epss: 0` (592 × `ALPINE-CVE-*`) |
| G5 | Risk scores | VEX export `with_risk > 0` OR scan API shows `risk_score > 0` | **Fail** — CVSS vectors not parsed |
| G6 | Vendor VEX coverage | `vex-coverage` has `covered > 0` or export states include `not_affected` | **Fail** — `{covered:0, not_covered:592}` |
| G7 | Status CVSS | `top_components[].highest_cvss_score > 0` when findings exist | **Fail** — same CVSS gap |
| G8 | Layer 1 visible | Scan or export shows non-`informational` `deterministic_level` where KEV/EPSS/CVSS warrant | **Fail** — blocked by G4/G5 |

**Code fixes required to clear G2–G8 on Alpine:** vendor feed fetch (zip/crawl — see above),
`ParseOSVFeed.firstCVE()`, `mapOSVVuln` CVE normalization, OSV CVSS vector parsing; optional
Group 16.1 (package names) for higher vendor match rate.

**Operator-only workarounds until code ships:** SQL for product version (G3); no workaround for
G2/G4/G5/G6/G7/G8 on Alpine OSV findings.

---

#### Pre-Phase 2b Gate — Feed Reliability and Signal Quality (Group 31 — 8 tasks BLOCKING)

Identified during the intel-source-tiers cross-check after Phase 2a was declared complete.
All 8 tasks must close before Phase 2b implementation begins. Tracked in
`openspec/changes/archive/2026-06-17-themis-phase-2a/tasks.md` §31.
Reference: `openspec/intel-source-tiers.md`.

##### 31a — OSV / Alpine CVE normalization

| # | Task | Root cause |
| - | ---- | ---------- |
| 31.1 | Normalize `ALPINE-CVE-*` IDs to `CVE-*` in `mapOSVVuln` (`internal/adapter/osv/`) | 592/592 Alpine findings show `with_epss: 0` — EPSS/KEV join never matches `ALPINE-CVE-*` form |
| 31.2 | Fix `ParseOSVFeed.firstCVE()` to strip `ALPINE-CVE-` prefix | Alpine advisories silently dropped because `firstCVE()` only accepts `CVE-*` prefix |
| 31.3 | Fix OSV CVSS vector parsing — replace `fmt.Sscanf("%f")` with proper vector parser | `CVSS:3.1/AV:N/...` strings not parsed; all CVSS scores = 0; Layer 1/G5/G7 blocked |

##### 31b — Vendor feed URL fixes

| # | Task | Root cause |
| - | ---- | ---------- |
| 31.4 | Alpine OSV: update default URL to GCS zip; wire `ZipOSVFeedSource` | Default URL returns HTTP 302 (GitLab login redirect) |
| 31.5 | Rocky Linux OSV: update default URL to GCS zip | Default URL returns HTTP 404 |
| 31.6 | Red Hat CSAF: implement `CSAFDirectoryFeedSource` to crawl advisory index | Default URL returns HTML directory listing; cannot fix with URL override alone |

##### 31c — ExploitDB signal wiring

| # | Task | Root cause |
| - | ---- | ---------- |
| 31.7 | Expose `exploit_public` in scan findings API response | Adapter exists; `exploit_public` invisible to operators via primary API |
| 31.8 | Wire `themis_exploitdb_sync_total` Prometheus counter in ExploitDB scheduler | Listed in Group 30.2 but counter not emitted; sync success unverifiable via `/metrics` |

##### Alpine E2E bring-up gate (G1–G8)

**v0.2.1 code landed** (OpenSpec `themis-v0-2-1`); verified 2026-06-17 via integration tests
(`TestV021*`) + local `./scripts/run-alpine-e2e-local.sh` (G2 metrics) + `./scripts/alpine-e2e-gate.sh`:

| Check | Pre-v0.2.1 | v0.2.1 (expected after deploy + backfill) | Verified 2026-06-17 |
| ----- | ---------- | ------------------------------------------- | ------------------- |
| G1 EPSS/KEV sync | PASS | PASS | **PASS** (metrics; local run may need ≥120s warm-up) |
| G2 Vendor VEX sync (Alpine/Rocky/RHEL) | **FAIL** | **PASS** (zip + CSAF directory sources) | **PASS** (`themis_vexfeed_sync_total{feed="alpine",status="success"}`) |
| G3 VEX export without manual SQL | **FAIL** | **FAIL** — still requires `themis-core-model` | **FAIL** (404 without product-version wiring) |
| G4 EPSS on Alpine findings | **FAIL** | **PASS** (CVE normalize + backfill + re-enrich) | **PASS** (`TestV021AlpineEPSSAfterReEnrich`) |
| G5 Risk scores > 0 | **FAIL** | **PASS** (CVSS vector parsing) | **PASS** (integration + OSV CVSS unit tests) |
| G6 Vendor VEX coverage > 0 | **FAIL** | **PASS** (after G2 + PURL match) | **PASS** (`TestV021ZipVendorVEXFeedLoadsAssertions`) |
| G7 Status `highest_cvss_score > 0` | **FAIL** | **PASS** | **PASS** (CVSS vector parsing in `mapOSVVuln`) |
| G8 Layer 1 `deterministic_level` non-informational | **FAIL** | **PASS** (after G4 + G5) | **PASS** (integration re-enrich with KEV/EPSS stubs) |

**Operator checklist:** `./scripts/run-alpine-e2e-local.sh` (embedded Postgres + server) or
`./scripts/alpine-e2e-gate.sh` against an existing deployment after Alpine SBOM upload.

---

#### DEFECT D-CVSS-1 — CVSS/severity never enriched for OSV-origin (apk/rpm) findings (BLOCKING Phase 2b)

**Status:** ✅ RESOLVED (2026-06-24) — implemented as **CR-5** (NVD `FetchByCVEID` CVSS
backfill + ReEnrich propagation + interim risk floor) and **CR-4** (distro feeds now carry
severity into correlation findings). All gates green on branch `themis-phase-2`. Phase 2b is
unblocked. _Remaining: G1–G8 verification on a real Alpine/RPM deployment (operational E2E)._
The original analysis below is retained for history.
**Severity:** High (functional — blocks prioritisation for the primary Alpine/apk use case).
**Found:** 2026-06-21, during the v0.3.0 Layer 0 audit (the same audit that fixed the
correlation over-match, the double-versioned `component_purl`, and risk-score saturation —
see PR #23). This defect is **separate** from those three and was surfaced by them: once
correlation and vendor-VEX matching were correct, every remaining apk finding still showed
`severity=unknown`, `cvss_score=0`, `risk_score=0`.

**Symptom (verified on a real Alpine SBOM, server running 5h):**

- `GET /api/v1/status` → `by_severity: { unknown: 34 }`; all `top_components` have
  `highest_severity: "unknown"`, `highest_cvss_score: 0`.
- `vulnerabilities` catalog rows confirm it at source — even long-established CVEs that NVD
  scored years ago are empty:

  ```text
  cve_id          | severity | cvss_score | cvss_vector
  CVE-2025-31498  | unknown  |    0.0     | (empty)
  CVE-2016-9594   | unknown  |    0.0     | (empty)
  CVE-2023-*      | unknown  |    0.0     | (empty)
  ```

- Finding-year spread is mostly 2015–2024 (45 of ~50), so this is **not** upstream NVD lag
  ("awaiting analysis" only plausibly explains the 2 × 2025 + 3 × 2026 entries).
- Net effect: 34 vendor-VEX-**confirmed** (still-vulnerable) findings all score `0` →
  prioritisation is impossible; `risk_score` carries no signal for apk SBOMs.

**Root cause (verified in code):**

1. apk/rpm findings are correlated via **OSV**, and Alpine OSV carries no CVSS, so
   `mapOSVVuln` stores `severity=unknown`, `cvss_score=0` (`adapter/osv/client.go`). The
   v0.2.1 OSV CVSS-vector parser only helps when the OSV record _has_ a vector; Alpine
   usually does not.
2. NVD enrichment is a **time-windowed, CPE-based watch**: the client exposes only
   `FetchModifiedSince` and matches by CPE (`adapter/nvd/client.go` — `FetchModifiedSince`,
   `parseCPEPackage`/`cpeVendorToEcosystem`). There is **no fetch-by-CVE-ID path**, so it
   never backfills CVSS for historical CVEs, and apk packages don't align with NVD CPE names
   anyway. The catalog rows therefore stay `unknown`/`0` indefinitely.
3. Scoring is correct given the input: `ComputeRiskScoreV2` returns `0` when base severity is
   unknown (`base == 0`) — so unknown severity propagates straight to `risk_score = 0`.

**Why it blocks Phase 2b:** the AI knowledge layer (RAG, exploitability/triage workers,
KB-first reuse, AI-assisted VEX thresholds) consumes `severity`/`cvss_score`/`risk_score` as
input signals and as the basis for confidence/ordering. Seeding and tuning AI workers against
an all-`unknown`/all-`0` corpus makes it impossible to tell AI error from missing-data error
— the same reason Phase 2a had to land before 2b. Garbage-in here means garbage KB.

**Proposed fix (new capability — NVD CVSS backfill by CVE ID):**

1. Add an NVD client method for the by-ID endpoint (`/cves/2.0?cveId=CVE-…`) returning
   `severity`/`cvss_score`/`cvss_vector`.
2. Add a backfill enrichment job: select `vulnerabilities` where
   `cvss_score = 0 OR severity = 'unknown'`, fetch each from NVD, update the row; then
   `ReEnrichJob` recomputes `risk_score`. Rate-limited; `THEMIS_NVD_API_KEY` strongly
   recommended. Record "checked, still none" with a retry-after so genuinely un-scored
   (very recent) CVEs don't loop.
3. On-demand trigger + scheduler wiring; metric (`themis_cvss_backfill_*`).

**Interim mitigation (optional, decouples operator value from the backfill):** apply a
non-zero risk-score floor for findings that are vendor-VEX **confirmed** or **KEV-listed** so
a confirmed-vulnerable finding never scores `0` while severity is unknown (today
`base == 0 → score 0` hides them). Small change in `ComputeRiskScoreV2` / its caller.

**Acceptance:** after backfill on the Alpine test SBOM — `by_severity` is no longer
all-`unknown`; `cvss_score > 0` for CVEs NVD has scored; `risk_score` spreads across the 34
confirmed findings; `GET /api/v1/status` `top_components[].highest_cvss_score > 0`. Clears the
old Alpine E2E gate checks G5/G7/G8 for OSV-origin findings.

**Sequencing:** fix **before** opening `themis-phase-2b`. Candidate change name:
`themis-nvd-cvss-backfill`. Related: the original "OSV CVSS vector parsing" and "OSV Alpine
CVE ID normalization" follow-ons above (those landed in v0.2.1 but only cover OSV-supplied
vectors, not NVD backfill).

> **Consolidated → CR-5** (with CR-4 distro severity + CR-2 correlation) in the
> "Layer-0 Correctness & Observability Refactor (CR-1 … CR-10)" section below — the single
> source of truth for execution; the `themis-nvd-cvss-backfill` name is retained here for history.

---

#### DEFECT D-FEED-1 — Vendor "VEX" feeders conflate three feed classes; OSV/RHSA correlation data is miscategorised as VEX overlay (architectural)

**Status:** ✅ RESOLVED (2026-06-24) — implemented as **CR-4** (feed taxonomy split
`rhel_vex_url`/`rhel_csaf_url`; Alpine/Rocky/Wolfi OSV + RHSA advisories re-layered as
correlation sources carrying severity + fixed version; overlay now carries only true Red Hat
CSAF VEX; `csaf.go` "known affected" typo fixed; RHSA NEVRA range extraction). All gates green
on branch `themis-phase-2`. The original analysis below is retained for history.
**Severity:** High (architectural / correctness) — Themis currently consumes **zero true
vendor VEX**, runs a second hidden correlation engine inside the VEX overlay, and discards the
distro-authoritative data that would resolve [D-CVSS-1]. Not a crash; a wrong-by-design data flow.
**Found:** 2026-06-21, during the v0.3.0 Layer-0 "feeders correct in all aspects" audit (same
audit that raised D-CVSS-1 and the NVD over-match findings, see Companion defects below).
**Surfaced by:** review of the `vexfeed:` config block — the operator-proposed config that
splits Red Hat VEX from Red Hat advisories and labels the OSV URLs "not VEX" is, in fact, the
correct taxonomy; the current code does not honour it.

##### The core problem (one line)

The `vexfeed` config bucket lumps together **three fundamentally different feed classes** and
treats all of them as "vendor VEX," when only one of them is VEX. Two of the three are
**vulnerability-correlation** sources that belong in Layer 0 (finding creation/enrichment),
not in the VEX overlay (Layer 2/3 exploitability context).

| Feed (config key) | Default endpoint | What it actually is | Correct layer | What Themis does today |
| ----------------- | ---------------- | ------------------- | ------------- | ---------------------- |
| `rhel_url` | `…/csaf/v2/`**`advisories`**`/` ([config.go:182]) | RHSA **advisory** (which fix lands in which RPM NEVR) — _correlation_ | L0 correlation (rpm) | parsed as VEX ([csaf.go]) |
| _(missing)_ `rhel_vex_url` | `…/csaf/v2/`**`vex`**`/` | Red Hat's **actual VEX** (affected / not_affected / fixed + justification) — _exploitability context_ | **VEX overlay** | **not consumed at all** |
| `alpine_osv_url` | Alpine OSV `all.zip` | OSV **vulnerability DB** (affected ranges + fixed version) — _correlation_ | L0 correlation (apk) | parsed → `VEXStatusAffected`, applied as overlay |
| `rocky_osv_url` | Rocky OSV `all.zip` | OSV vulnerability DB (rpm) — _correlation_ | L0 correlation (rpm) | same |
| `wolfi_osv_url` | Wolfi `security.json` | OSV vulnerability DB (apk) — _correlation_ | L0 correlation (apk) | same |

##### Root cause (verified in code)

1. **Only one config field for Red Hat, pointed at the wrong endpoint.** `VEXFeedConfig`
   ([config.go:113-117]) has a single `RHELURL`, defaulting to the **advisories** directory
   ([config.go:182]). Red Hat's true VEX lives at the sibling `…/csaf/v2/vex/` and has **no
   config key and no adapter wiring** — so Themis ingests RHSA advisories _as if_ they were
   VEX and never sees the real VEX stream.
2. **The OSV distro feeds are forced into the VEX model.** [osv.go:41] emits every parsed OSV
   range as `domain.VEXStatusAffected`; the matcher's [matchAlpineOSV] →
   [alpineRangeStatus] then recomputes affected/not_affected purely from
   `installed` vs `introduced`/`fixed`. That is **version-range correlation** — the identical
   question the L0 OSV.dev live query already answers in [component_fetcher.go]. Result: two
   parallel correlation engines, two sources of truth for the same finding, with the distro one
   masquerading as a vendor exploitability verdict.
3. **The carrier type has nowhere to put severity, and the parser never reads it.**
   `VendorVEXAssertion` ([risk_phase2a.go:34-45]) carries `Status/Introduced/Fixed` but **no
   `Severity`/`CVSSScore`/`CVSSVector`**; `osvEntry` ([osv.go:51-55]) only unmarshals
   `id/aliases/affected` and **drops the OSV `severity` / `database_specific` blocks**. So even
   where a distro feed carries CVSS, it is fetched and thrown away.
4. **`vex-coverage` semantics are overstated.** Because (2) routes range math through the VEX
   path, `upstream_vex_coverage` (`covered`/`not_covered`/`purl_mismatch`) reads as "vendor
   analysed this CVE" when it actually means only "installed version ≥ the fixed version."

##### Why it matters / impact (live today)

- **No real vendor VEX.** The single source of genuine, non-derivable exploitability context
  (Red Hat CSAF VEX) is unused. Everything labelled "vendor VEX" is version-range correlation
  wearing a VEX label — misleading to operators and to anyone tuning Phase 2b/2c off VEX
  precedence.
- **Directly half of [D-CVSS-1].** The Alpine/Rocky/Wolfi feeds are the _authoritative_ apk/rpm
  source for affected ranges and fixed versions (and sometimes severity). Themis already
  downloads them, then discards everything except the range verdict. D-CVSS-1 is therefore not
  only "NVD has no by-CVE backfill" — the apk/rpm data is **in hand and discarded at the wrong
  layer**.
- **rpm correlation gap persists.** OSV.dev live queries skip `rpm` (see "SBOM correlation, OSV,
  and Linux distros" in the README); RHSA advisories + Rocky OSV are exactly the rpm correlation
  source — but they're trapped in the overlay, so rpm SBOMs still get few/no findings from them.
- **Two-source-of-truth fragility.** When the distro OSV feed and OSV.dev disagree on ranges, an
  L0 finding from one can be silently flipped not_affected by the other — non-obvious, with no
  provenance trail of _which_ source decided.

##### Companion / latent bug found in the same path

- **`csaf.go` status typo (dangerous direction).** [csaf.go:54] groups `"known affected"`
  (space variant) with the **not_affected** cases, so it would flip a real finding to
  suppressed. CSAF uses the underscore form `known_affected` (handled correctly at
  [csaf.go:56]), so it does not fire on real data today — but it is the unsafe direction and
  should be corrected when this area is touched.

##### Proposed fix (staged)

1. **Config taxonomy split (cheap, unambiguously correct).** Replace single `rhel_url` with
   `rhel_vex_url` (true VEX, overlay) **and** `rhel_csaf_url` (advisories, correlation); keep
   `alpine_osv_url` / `rocky_osv_url` / `wolfi_osv_url` but **reclassify them as OSV correlation
   feeds, not VEX**. Document each line's class. This is the operator-proposed YAML shape.
   Reconcile with the `themis-feed-registry` candidate (a feed's _class_ — `vex` vs `osv` vs
   `csaf-advisory` — becomes a first-class field, like `tier`).
2. **Re-layer the feeders (the real fix).** Route distro OSV + RHSA advisories into the
   **correlation / enrichment** path (create/enrich `component_vulnerabilities`, capturing
   severity + authoritative fixed version → resolves D-CVSS-1 for apk/rpm and fills the rpm
   gap). Keep **only** Red Hat CSAF VEX (`/vex/`) — and later Debian/Ubuntu VEX — on the VEX
   overlay. Add a `Severity`/`CVSSScore`/`CVSSVector` carrier (or feed directly into the catalog
   upsert) and parse the OSV `severity` block.
3. **Provenance.** When two correlation sources (OSV.dev, distro OSV, RHSA) can produce the same
   `(component_purl, cve_id)` finding, record `source` / `found_by` so verdicts are traceable and
   merge precedence is explicit (ties to the aggregator/provenance reframe noted below).

##### Acceptance criteria

- A real Red Hat CSAF **VEX** document (`…/csaf/v2/vex/`) is ingested and visible as an overlay
  with `source=upstream_vendor` and a real justification — distinct from advisory-derived data.
- Alpine/Rocky/Wolfi OSV + RHSA advisories produce **findings/enrichment** (with severity + fixed
  version), not overlay assertions; `cvss_score > 0` for apk/rpm CVEs the distro feed scores.
- `upstream_vex_coverage` reflects only _actual VEX_ coverage, not version≥fix range math.
- rpm SBOMs gain findings from RHSA/Rocky correlation.
- `csaf.go` `"known affected"` mapping corrected to `affected`.

##### Sequencing & relationships

- **Next change cycle** — after v0.2.1 testing closes. Candidate change name: `themis-feed-layering`.
  **Consolidated → CR-4** (with CR-2 correlation core + CR-3 provenance) in the Layer-0 Refactor
  section below (single source of truth for execution).
- **Strongly consider folding the distro-OSV-as-correlation work into [D-CVSS-1]'s
  `themis-nvd-cvss-backfill`** — they fix the same apk/rpm severity gap from two angles (NVD
  by-CVE backfill vs distro feed as authoritative correlation). Decide whether one change or two.
- Related candidates above: **`themis-feed-registry`** (feed class becomes a config field) and
  **`themis-feed-observability`** (per-feed health) — this defect changes the _shape_ of the feed
  set both of those build on; sequence accordingly.
- Cross-refs: the deferred SBOM-vs-image-scan / correlator-vs-aggregator reframe (provenance
  `source` column) is the same provenance need as fix step 3.

[D-CVSS-1]: #defect-d-cvss-1--cvssseverity-never-enriched-for-osv-origin-apkrpm-findings-blocking-phase-2b
[config.go:113-117]: internal/infrastructure/config/config.go#L113-L117
[config.go:182]: internal/infrastructure/config/config.go#L182
[csaf.go]: internal/adapter/vexfeed/csaf.go
[csaf.go:54]: internal/adapter/vexfeed/csaf.go#L54
[csaf.go:56]: internal/adapter/vexfeed/csaf.go#L56
[osv.go:41]: internal/adapter/vexfeed/osv.go#L41
[osv.go:51-55]: internal/adapter/vexfeed/osv.go#L51-L55
[matchAlpineOSV]: internal/adapter/vexfeed/matcher.go#L118
[alpineRangeStatus]: internal/adapter/vexfeed/matcher.go#L153
[component_fetcher.go]: internal/adapter/osv/component_fetcher.go
[risk_phase2a.go:34-45]: internal/domain/risk_phase2a.go#L34-L45

---

#### DEFECT D-FEED-2 — Intel source-tier taxonomy is docs-only; feed failure behaviour is not tier-differentiated

**Status:** 🔶 OPEN (found 2026-07-23, during the feed end-to-end verification —
`docs/current-changes/FEED-E2E-VERIFICATION.md`).

**Severity:** Low (operability) — not currently biting (all feeds healthy), but a **tier-3** "gold" feed
failing (e.g. ExploitDB) surfaces identically to a **tier-1** critical feed failing, so operators cannot triage
a degraded signal by importance.

**Symptom:** `openspec/intel-source-tiers.md` defines a 4-tier feed classification with differentiated failure
behaviour (tier 1 → `signals_stale` + notify; tier 2 → `WARN` + `degraded_feeds[]`; tier 3 → `INFO` only), but
the taxonomy is **never applied in code** — every feed is treated identically.

**Root cause:** the `feed_health` table has `class`/`tier` columns, but [RecordFeedSuccess] / [RecordFeedFailure]
never write them, and both [DegradedFeeds] (`WHERE consecutive_failures > 0`) and `SignalsStale` are
**tier-agnostic**. No Go code references a feed tier (grep for `tier`: zero matches).

**Fix:** record each feed's tier (config- or ACL-driven) on `feed_health`, then make `DegradedFeeds` and the
`signals_stale` computation tier-aware — a tier-1 failure escalates (stale + notify), a tier-3 failure stays
informational. Cheap; no schema change (the columns already exist).

**Phase-3 note:** in the go-forward this belongs on the Knowledge feed-ACL registry (feeds already carry a
`class` = overlay/correlation; add `tier`), driving feed health/staleness. Cross-ref **Part 1 §C** above.

**Go-forward status:** ✅ **realized in `phase3-knowledge-feeds`** (2026-07-23) — `Registry.Tier(source)`
classifies every feed, and `domain.FeedObservation.Evaluate` gives a tier-differentiated verdict
(Tier-1 → stale + escalate, Tier-2 → degraded, Tier-3 → informational). The **v0.3.x monolith** wiring of
this policy into `feed_health` / `signals_stale` here remains open.

**Cross-refs:** [D-FEED-1] (the feed-taxonomy split / CR-4), and the source-tier reference table in
`openspec/intel-source-tiers.md`.

[RecordFeedSuccess]: internal/adapter/store/feed_health.go#L28
[RecordFeedFailure]: internal/adapter/store/feed_health.go#L46
[DegradedFeeds]: internal/adapter/store/feed_health.go#L66

---

#### DEFECT D-NVD-1 — NVD CPE feeder over-matches version ranges and misclassifies ecosystem (Layer-0 correctness)

**Status:** ✅ RESOLVED (2026-06-24) — implemented as **CR-1** (unified version engine:
`BuildConstraintGroup` keeps the lower bound as one AND group; `versionStartExcluding` honored)
and **CR-6** (NVD CPE rebuilt on that engine; `vendor==product → npm` guess removed). Finding 3
(multi-version CVSS parse v3.1→v3.0→v2.0) landed in **CR-5/CR-6**. All gates green on branch
`themis-phase-2`. The original analysis below is retained for history.
**Severity:** High for the over-match (#1); Medium for the ecosystem and CVSS-coverage issues
(#2, #3). #1 is the **same over-match class already fixed in the OSV feeder** during the v0.3.0
Layer-0 audit (see commit `f6b4d97`, "fix Layer 0 vulnerability correlation and identity") — but
that fix only touched OSV; the NVD feeder was never given the same treatment.
**Found:** 2026-06-21, during the v0.3.0 Layer-0 "feeders correct in all aspects" audit (same
audit that raised [D-CVSS-1] and [D-FEED-1]).
**Scope:** `internal/adapter/nvd/client.go` (CVE-watch correlation path). NVD findings reach
operators via the background watch (`FetchModifiedSince` → catalog → correlation against
registered components), so these bugs inflate / misroute findings for any ecosystem whose CPE
product names align with NVD (npm, maven, pypi, go, etc.).

##### Finding 1 (High) — `cpeAffectedVersions` drops the lower bound → over-match

[cpeAffectedVersions] builds the affected-version constraints from a CPE match. For the
extremely common shape "from 2.0 up to but not including 2.5"
(`versionStartIncluding=2.0`, `versionEndExcluding=2.5`):

```go
if match.VersionEndExcluding != "" { affected = append(affected, "< "+...) }   // ["< 2.5"]
if match.VersionEndIncluding != "" { ... }
if match.VersionStartIncluding != "" && len(affected) == 0 { ... }             // SKIPPED (len==1)
```

- The `>= 2.0` lower bound is **dropped whenever an upper bound exists** (guarded by
  `len(affected) == 0`), so the constraint collapses to `< 2.5` and matches **1.x, 0.x —
  every version below 2.5**. A component on 1.0 is flagged for a CVE that only affects [2.0, 2.5).
- Even if both bounds were kept, they are appended as **separate slice elements**, and
  `domain.VersionMatches` treats slice elements as **OR across groups** (comma-within-group =
  AND, post-audit semantics) — so `["< 2.5", ">= 2.0"]` would match `< 2.5` **OR** `>= 2.0` =
  _all versions_. The bounds must be **one AND group**, not two OR elements.
- `versionStartExcluding` is **not in the `cpeMatch` struct at all** ([cpeMatch struct]), so
  `> x` (exclusive lower) ranges are silently ignored.

**Fix:** mirror the OSV feeder's [rangeConstraintGroup] — emit a single comma-joined AND group
(e.g. `">= 2.0, < 2.5"`), and add `VersionStartExcluding` (`> x`). This is the direct analogue
of the OSV Finding A fix and is a clear must-fix under the zero-Layer-0-bug rule.

##### Finding 2 (Medium) — `cpeVendorToEcosystem` defaults unknown `vendor==product` to `"npm"`

[cpeVendorToEcosystem] ends with:

```go
default:
    if vendor == product {
        return "npm"
    }
    return vendor
}
```

For `cpe:2.3:a:openssl:openssl:…` (vendor == product == `openssl`) this returns **`npm`**. The
ecosystem is then wrong on the resulting `FeedVulnerability`, so downstream
`domain.PackageIdentityMatch` either **drops the finding** (ecosystem mismatch vs the real
component) or **misroutes** it to a coincidental npm package. The `vendor==product → npm`
heuristic is an arbitrary hack with no basis.

**Fix:** remove the `→ npm` guess; for unmapped vendors, either fall through to an "unknown"
ecosystem that matches on name only (explicit, logged) or skip with a correlation-logger entry,
rather than fabricating an ecosystem.

##### Finding 3 (Medium) — NVD parser reads only `cvssMetricV31`

[mapNVDCVE] reads severity/score/vector **only** from `metrics.cvssMetricV31[0]`
([nvdCVE metrics]). CVEs scored solely under **CVSS v3.0, v4.0, or v2.0** come back
`severity=unknown`, `score=0`, `vector=""` even though NVD scored them — feeding the same
`unknown`/`0` problem as [D-CVSS-1], and it will undercut the planned NVD-by-CVE backfill
(`themis-nvd-cvss-backfill`) unless fixed in the same pass.

**Fix:** read metrics in precedence order `cvssMetricV31 → cvssMetricV30 → cvssMetricV2`
(optionally `cvssMetricV40`), taking the first present. Reuse / share the CVSS-vector parser
already in `internal/adapter/osv/cvss.go` where a vector is present but a base score is not.

##### Minor / latent (same file)

- **Dead match-all fallback record.** When a CVE has no usable CPE node, [mapNVDCVE] appends a
  `FeedVulnerability{AffectedVersions: ["unknown"]}` with **empty `PackageName`/`Ecosystem`**.
  `"unknown"` is match-all post-audit, but the empty package name makes
  `PackageIdentityMatch` reject it — so it never matches a component. Harmless today but dead;
  drop it or make the intent explicit.
- **`QueryByEcosystem` index assumption (OSV, not NVD, noted for completeness).**
  `internal/adapter/osv/client.go` ranges `payload.Results` while indexing `packages[i]`;
  panics only if OSV returns _more_ results than queries (it won't). Defensive nit, logged here
  so the feeder audit is complete.

##### Acceptance criteria

- A CPE range `[2.0, 2.5)` flags **only** versions in `[2.0, 2.5)` — 1.x/0.x no longer match
  (property test mirroring the OSV range tests).
- `versionStartExcluding` produces a `> x` lower bound.
- `cpe:…:openssl:openssl:…` no longer classifies as `npm`; unmapped vendors are handled
  explicitly (logged), not guessed.
- A CVE with only v3.0 / v2.0 metrics yields non-zero `cvss_score` and a real `severity`.
- NVD-correlated finding counts on a known component set drop to the true affected set (no
  long-fixed CVEs on modern versions) — the same sanity check used after the OSV over-match fix.

##### Sequencing & relationships

- **Next change cycle.** Smallest, most self-contained of the three feeder defects (~30 lines +
  tests, all in `nvd/client.go`). Candidate change name: `themis-nvd-feeder-fix`, or fold into
  `themis-nvd-cvss-backfill` (Finding 3 is literally the same NVD-CVSS work; #1/#2 are cheap to
  carry along).
- **Consolidated → CR-6** (Findings 1 & 2, on the CR-1 unified version engine) and **CR-5**
  (Finding 3, CVSS multi-version parse) in the Layer-0 Refactor section below (single source of truth).
- Cross-refs: [D-CVSS-1] (NVD CVSS), [D-FEED-1] (distro feeds as the _other_ apk/rpm severity
  source), and the OSV over-match fix in commit `f6b4d97` (the template for Finding 1).

[D-FEED-1]: #defect-d-feed-1--vendor-vex-feeders-conflate-three-feed-classes-osvrhsa-correlation-data-is-miscategorised-as-vex-overlay-architectural
[cpeAffectedVersions]: internal/adapter/nvd/client.go#L239
[cpeMatch struct]: internal/adapter/nvd/client.go#L153-L159
[cpeVendorToEcosystem]: internal/adapter/nvd/client.go#L221
[mapNVDCVE]: internal/adapter/nvd/client.go#L161
[nvdCVE metrics]: internal/adapter/nvd/client.go#L142-L151
[rangeConstraintGroup]: internal/adapter/osv/client.go#L239

---

#### DEFECT D-NVD-2 — CVSS v4.0 not parsed (NVD + OSV) → recent CVEs land severity=unknown / risk=0 (Layer-0 signal quality)

**Status:** 🔶 OPEN (found 2026-07-23). Direct successor to **[D-NVD-1] Finding 3 / CR-5**, which extended the
NVD CVSS parse to `v3.1 → v3.0 → v2.0` but **never added v4.0**. NVD/CNAs are now scoring recent CVEs with
**CVSS 4.0**, so the same `unknown`/`0` symptom D-NVD-1 Finding 3 fixed for v3.0/v2 has returned for v4.0.

**Severity:** Medium (signal quality) — affected CVEs show `severity=unknown`, `cvss_score=0`, and therefore
`risk_score=0`, even though NVD/OSV **do** carry a valid CVSS 4.0 base score. They do **not** self-heal via the
NVD-by-CVE backfill (see "Why it won't self-heal").

**Found:** 2026-07-23, ingesting a real Trivy CycloneDX 1.6 SBOM (the `oamp` container). Of the 228 findings,
the only remaining `unknown`-severity ones were **5 distinct CVEs / 7 findings**, all PyPI (pip, aiosmtplib):
`CVE-2025-8869`, `CVE-2026-1703`, `CVE-2026-3219`, `CVE-2026-6357`, `CVE-2026-53533`. A bucket query confirmed
**100%** of the unknowns carry a `CVSS:4.0/...` vector (no "missing data" cases).

**Symptom:** `vulnerabilities` row has `severity=unknown`, `cvss_score=0.0`, but `cvss_vector` is present and
begins `CVSS:4.0/...`; `epss_score` is populated (EPSS is a separate FIRST.org feed keyed by CVE, independent
of CVSS), so the finding shows an EPSS but no severity and `risk=0`.

**Root cause (two code paths):**

1. **NVD-by-CVE backfill** — [extractNVDCVSS] reads `cvssMetricV31 → cvssMetricV30 → cvssMetricV2` and has no
   `cvssMetricV40` branch; the response metrics struct ([nvdCVE metrics v3-only]) has no `CVSSMetricV40`
   field. A CVE NVD scored **solely** under v4.0 returns `("unknown", 0, "")`.
2. **OSV correlation** (how PyPI/apk/rpm findings get CVSS) — [osv cvssV3BaseScore] implements the **v3.1
   base-score formula only**. `parseCVSSScore` passes a `CVSS:4.0/...` vector to it, `parseCVSSMetrics` fails,
   and it returns `(0, vector)`: the vector is stored but the score is 0.

**Evidence:** the live NVD API for `CVE-2025-8869` returns `metrics: { cvssMetricV40 (baseScore 5.9, MEDIUM,
type=Secondary), ssvcV203 }` with `vulnStatus=Deferred` — **no v3.1 at all**. NVD has the severity; Themis
just never reads that key.

**Why it won't self-heal:** the CVSS backfill records `cvss_checked_at=NOW()` after a check that found no v3
metric, then backs off (the D-CVSS-1/CR-5 retry guard). The CVE stays `unknown` until the code reads v4.0 (or
NVD adds a v3.1 _primary_ score — unlikely for new CVEs). This is a **code gap, not a timing/back-off issue**;
the ~200 severities that filled in post-ingest were genuine v3.1 backfills.

**Fix:**

- **NVD client (cheap, high value):** add an `nvdCVSSMetricV40` type (`cvssData.baseScore` + `baseSeverity` +
  `vectorString`) to the metrics struct and a branch in `extractNVDCVSS`. NVD supplies the **computed** score,
  so the existing backfill fills these directly. Suggested precedence **`v3.1 → v3.0 → v4.0 → v2`** (v3.1-first
  for cross-fleet comparability; v4.0 as the fallback when it is the only score), preferring **Primary** over
  **Secondary** within a version. Add a test on `CVE-2025-8869`'s shape (v4.0-only, Secondary).
- **OSV path (harder):** OSV provides only the vector, not a score; a true v4.0 base score needs the v4.0
  **MacroVector** lookup table. Largely mitigated once (1) lands — the NVD backfill supplies the score. If a
  standalone OSV scorer is wanted, vendor a v4.0 base-score calculator.
- **Residual (by design):** a CVE in NVD status `Received`/`Awaiting Analysis` has **no** CVSS from anyone yet
  → legitimately `unknown`. Fall back to distro/vendor severity (OSV / Red Hat) + EPSS/KEV as risk inputs.

**Phase-3 note:** the same v4.0 gap will affect Phase-3 **Knowledge** (feed ACLs + `Reconcile` headline
severity by source precedence). Tracked as a cross-ref in **Part 1 §C** above.

**Go-forward status:** ✅ **realized in `phase3-knowledge-feeds`** (2026-07-23) — the Knowledge NVD client
reads `cvssMetricV40` in the precedence `v3.1 → v3.0 → v4.0 → v2` (Primary > Secondary), so a v4.0-only CVE
resolves to a real severity.

**v0.3.x monolith:** ✅ the **NVD side is now fixed too** (2026-07-23) — `internal/adapter/nvd/client.go`
`extractNVDCVSS` reads `cvssMetricV40` in precedence `v3.1 → v3.0 → v4.0 → v2` (test `TestClientFetchCVSSv40`).
Verified live: 4/5 v4.0-only CVEs in the oamp scan resolved (`unknown → medium/low`); findings `unknown` 7 → 1
(the 1 residual is a CVE NVD has not scored, not a code gap). Only the harder OSV vector-computation path
(`internal/adapter/osv/cvss.go`) is left, and it is **not needed for NVD-scored CVEs** — the backfill supplies
the score.

**Cross-refs:** [D-NVD-1] (Finding 3 = the v3.1→v3.0→v2 parse this extends), [D-CVSS-1] (OSV-origin CVSS
enrichment / CR-5 backfill + back-off), [D-FEED-1] (distro feeds as the _other_ apk/rpm severity source).

[extractNVDCVSS]: internal/adapter/nvd/client.go#L346
[nvdCVE metrics v3-only]: internal/adapter/nvd/client.go#L273-L275
[osv cvssV3BaseScore]: internal/adapter/osv/cvss.go#L27

---

#### DEFECT D-LOG-1 — Logging architecture is configured but barely propagated; most modules are silent at runtime (observability)

**Status:** ✅ RESOLVED (2026-06-24) — implemented as **CR-7**: a `domain.Logger` port over zap,
DI-injected into the schedulers, feed services, correlator, and feed clients; all four feed
schedulers now log per-cycle success/failure; the vexfeed `SyncLogger` is wired; `slog.Default()`
is retired from osv/vexfeed (clean-arch preserved — no zap/slog in domain/usecase). All gates
green on branch `themis-phase-2`. _Note: `adapter/notify` still uses an injected `*slog.Logger`
(discard default) — not a `slog.Default()` leak; full unification onto the port is optional._
The original analysis below is retained for history.
**Severity:** High (operability) — operators cannot tell what Themis is doing. The system
surfaces _composition_ data (what is in the SBOM) but there is no runtime log of whether feeds
fetched, whether correlation/enrichment ran, whether jobs failed, or what config is live. This
is the umbrella defect under which the feeder-logging request (NVD/OSV/EPSS/KEV/ExploitDB/vendor
VEX success+failure) sits.
**Found:** 2026-06-21, during the v0.3.0 Layer-0 audit while adding feeder fetch logging — the
attempt surfaced that the logging _architecture_ itself is the problem, not just the feeders.

##### What works today (be fair)

- A proper **zap** logger is built at startup and **honours `THEMIS_LOG_LEVEL`** /
  `log.level` (`internal/infrastructure/http/startup.go:230` → `NewLoggerWithLevel("themis",
  level)`; `internal/infrastructure/http/logger.go`). JSON output, `component` field.
- It logs the **HTTP server start** (`server.go:58`), **request middleware**, and the
  **shutdown signal** (`startup.go:271`).

That is essentially the entire runtime log surface.

##### The core problem (one line)

The logger is **created but almost never propagated**, and a **second, unconfigured logging
system runs in parallel** — so the configured level/format applies to a thin HTTP/startup slice
while the rest of the system logs in a different format, at a fixed level, or not at all.

##### Findings (verified in code)

1. **Logger reaches almost nothing.** No scheduler, feed service, use case, store, or feed
   client takes a `*zap.Logger` (grep: zero `logger *zap.Logger` params outside `http`/`server`).
   The zap logger is confined to the HTTP request path + startup/shutdown. Correlation, risk
   scoring, VEX overlay, triage, blast-radius, DB access, and every outbound feed fetch run
   **without the application logger**.
2. **Two disjoint logging systems.** Besides zap, two adapters log via `slog.Default()`
   (`internal/adapter/osv/correlation_logger.go:36`,
   `internal/adapter/vexfeed/logger.go:15`). `slog.Default()` is **not** configured by
   `THEMIS_LOG_LEVEL`, emits **text** (not zap's JSON), and writes independently. Setting
   `THEMIS_LOG_LEVEL=debug` does nothing for these; their output can't be parsed alongside zap.
3. **Feed schedulers swallow all results and errors.** All four discard the return:
   `_ = svc.RunCycle(ctx)` (`watch_scheduler.go:23,29`) and `_, _ = svc.RunSync(ctx)`
   (`epsskev_scheduler.go`, `exploitdb_scheduler.go`, `vexfeed_scheduler.go`, lines 23/29). A
   feed that fails to fetch produces **no log line** — the operator's exact complaint.
4. **vexfeed `SyncLogger` is never wired.** `api_wiring.go:101` constructs `vexFeedSvc` with no
   `Logger:` field → it defaults to `NoOpSyncLogger` (`vexfeed/service.go`), so even the existing
   `logger.Warn("vendor vex feed fetch failed", …)` is **dropped**. Dead logging code today.
5. **Startup failures are unstructured stderr prints, not logs.** DB connect / migration /
   schema-skew failures (`startup.go:111/116/119`) return wrapped errors that `cmd/themis/main.go`
   prints with `fmt.Fprintf(os.Stderr, "error: %v")` — not via the JSON logger, not queryable.
6. **Queue job failures are not logged.** `internal/infrastructure/queue/inprocess.go:200/207/222`
   persist `MarkFailed` to the DB and discard its error (`_ =`); a failing ingestion/enrichment
   job emits no log. (`cmd/themis/main.go` configures no logger at all.)
7. **Config load is silent.** `internal/infrastructure/config/` logs nothing — no record of which
   config file was loaded, which env overrides applied, or which optional feeds are
   unconfigured/disabled. Operators cannot confirm what configuration is actually live.

##### Per-module logging coverage (call-site sweep, non-test files)

| Module | Files with any logging | Note |
| ------ | ---------------------- | ---- |
| `infrastructure/config` | 0/2 | no load/override/validation logs |
| `infrastructure/db` | 0/1 | no connect / migration / pool logs |
| `infrastructure/queue` | 1/7 | job failures discarded |
| `usecase/ingestion` | 1/4 | pipeline stages largely silent |
| `usecase/enrichment` | 0/9 | risk score / VEX overlay / state machine silent |
| `usecase/triage` | 0/3 | human triage decisions unlogged |
| `usecase/watch` | 0/3 | NVD/OSV CVE watch silent |
| `adapter/store` | 0/17 | no DB error/slow-query context |
| `adapter/nvd` | 0/2 | no fetch / rate-limit / key logs |
| `adapter/epsskev` | 0/4 | no EPSS/KEV fetch logs |
| `adapter/exploitdb` | 1/3 | partial |
| `adapter/osv` | 1/7 | via `slog.Default()` (system #2) |
| `adapter/vexfeed` | 2/15 | via `slog.Default()`; SyncLogger unwired |
| `adapter/assetgraph` | 0/3 | blast-radius traversal silent |
| `adapter/api` | 4/19 | mostly request middleware |

##### Impact

- **No feed visibility** (the trigger): success/failure of every feeder line is invisible —
  directly blocks the v0.2.1 feed-reliability testing this defect was found during.
- **Undebuggable correlation/enrichment:** when findings look wrong (see D-CVSS-1, D-FEED-1,
  D-NVD-1), there is no log trail of what matched, what was skipped, or why.
- **Silent failures:** job failures, startup failures, and feed failures don't reach a log.
- **Inconsistent, partly-unconfigurable output:** two formats, two level controls; log
  aggregation/alerting cannot rely on one schema.

##### Proposed fix (architecture, then coverage)

1. **One logger, one config.** Pick a single backend (zap is already configured and level-aware)
   and **retire `slog.Default()` ad-hoc use** — or bridge slog→zap — so all logs share format +
   level + `THEMIS_LOG_LEVEL`.
2. **Define a domain logging port and propagate it.** Add a small `domain.Logger` interface
   (Debug/Info/Warn/Error with structured fields), implemented in `infrastructure` over zap, and
   **inject it** into schedulers, feed services, use cases (ingestion/enrichment/triage/watch),
   and feed clients via DI in `api_wiring.go`. Keeps `domain`/`usecase` free of zap/slog imports
   (Clean-Architecture-correct; `make clean-arch` stays green).
3. **Feeders first (the immediate ask):** log success (with row/assertion counts) and failure
   (with feed name + error) for every feeder cycle — NVD/OSV watch, EPSS/KEV, ExploitDB, vendor
   VEX — and **wire vexfeed's `SyncLogger`** so per-feed-line status surfaces. (This is the work
   started and reverted during discovery of this defect.)
4. **Fill the silent modules:** correlation match/skip (already has `CorrelationLogger` —
   fold into the unified logger), risk-score/enrichment decisions, triage decisions,
   queue job start/success/failure, DB connect + migration applied, config loaded + overrides +
   disabled feeds.
5. **Startup failures via the logger** (DB/migration/schema-skew) before returning, so they are
   structured + queryable.

##### Acceptance criteria

- A single log format/level controlled by `THEMIS_LOG_LEVEL`; no `slog.Default()` path that
  ignores it.
- Every feeder cycle emits one structured success or failure line (per feed line for vendor VEX).
- A failed feed, a failed job, and a failed startup each produce a structured ERROR log.
- Config load logs the active config source + applied env overrides + any disabled/unconfigured
  feeds at startup.
- `domain`/`usecase` import neither `zap` nor `slog` (clean-arch preserved); coverage gates green.

##### Sequencing & relationships

- **Next change cycle.** Candidate change name: `themis-logging-architecture` (or `themis-observability`).
  **Consolidated → CR-7** in the Layer-0 Refactor section below (single source of truth for execution).
- **Foundation for `themis-feed-observability`** (persisted `feed_health` + notifications) — that
  candidate assumes logs/metrics exist to build on; land the logging port first or together.
- Cross-refs: this is the diagnosis layer for **D-CVSS-1 / D-FEED-1 / D-NVD-1** (without logs,
  those feeder bugs are hard to confirm in the field); complements the existing Prometheus
  `themis_*_sync_total` metrics (metrics say _how many_, logs say _what/why_).

---

### Layer-0 Correctness & Observability Refactor (CR-1 … CR-10)

**Status:** ✅ IMPLEMENTED (2026-06-24) — all of CR-1 … CR-10 are coded on branch
`themis-phase-2`; every gate is green (build → unit → coverage [all per-package thresholds] →
deadcode → integration → clean-arch → verify-build). **Merged to `themis-phase-2` (PR #24) and
released as part of `v0.3.0` (2026-06-24).** See "Implementation status & unfinished tasks"
immediately below for the per-CR result and the short list of what genuinely remains.
**Created:** 2026-06-21 (v0.3.0 Layer-0 audit).
**Scope:** the correlation/feeder/observability core that determines whether Themis tells the
truth and whether operators can see it. Excludes Phase 2b AI work (separate track).
**Relationship to the DEFECT entries above:** this section is the structural **parent** of
D-CVSS-1, D-FEED-1, D-NVD-1, D-LOG-1 and of the feeder candidate changes below. Those are the
symptoms; the CRs here fix the causes. This is the single source of truth for execution.

#### Implementation status & unfinished tasks (2026-06-24)

All ten CRs are implemented on branch `themis-phase-2`; all gates green; **not yet committed or
tagged**. The four root causes (R1 forked version logic, R2 multiple correlation engines, R3
observability afterthought) are eliminated.

| CR | Result |
| -- | ------ |
| CR-1 unify version semantics | ✅ Done. `domain` engine: `CompareVersionsEco` (generic/apk/rpm incl. rpmvercmp `~`), `VersionConstraintSet`, `BuildConstraintGroup`. osv/nvd/vexfeed/watch all call it; 3 forked vexfeed comparators deleted. 100% domain coverage + property tests. |
| CR-2 single correlator + source port | ✅ Done. `domain.CorrelationSource` + `usecase/correlation.Correlator` (multi-source, provenance tagging, precedence merge, deterministic order). Wired into ingest **and** watch (watch re-correlates catalog components through the shared distro index). 100% covered + order-independence property test. |
| CR-3 finding provenance | ✅ Done. `source`/`source_severity`/`source_cvss_score`/`source_cvss_vector`/`source_fixed_version` columns folded into the v0.3.0 baseline; distro-authoritative precedence (strict total order); tagged at both feeds; populated at ingest + watch; persisted; unit + integration tests. |
| CR-4 feed taxonomy + re-layering | ✅ Done. Config split `rhel_vex_url` (overlay) + `rhel_csaf_url` (correlation), `rhel_url` deprecated alias; Alpine/Rocky/Wolfi OSV + RHSA advisories are correlation sources (severity + fixed); overlay = true VEX only; `csaf.go` typo fixed; **RHSA NEVRA range extraction** done. |
| CR-5 CVSS/severity enrichment | ✅ Done. NVD `FetchByCVEID` + `CVSSBackfillService` (back-off via `cvss_checked_at` column) + catalog→risk_context propagation + re-enrich trigger + `themis_cvss_backfill_total` metric + interim risk floor. _Operational E2E (G1–G8 on real SBOMs) still to confirm on a deployment._ |
| CR-6 NVD CPE correctness | ✅ Done (with CR-1). Lower bound preserved, `versionStartExcluding`, no `vendor==product→npm`, multi-version CVSS. |
| CR-7 observability / logging | ✅ Done. `domain.Logger` port over zap, DI-injected; schedulers/feeders log success/failure; `slog.Default()` retired in osv/vexfeed; feed-health surface (CR-8). |
| CR-8 operator feed-health surface | ✅ Done. `feed_health` table (baseline up/down) + recorder wired into all schedulers + `degraded_feeds[]` on `GET /api/v1/status`. |
| CR-9 parser integrity | ✅ Done. Trivy one-component-per-package, CycloneDX bom-ref→purl edges, shared PURL-qualifier helper, dead `CanonicalSBOM.Vulnerabilities` parsing removed (decision: pure re-correlator). |
| CR-10 regression corpus + property tests | ✅ Done (core). `internal/testutil/findingset` diff harness + golden distro corpus; property tests for CR-1 (comparator laws, range over-match) and CR-2 (merge order-independence); parser robustness already covered. _Corpus may be expanded with real sanitised feed slices over time._ |

**Open product decisions — RESOLVED (signed off 2026-06-24):**

1. CR-9 scanner findings → **remove the dead parsing** (Themis stays a pure re-correlator).
2. CR-3 precedence → **distro-authoritative** (distro feed > OSV.dev > NVD for apk/rpm; OSV.dev/NVD for app ecosystems).
3. CR-3 timing → **fold the new columns into the v0.3.0 baseline** migration.

**Unfinished tasks (what genuinely remains):**

1. ✅ **Commit + tag — DONE (2026-06-24).** Merged to `themis-phase-2` (PR #24) and tagged
   `v0.3.0` (core-model + this refactor). Phase 2b/2c re-numbered to `v0.4.0`/`v0.5.0`.
2. **Real-SBOM E2E (G1–G8)** — verify on a deployment with live Alpine **and** RPM SBOMs +
   reachable feeds + NVD key. Unit/integration prove the logic; the live bring-up is unverified
   in-repo (it is the refactor's one operational Definition-of-done item).
3. **User-defined feed registry** (`themis-feed-registry`, below) — CR-4 delivered the feed
   _class_ taxonomy but **not** the `vexfeed.feeds:` delta list to add/remove/disable arbitrary
   feeds. Feeds are still fixed in DI (no per-feed on/off). Tracked as a follow-on candidate.
4. **Corpus expansion (CR-10)** — seed the golden corpus with real sanitised Alpine/RPM/npm
   SBOMs, OSV zip slices, NVD CPE samples, and CSAF/RHSA fixtures (the synthetic boundary matrix
   is in; real feed slices are the enrichment).
5. **`adapter/notify` logger unification (CR-7, optional)** — notify uses an injected
   `*slog.Logger` (discard default); migrating it onto `domain.Logger` would make logging fully
   uniform. Not a `slog.Default()` leak.
6. **OpenSpec formalization (docs)** — this refactor was executed as CRs in this backlog, not as
   an `openspec/changes/` change. Optional follow-up: create `themis-layer0-refactor` (or fold
   into `themis-core-model`), sync spec deltas for `upstream-vex-feeds` / `intelligence-enrichment`
   / `cve-watch` / `sbom-parser`, and archive. README / `themis.yaml.example` / `PROJECT_CONTEXT.md`
   / `openspec/STATUS.md` are already updated (2026-06-24).

Pre-existing, out of refactor scope: 3 `deadcode` findings on `enrichment/metrics.go`
`NoOpMetricsRecorder` (present on `HEAD` before this work).

#### Why this refactor exists

The audit found a cluster of "rudimentary" bugs that defeat the product's purpose (tell users
what is vulnerable, accurately, and let them see the system working):

- **Over-matching** — NVD CPE ranges drop the lower bound; everything below the upper bound is
  flagged (D-NVD-1). The identical bug was fixed in OSV but not NVD.
- **Miscategorised feeds** — OSV distro feeds and RHSA advisories (correlation data) are ingested
  as "vendor VEX," and their severity/fixed data is discarded (D-FEED-1).
- **All-zero risk** — apk/rpm findings have `severity=unknown`, `cvss_score=0`, `risk_score=0`
  (D-CVSS-1).
- **Silent runtime** — feed fetches, correlation, jobs, and startup failures emit no logs; the
  configured logger reaches almost nothing (D-LOG-1).

These are not independent. They share **three structural root causes**:

| Root cause | Evidence | Consequence |
| ---------- | -------- | ----------- |
| **R1. Version logic is forked** — 3 comparators + 3 range builders, no shared code | `domain.CompareVersions`; `vexfeed.compareAlpineVersion`; `vexfeed.compareRPMEVR`; `osv.rangeConstraintGroup`; `nvd.cpeAffectedVersions`; `vexfeed.alpineRangeStatus` | A fix in one path (OSV) never reaches the others (NVD); the same apk/rpm version is compared by different rules depending on code path |
| **R2. Multiple correlation engines** — ingest vs watch vs vexfeed-overlay each match independently | `ingestion.correlateComponents`→`FetchForComponent`; `watch.MatchCatalog` over NVD+OSV; `vexfeed.matchAlpineOSV` | Two+ sources of truth, no provenance, no merge; feeds land in the wrong layer |
| **R3. Observability is an afterthought** — logger configured but not propagated; second `slog.Default()` system; feeders swallow errors | `startup.go` builds zap; nothing downstream takes it; `osv`/`vexfeed` use `slog.Default()`; schedulers `_,_ = svc.RunSync` | Operators cannot see or debug any of the above |

Fixing symptoms without R1/R2/R3 guarantees the next divergent bug.

#### Guiding principles

1. **One way to do each thing.** One version engine, one correlation core, one logger.
2. **Provenance over guessing.** Every finding records who found it; conflicts resolve by explicit
   precedence, not by whichever code path ran last.
3. **Right data in the right layer.** Correlation creates findings; VEX only adjusts
   `effective_state`. Never blur them.
4. **Visible by default.** Every external fetch and state transition is observable.
5. **Extend, don't rewrite.** Keep the v0.3.0 schema/identity contract and Clean Architecture; add
   columns and ports, do not restructure.
6. **Property-tested invariants.** Anything that compares versions or merges sources gets property
   tests, not just examples.

#### What is KEPT AS-IS (explicitly not changing)

- **Clean Architecture + dependency rule** and the `make clean-arch` / `depguard` gates.
- **v0.3.0 core schema**: `sboms` + `scan_reports` split; the Durable-Enrichment Identity Contract
  `(artifact_id, component_purl, cve_id)` (D15); `v_latest_findings`. CRs add columns, never
  restructure these.
- **VEX overlay invariant** — raw `component_vulnerabilities` are never deleted; VEX changes only
  `risk_context.effective_state`.
- **CanonicalSBOM normalization + parser registry** pattern.
- **Idempotency** (D12), the trust gate, the async ingestion lifecycle.
- **Composite risk score V2** formula (corrected this cycle) and EPSS/KEV/ExploitDB enrichment.
- **API surface + error envelope** — changes additive (new fields), no breaking renames.
- **Property-based testing harness** and per-package coverage thresholds.

#### Target architecture (the deep change)

Today (simplified):

```text
ingest ──> correlateComponents ──> OSV.dev live ─┐
                                                 ├─> component_vulnerabilities  (no source)
watch  ──> MatchCatalog ──> NVD + OSV ───────────┘
vexfeed ─> matchAlpineOSV/RPM/CSAF ──> vex_assertions ──(range math as "VEX")──> risk_context
                                  (3 comparators, 3 range builders, slog.Default, errors dropped)
```

Target:

```text
                         ┌──────────────────── domain ────────────────────┐
                         │  VersionConstraintSet + CompareVersions(eco,a,b) │  (CR-1: one engine)
                         │  Logger port                                     │  (CR-7)
                         │  Finding{...,Source,SourceSeverity,SourceFixed}  │  (CR-3: provenance)
                         └──────────────────────────────────────────────────┘
        CorrelationSource port (CR-2)                 VEX overlay (unchanged invariant)
        ├─ OSV.dev live (apk/npm/...)                 └─ Red Hat CSAF VEX only (CR-4)
        ├─ NVD (CPE, by-CVE backfill)  (CR-5/6)            (true exploitability context)
        ├─ distro OSV (Alpine/Rocky/Wolfi)  (CR-4)
        └─ RHSA advisories (rpm)  (CR-4)
                    │  (all emit canonical constraints + severity + fixed, with Source)
                    ▼
        Correlator use case (CR-2) ── merge by precedence ──> component_vulnerabilities (Source)
                    │                                                   │
                    ▼                                                   ▼
        enrichment (risk score, EPSS/KEV)                       risk_context (effective_state)
                    │
        observability: every fetch/merge/transition logged (CR-7) + feed_health surface (CR-8)
```

Key moves: **(a)** one version engine in `domain`; **(b)** one `Correlator` over a
`CorrelationSource` port with provenance + precedence; **(c)** distro/RHSA become _correlation
sources_, not VEX; **(d)** a `domain.Logger` port propagated everywhere; **(e)** feed health
surfaced to operators.

#### Change Requests

Each CR: **Root cause → Keep/Change → Behavior on inputs → Architecture impact → Testing →
Risk/Deps → Maps to**.

##### CR-1 — Unify version semantics (one constraint model + ecosystem-aware comparator)

- **Root cause:** R1. Three comparators and three range builders diverge.
- **Change:** Introduce in `domain`: a `VersionConstraintSet` value object (AND-within-group,
  OR-across-groups — the semantics already in `VersionMatches`) and
  `CompareVersions(ecosystem, a, b)` dispatching to generic / **apk** (`-rN` revisions) / **rpm**
  (epoch:version-release, `~` pre-release) rules. All range producers
  (`osv.rangeConstraintGroup`, `nvd.cpeAffectedVersions`, `vexfeed.alpineRangeStatus`,
  `vexfeed.compareRPMEVR`) become thin adapters that build the canonical model; all matchers call
  the one engine.
- **Keep:** the existing `VersionMatches` public behavior/semantics; the rpmvercmp-style numeric
  handling already added.
- **Behavior on inputs:** CPE `[2.0,2.5)` + installed `1.0` → was match (lower bound dropped) →
  now no match. apk `1.36.1-r2` vs introduced `1.36.1-r5` → compared by apk rules on every path.
  rpm `0:1.2-3.el8` with `~`/epoch → consistent ordering everywhere.
- **Architecture impact:** new `domain/version/` (or extend `version_match.go`); ecosystem passed
  into comparison. No schema change.
- **Testing:** _unit/property_ — comparator laws per ecosystem; constraint-set truth table;
  round-trip of OSV/NVD/CPE inputs → canonical set; port the real bug counterexamples (CPE
  `[2.0,2.5)`+1.0; apk `-rN`) as regression cases. _Integration_ — exercised via CR-2/6.
- **Risk/Deps:** foundational, no deps. Risk: changing comparison could shift existing matches —
  mitigated by keeping `VersionMatches` semantics + golden corpus diff (CR-10).
- **Maps to:** root of D-NVD-1; substrate for D-FEED-1/D-CVSS-1.

##### CR-2 — Single correlation core with a source port + provenance

- **Root cause:** R2. Ingest and watch correlate via separate code with separate matching.
- **Change:** Define `domain.CorrelationSource` (`LiveQuery(component)` and `BulkFeed()` shapes)
  implemented by OSV.dev, NVD, distro-OSV, RHSA. A `usecase/correlation` `Correlator` runs all
  applicable sources, matches via **CR-1**, and **merges** per **CR-3** precedence into
  `component_vulnerabilities`. Ingest and watch both call the Correlator — one match path.
- **Keep:** ingest lifecycle, watch cadence, the catalog table, `CreateFinding` (extended with
  `source`).
- **Behavior on inputs:** Alpine apk matched by OSV.dev + distro-OSV → one merged finding with the
  higher-confidence source's severity/fixed, `source` recorded. npm → OSV.dev + NVD merge
  deterministically. Same bytes re-uploaded → idempotent.
- **Architecture impact:** new `usecase/correlation`; adapters expose `CorrelationSource`; both
  ingest and watch depend on the Correlator.
- **Testing:** _unit_ — merge/precedence (table + property: order-independent); per-source mapping.
  _integration_ — Alpine SBOM with stub OSV.dev + stub distro-OSV → one merged set with
  provenance; watch produces same shape; conflicts resolve by precedence; idempotent re-run.
- **Risk/Deps:** depends on CR-1, CR-3. Largest CR. Risk: finding-set change — mitigated by golden
  corpus (CR-10) + shadow-run/compare before cutover.
- **Maps to:** R2; enables D-FEED-1, D-NVD-1, D-CVSS-1.

##### CR-3 — Finding provenance + multi-source merge model

- **Root cause:** R2. No `source` on findings; conflicts silent.
- **Change:** Add to `component_vulnerabilities` (and the canonical finding): `source`
  (`osv` | `nvd` | `distro_osv:<feed>` | `rhsa` | `scanner:<tool>`), `source_severity`,
  `source_cvss_score`, `source_cvss_vector`, `source_fixed_version`. Define precedence (distro-
  authoritative > OSV.dev > NVD for distro packages; OSV.dev/NVD for app ecosystems). Keep the
  identity PK; `source` is descriptive (one finding per identity, attributed to the winning source,
  with a record of others via an optional `finding_sources` side table).
- **Keep:** identity contract (D15); VEX overlay invariant.
- **Behavior on inputs:** a finding answers "who says so and what did they say"; disagreements are
  visible, not silently overwritten.
- **Architecture impact:** additive migration; domain `Finding` gains fields; store upsert
  extended.
- **Testing:** _unit_ — precedence resolution; source-field serialization. _integration_ —
  migration up/down; two sources for one identity → winning source persisted, others recorded;
  API exposes `source`.
- **Risk/Deps:** additive schema. Fold into v0.3.0 baseline before tag if timing allows, else new
  migration. Risk: low.
- **Maps to:** foundation for CR-2/CR-4; the provenance need from the correlator-vs-aggregator
  discussion.

##### CR-4 — Feed taxonomy + re-layering (VEX vs correlation)  (= D-FEED-1)

- **Root cause:** R2 + miscategorisation. OSV distro + RHSA treated as VEX.
- **Change:** Config: split `rhel_url` → `rhel_vex_url` (overlay) + `rhel_csaf_url` (correlation);
  reclassify `*_osv_url` as **correlation** feeds. Route distro-OSV + RHSA through the **Correlator**
  (CR-2) as sources carrying severity + fixed. Keep **only** Red Hat CSAF VEX on the overlay. Fix
  the `csaf.go` `"known affected"` → not_affected typo.
- **Keep:** the VEX overlay machinery (now fed only by true VEX); `upstream_vex_coverage` (now
  meaning real VEX coverage).
- **Behavior on inputs:** Alpine apk → distro-OSV findings with severity/fixed (was overlay-only,
  severity discarded). rpm → RHSA findings (was: OSV.dev skips rpm). Red Hat CSAF VEX
  `not_affected` → suppresses via overlay (was never ingested).
- **Architecture impact:** config shape change (folds in `themis-feed-registry`: feed _class_
  becomes a field); feeds become correlation sources.
- **Testing:** _unit_ — feed→finding mapping per source; CSAF status mapping incl. typo fix;
  config parse. _integration_ — RHSA fixture → rpm findings; distro-OSV → apk findings w/ severity;
  CSAF VEX → overlay not_affected; `vex-coverage` reflects only VEX.
- **Risk/Deps:** depends on CR-2/CR-3. Config migration (keep old key as deprecated alias one
  release). Risk: medium.
- **Maps to:** D-FEED-1 (absorbs `themis-feed-layering` + `themis-feed-registry`).

##### CR-5 — CVSS/severity enrichment pipeline  (= D-CVSS-1)

- **Root cause:** apk/rpm findings have no CVSS; NVD has no by-CVE backfill; distro severity
  discarded.
- **Change:** (a) NVD client `FetchByCVEID` + rate-limited backfill job for
  `cvss_score=0 OR severity='unknown'`; (b) consume distro-feed severity via CR-4; (c) parse all
  CVSS metric versions (v3.1→v3.0→v2.0, optional v4.0); (d) interim non-zero **risk floor** for
  vendor-VEX-confirmed / KEV-listed findings.
- **Keep:** the risk score V2 formula; ReEnrichJob.
- **Behavior on inputs:** Alpine SBOM after backfill → `cvss_score>0`, severity populated,
  `risk_score` spreads; `top_components[].highest_cvss_score>0`.
- **Architecture impact:** new NVD method + backfill scheduler + metric; no schema change beyond
  CR-3.
- **Testing:** _unit_ — CVSS multi-version parse; backfill selection; floor logic. _integration_ —
  zero-CVSS catalog → backfill → ReEnrich spreads risk; G5/G7/G8 pass for OSV-origin findings.
- **Risk/Deps:** depends on CR-1/2/3/4; `THEMIS_NVD_API_KEY` recommended.
- **Maps to:** D-CVSS-1 (absorbs `themis-nvd-cvss-backfill`).

##### CR-6 — NVD CPE feeder correctness  (= D-NVD-1)

- **Root cause:** R1 (range over-match) + ecosystem misclassification.
- **Change:** Rebuild NVD range extraction on the **CR-1** constraint model (one AND group,
  `versionStartExcluding` supported, lower bound preserved); remove the `vendor==product → "npm"`
  guess (unmapped vendors handled explicitly + logged); expose NVD as a `CorrelationSource` (CR-2).
- **Keep:** the NVD client transport/rate limiter.
- **Behavior on inputs:** CPE `[2.0,2.5)` matches only `[2.0,2.5)`; `openssl:openssl` no longer
  npm.
- **Testing:** _unit/property_ — CPE→constraint mapping (reuse CR-1 corpus); ecosystem table.
  _integration_ — watch finding counts drop to the true set on a known catalog.
- **Risk/Deps:** depends on CR-1; reachable via CR-2.
- **Maps to:** D-NVD-1 (absorbs `themis-nvd-feeder-fix`; Finding 3 → CR-5).

##### CR-7 — Observability: logging architecture  (= D-LOG-1)

- **Root cause:** R3.
- **Change:** Add a `domain.Logger` port (Debug/Info/Warn/Error + structured fields), implement
  over zap in `infrastructure`, **inject via DI** into schedulers, feed services, the Correlator,
  use cases, and feed clients. Retire ad-hoc `slog.Default()` (or bridge slog→zap) so one
  format/level honors `THEMIS_LOG_LEVEL`. Log: every feeder cycle success/failure (with counts),
  correlation match/skip, job start/success/failure, DB connect + migration applied, config
  loaded + overrides + disabled feeds, startup failures (structured, before returning).
- **Keep:** zap backend; `THEMIS_LOG_LEVEL` semantics.
- **Behavior on inputs:** a failed feed, failed job, or failed startup each emit a structured
  ERROR; `THEMIS_LOG_LEVEL=debug` affects all logs uniformly.
- **Architecture impact:** `domain.Logger` interface (no zap/slog import in domain/usecase —
  clean-arch preserved); DI wiring in `api_wiring.go`.
- **Testing:** _unit_ — capture logger asserts per-feeder success/failure; level filtering.
  _integration_ — failing stub scheduler → ERROR emitted; clean-arch gate green.
- **Risk/Deps:** independent foundation; can land first. Risk: low.
- **Maps to:** D-LOG-1 (absorbs `themis-logging-architecture`).

##### CR-8 — Operator-facing feed health surface  (= `themis-feed-observability`)

- **Root cause:** R3 — even with logs, there is no API/state view of feed health.
- **Change:** `feed_health` table (`feed`, `class`, `tier`, `last_success_at`,
  `consecutive_failures`, `last_error`, `last_attempt_at`), upserted each cycle; `degraded_feeds[]`
  on `GET /api/v1/status`; per-tier signal on `/readyz`; optional `FEED_DEGRADED` notification.
- **Keep:** existing `themis_*_sync_total` metrics; `signals_stale`.
- **Behavior on inputs:** one API call shows every feed line's health, not just EPSS/KEV.
- **Architecture impact:** additive table + status/readyz wiring; reuses `NotificationSender`.
- **Testing:** _unit_ — health upsert + degraded computation. _integration_ — failing feed →
  `degraded_feeds[]` populated; migration up/down.
- **Risk/Deps:** depends on CR-7 (shared logging) and the feed-class field from CR-4.
- **Maps to:** `themis-feed-observability` (reconciles `themis-feed-registry`).

##### CR-9 — Parser integrity + scanner-findings decision

- **Root cause:** parser correctness bugs + dead data paths.
- **Change:** Fix Trivy **one-component-per-result** bug (iterate packages, not first vuln);
  handle CycloneDX/SPDX **bom-ref ≠ purl** for dependency edges; unify **PURL qualifier/subpath
  normalization** (one helper, parser + matcher). **Decide** the parsed-`Vulnerabilities`
  question: either _import_ scanner findings as a `CorrelationSource` (`scanner:<tool>` via CR-3)
  or _remove_ the dead parsing — no silent middle.
- **Keep:** CanonicalSBOM + registry; component-by-PURL identity.
- **Behavior on inputs:** Trivy scan of an N-package image → N components (was 1); CycloneDX with
  non-purl bom-refs → correct or explicitly-skipped edges; decided, documented embedded-vuln
  behavior.
- **Architecture impact:** parser fixes; optional new `scanner` CorrelationSource if import chosen.
- **Testing:** _unit/fuzz_ — parsers never panic, idempotent, correct component counts; qualifier
  round-trip. _integration_ — Trivy/CycloneDX/SPDX fixtures → expected inventory + (if imported)
  findings with `source=scanner:*`.
- **Risk/Deps:** depends on CR-3 if importing. Risk: low–medium (import decision is a product
  call — see Open decisions).
- **Maps to:** the SBOM-vs-image-scan / correlator-vs-aggregator discussion.

##### CR-10 — Quality gates: regression corpus + acceptance oracle expansion

- **Root cause:** the bugs shipped because tests used synthetic data and per-path logic was
  untested against real feeds.
- **Change:** Build a **golden corpus** of real (sanitised) inputs — Alpine/RPM/npm SBOMs, OSV zip
  slices, NVD CPE samples, CSAF VEX + RHSA advisories — and a **before/after finding-set diff**
  harness so any correlation change is reviewed as an explicit delta. Expand the acceptance oracle
  (G1–G8) to OSV-origin severity, provenance, feed re-layering. Add property tests for CR-1/CR-2;
  fuzz for parsers (CR-9).
- **Keep:** the `rapid` harness, coverage thresholds, the 6-gate sequence.
- **Testing:** this IS testing; the corpus diff is a required review artifact for CR-2/CR-4/CR-6.
- **Risk/Deps:** spans all CRs; start early so CR-1/CR-2 land against it.
- **Maps to:** quality assurance for the whole plan.

#### Behavior-on-inputs matrix (end-state, after all CRs)

| Input | Today | After refactor |
| ----- | ----- | -------------- |
| Alpine apk SBOM | findings from OSV.dev only; severity/risk all 0; distro data in overlay | merged OSV.dev + distro-OSV findings with severity + fixed; risk spreads; `source` recorded |
| RPM SBOM | OSV skipped → near-zero findings | RHSA + Rocky-OSV correlation → real findings |
| npm SBOM | OSV.dev + NVD (NVD over-matches) | OSV.dev + NVD merged, correct ranges, provenance |
| Trivy image scan | 1 component per result; vulns parsed then dropped | N components; decided import (provenance) or removed |
| CPE `[2.0,2.5)` + v1.0 | false match | no match |
| Duplicate re-upload | idempotent | idempotent (unchanged) |
| Red Hat CSAF VEX `not_affected` | never ingested | overlay suppresses finding |
| Feed outage | silent; cached data; no signal | ERROR log + `degraded_feeds[]` + metric |
| `THEMIS_LOG_LEVEL=debug` | affects zap slice only | affects all logs uniformly |

#### Testing strategy (cross-cutting)

1. **Unit (per-package thresholds):** pure logic — version engine, constraint sets,
   merge/precedence, CVSS parse, feed mappers, parsers. Property tests for all comparison/merge
   invariants.
2. **Integration (`//go:build integration`, embedded Postgres):** each `CorrelationSource` end to
   end; multi-source merge + provenance; feed re-layering; migrations up/down; logging assertions;
   `degraded_feeds[]`.
3. **Acceptance (oracle):** extend G1–G8 to OSV-origin severity, provenance, correlator-vs-overlay
   separation; score oracle stays green.
4. **Regression corpus (CR-10):** golden real-world inputs + finding-set diff; required review
   artifact for any correlation-affecting CR; seeded with the exact counterexamples behind D-NVD-1.
5. **Gate sequence (unchanged):** build → unit → coverage → deadcode → integration → clean-arch →
   verify-build, per CR.

#### Sequencing & release mapping

| Phase | CRs | Theme | Gate to next phase |
| ----- | --- | ----- | ------------------ |
| **A — Foundations** | CR-1, CR-3, CR-7, CR-10 (seed) | version engine, provenance schema, logging, corpus | foundations green; corpus baseline captured |
| **B — Correlation core** | CR-2, CR-6, CR-4 | one correlator, NVD fix, feed re-layering | corpus diff reviewed; no unexpected finding-set drift |
| **C — Enrichment & visibility** | CR-5, CR-8, CR-9 | CVSS backfill, feed health surface, parser integrity | G1–G8 pass on real Alpine/RPM SBOMs |

- **v0.3.0 (current line):** fold CR-3's additive columns in before tag if timing allows (else a
  new migration). CR-1/CR-7 safe to land early.
- **Next minor (post-v0.2.1):** Phase A + B. **Following minor:** Phase C; clears the Phase 2b
  feed-health/signal-quality gate.
- Each CR maps to an `openspec/changes/<name>/` change for execution.

#### Backward compatibility & data migration

- **Schema:** all changes additive; existing rows valid; `source` backfilled as `legacy` then
  recomputed on next scan/backfill.
- **Config:** `rhel_url` kept as a deprecated alias for `rhel_csaf_url` for one release with a
  startup WARN (now that logging exists — CR-7).
- **API:** new fields additive; `vex-coverage` semantics tighten (document in release notes).
- **No in-place pre-v0.3.0 upgrade** assumption unchanged.

#### Risks & mitigations

| Risk | Mitigation |
| ---- | ---------- |
| Correlation changes shift finding sets unexpectedly | CR-10 golden-corpus diff as required review; shadow-run new Correlator and compare before cutover |
| Version-engine change alters existing correct matches | keep `VersionMatches` semantics; property + corpus regression |
| Scope creep across 10 CRs | strict phase gates; each CR independently shippable behind the foundations |
| Schema change late in v0.3.0 | additive only; can defer to a follow-on migration |
| Mid-cycle disruption to v0.2.1 testing | plan only now; no code until v0.2.1 testing closes |

#### Open product decisions — RESOLVED (2026-06-24)

1. **CR-9 — scanner findings:** ✅ **remove the dead parsing** (Themis stays a pure re-correlator).
2. **CR-3 — provenance precedence:** ✅ **distro-authoritative** (distro feed > OSV.dev > NVD for
   distro packages; OSV.dev/NVD for app ecosystems) — implemented as a strict total order.
3. **CR-3 timing:** ✅ **fold columns into the v0.3.0 baseline** migration.

#### Definition of done

- ✅ R1/R2/R3 eliminated: one version engine, one correlator with provenance, one observable logger.
- ✅ D-CVSS-1, D-FEED-1, D-NVD-1, D-LOG-1 closed with tests.
- ✅ Golden corpus + finding-set diff harness in the test suite; property tests for CR-1/CR-2.
  ⏳ **G1–G8 on real Alpine + RPM SBOMs** is the one outstanding (operational E2E) item.
- ✅ All six gates green for every CR; clean-arch preserved (no zap/slog in domain/usecase).
- ✅ Operators can answer "is my feeder working and what did it find" from `/status`
  (`degraded_feeds[]`), `/metrics` (`themis_cvss_backfill_total` etc.), and structured logs.

---

#### v0.2.1 — Maintenance release (feed reliability + Phase 1 hardening) — Planned

**Type:** patch release on the v0.2.x line. No breaking changes, no schema changes.
**Releases as:** v0.2.1
**Contents:**

- **Group 31 (8 tasks)** — feed-reliability and signal-quality fixes (Alpine CVE ID
  normalization, OSV CVSS vector parsing, vendor feed URLs, ExploitDB API/metric wiring).
  Clears Alpine E2E gate checks G2, G4–G8.
- **Group 16 hardening remainder** — 16.1 Alpine package-name normalization, 16.2/16.3
  integration tests, 16.5 upload helper, 16.6 `make check`, 16.7/16.8 coverage gates.

**Excluded (require breaking change):** 16.4 / 16.10 registration endpoints and the G3
VEX-export-without-SQL fix — these land with `themis-core-model` in v0.3.0.

**Why a separate patch:** ships the Alpine/feed correctness fixes to operators sooner,
without waiting for the breaking `themis-core-model` restructure and Phase 2b. `v0.2.1`
can be cut as soon as Group 31 + the Group 16 hardening remainder are green.

---

#### Candidate change — Feed observability (`themis-feed-observability`) — ✅ DONE (CR-8, 2026-06-24)

> **Implemented as CR-8** (2026-06-24): `feed_health` table (folded into the v0.3.0 baseline,
> up + down), a recorder wired into every feed scheduler (success resets / failure increments the
> streak), and `degraded_feeds[]` on `GET /api/v1/status`. The detailed problem analysis below is
> retained for history. _Optional remaining polish: a `FEED_DEGRADED` push notification and a
> `/readyz` per-tier signal (the table + status surface are in)._

**Type:** additive new capability (schema change — new table). Targets v0.3.0-era.
**Problem:** feed failures are easily missed. Today the only user-visible feed health is
`signals_stale` for EPSS/KEV, and it is **pull-only** (`GET /api/v1/status`). Vendor VEX and
ExploitDB sync failures persist nothing — they produce a single `WARN`/`ERROR` log line per
8–24h cycle plus a Prometheus counter that only helps if the operator scrapes it and wrote an
alert rule. The `degraded_feeds[]` design in `openspec/intel-source-tiers.md` was specced but
never implemented.

**Current state (verified in code):**

| Feed (tier) | Persisted status | In `/status` API | Metric | Notification |
| ----------- | ---------------- | ---------------- | ------ | ------------ |
| EPSS / KEV (T1) | `epss_kev_signals.stale` + 25 h TTL on `fetched_at` | `signals_stale` | `themis_epsskev_sync_total`, `themis_epsskev_stale` | none |
| Vendor VEX RHEL/Alpine/Rocky/Wolfi (T2) | none | none | `themis_vexfeed_sync_total` | none |
| ExploitDB (T2) | none | none | none (wired in v0.2.1, Group 31.8) | none |

**Proposed scope:**

- **Persist per-feed health** — new `feed_health` table (`feed`, `tier`, `last_success_at`,
  `consecutive_failures`, `last_error`, `last_attempt_at`). Each scheduler upserts on every
  cycle. Replaces the derived-only EPSS/KEV staleness with real, queryable history.
- **Surface in status API** — implement `degraded_feeds[]` on `GET /api/v1/status` per the
  tier doc, so one call shows every feed's health (not just EPSS/KEV).
- **Push, don't just store** — reuse the existing `NotificationSender` (SMTP/Teams) to send a
  `FEED_STALE` / `FEED_DEGRADED` alert when a Tier-1 feed goes stale or any feed fails N
  consecutive cycles. Turns a buried 24 h log into an actual notification (the "won't miss
  it" fix). Threshold + routing configurable.
- Optional: degraded signal on `/readyz` when a Tier-1 feed is stale.

**Hooks:** `NotificationSender` already exists (SMTP + Teams); per-tier error behavior is
defined in `openspec/intel-source-tiers.md`; metric names already registered.
**Why deferred from v0.2.1:** v0.2.1 is a non-breaking patch; the `feed_health` table is a
schema change and the notification path is new behaviour.

---

#### Candidate change — Feed registry / user-defined feeds (`themis-feed-registry`) — ✅ DONE (v0.3.9)

> **Complete (v0.3.9).** CR-4 delivered the feed _class_ taxonomy (`rhel_vex_url` vs
> `rhel_csaf_url`; OSV feeds reclassified as correlation sources); v0.3.9 adds the user-facing
> `vexfeed.feeds:` delta list. `config.FeedConfig` + `httpserver.ResolveVEXFeeds` merge built-in
> defaults (derived from the legacy `*_url` fields, so existing configs are unchanged) with the
> delta list **by name** — add a custom feed, override a built-in's fields, or disable one
> (`enabled: false`). `type` (`url`/`zip-osv`/`csaf-dir`) selects the source constructor; `class`
> (`correlation` default, or `overlay`) routes it to the correlation loader vs the VEX overlay
> service; unknown-type / missing-URL enabled feeds are skipped with a logged warning.
> `api_wiring.go` consumes the resolved lists. Built-in names: `rhel-vex` (overlay); `rhel-csaf`,
> `alpine`, `rocky`, `wolfi` (correlation). See `docs/release-notes/release-notes-v0.3.9.md`. Original proposal
> retained below.
>
> **Prior status — Partially done (2026-06-24).** CR-4 delivered the feed _class_ taxonomy; the
> user-defined `vexfeed.feeds:` delta list (add/remove/disable) was still pending — feeds were
> hardcoded in DI. Now shipped in v0.3.9.

**Type:** additive capability + config-shape change. Targets v0.3.0-era.
**Problem:** the feed set is fixed. `VEXFeedConfig` is hardcoded struct fields
(`RHELURL`, `AlpineOSVURL`, `RockyOSVURL`, `WolfiOSVURL`). Operators can **override** each
URL and poll interval (`themis.yaml` / env) but **cannot add, remove, or disable** a feed.

**Proposed scope:**

- Refactor vendor feed config from fixed fields to a **feed registry**: built-in defaults
  plus a user **delta list** in `themis.yaml`, merged by `name` (add custom feed, override a
  default, or disable one). Example:

  ```yaml
  vexfeed:
    feeds:
      - name: my-distro-osv
        type: zip-osv          # url | zip-osv | csaf-dir
        url: https://.../all.zip
        ecosystem: mydistro
        tier: 2
        enabled: true
        poll_interval: 12h
      - name: rocky-osv         # override/disable a default by name
        enabled: false
  ```

- Each entry carries its **tier**, so the error/observability behaviour from
  `themis-feed-observability` applies automatically to custom feeds.
- Subsumes the existing "Per-feed enable/disable" follow-on (see Vendor VEX feed operations
  table above) — that item folds into this registry model.
- Builds on the `ZipOSVFeedSource` / `CSAFDirectoryFeedSource` source abstraction introduced
  in v0.2.1 (the `type` field selects the fetch model).

**Why deferred from v0.2.1:** changes the config contract (`vexfeed` shape) and is broader
than the bug-fix scope; sequence it after v0.2.1 lands the source abstractions it builds on.

---

#### Phase 2b — AI Intelligence (`themis-phase-2b`) — Planned

**Gate:** Phase 2a archived, Group 31 complete, signal feeds confirmed healthy (G1–G8 pass),
and **DEFECT D-CVSS-1 fixed** — ✅ **D-CVSS-1 is now fixed (CR-5, 2026-06-24)** and the whole
Layer-0 refactor (CR-1…CR-10) has landed, so the AI workers will be seeded against real
severity/CVSS rather than an all-`unknown`/all-`0` corpus. The remaining gate item is the
operational G1–G8 confirmation on a real deployment. **Phase 2b is effectively unblocked.**
**Releases as:** v0.4.0
**OpenSpec change:** `openspec/changes/themis-phase-2b/` (to be created)

**Hardware prerequisites (operator must verify before deploying Phase 2b):**

- RAM: 16 GB minimum (Ollama model ~4.5 GB + PostgreSQL ~4 GB + pgvector + OS)
- GPU: strongly recommended — CPU-only inference is 60–180 s per model call
  (vs 1–8 s with GPU); CPU-only deployments set `ai.worker_concurrency=1`
- Disk: NVMe SSD; model weights ~4.5 GB; grow with pgvector KB size
- CyberPal-2.0 may not be in Ollama's public registry — most deployments will
  use the automatic Qwen2.5-7B fallback (see design.md Decision 3)
- PostgreSQL must have the `pgvector` extension installed before migration 000015

**What:**

- **Ollama integration** — HTTP client for CyberPal-2.0 / Qwen2.5-7B; model health check
- **pgvector + L1c Semantic Memory** — embedding table; HNSW index; nomic-embed-text model
- **KB-first optimisation** — pgvector similarity ≥ 0.92 → apply past decision, skip model
- **7 AI skill workers** — CWE Mapper, CVE Summarizer, Exploitability Analyzer, Context
  Analyzer, VEX Recommender, Remediation Advisor, False Positive Analyzer
- **Async JobQueue wiring** — AI enrichment jobs triggered for CVSS ≥ 7.0 OR KEV OR ExploitPublic
- **RAG context assembly** — per-finding context built from L0/L1/external sources + KB
- **Risk Explanation synthesis** — headline + narrative from all worker outputs
- **AI enrichment status in API** — `enrichment_status: pending|complete` in findings response
- **Cold-start fixes** — G1 (VEX overlay re-trigger), G7 (batch throttle), G9 (enrichment_status)

**Why deferred from 2a:** AI workers are only meaningfully testable when EPSS/KEV/ExploitDB
signals are present. Building 2b on an empty signal foundation makes it impossible to
distinguish AI errors from missing data errors.

**Phase 2a hooks:**

- Layer 1 + Layer 2 provide the deterministic signals AI workers consume
- Microservice/Deployment entities provide service descriptions for Context Analyzer
- `risk_context` and the durable enrichment family key on the stable identity
  `(artifact_id, component_purl, cve_id)` after `themis-core-model` (D15), so AI enrichment
  attaches additively — Phase 2b adds the `ai_exploitability` / `ai_reachability_confidence`
  columns (they do **not** exist yet; no core-model table needs ALTER to add them)

**Database migrations:** 000015 (pgvector extension + embeddings table),
000016 (ai_summaries, ai_cwe_mappings, ai_exploitability, ai_vex_recommendations,
ai_remediation_advice, ai_fp_analysis)

---

#### Phase 2c — AI-Assisted VEX (`themis-phase-2c`) — Planned

**Gate:** Phase 2b running; KB has ≥ 50 seeded analyst decisions (threshold tunable).
**Releases as:** v0.5.0
**OpenSpec change:** `openspec/changes/themis-phase-2c/` (to be created)

**What:**

- **VEX auto-apply** — VEX Recommender confidence ≥ threshold auto-creates
  `vex_document(source=ai_generated)`; resolves OQ-5 (default 0.85)
- **FP auto-apply** — FP Analyzer confidence ≥ threshold auto-sets
  `effective_state=FALSE_POSITIVE`; resolves OQ-6 (default 0.90)
- **Four-eyes rule** — `trust_policy=strict` requires human confirmation before
  auto-apply fires; resolves OQ-10
- **FINDING_AUTO_SUPPRESSED notification** — new event type when AI suppresses a
  finding; fixes G4 (silent suppression)
- **Confidence threshold config** — `config.ai.vex_auto_apply_threshold`,
  `config.ai.fp_auto_apply_threshold` configurable per deployment
- **AI justification in VEX export** — enriches the 2a vex-export with AI-generated
  justification text and confidence scores

**Why after 2b:** Confidence thresholds (0.85, 0.90) are only meaningful when the KB
has real analyst decisions to retrieve. Tuning auto-apply against an empty KB
would result in under- or over-suppression — either missing real issues or drowning
analysts in false positives.

**Phase 2b hooks:**

- VEX Recommender + FP Analyzer workers already produce `auto_apply` bool and
  `confidence` float in their JSON output
- `vex_documents.source` enum already includes `ai_generated`
- `trust_policy` enum in domain already has `strict`, `standard`, `permissive`

---

### Architecture — deep-module deepening opportunities

> Tracked from the `/improve-codebase-architecture` review (2026-07-02). These are **deepening**
> refactors — turn a shallow, scattered concept into a **deep module** (a lot of behaviour behind a
> small **interface**, at a clean **seam**, tested through that interface). Vocabulary: module,
> interface, depth, seam, adapter, leverage, locality, deletion test. None are blocking; revisit as
> the surrounding code is touched. **This list will grow during Phase 2b** (the AI workers + KB add
> new seams — record deepening candidates here as they surface).

Ranked by real friction (correctness first, then boilerplate). IDs `AD-n` for cross-referencing.

#### AD-1 — PURL identity smeared across ~6 parsers (Strong; correctness)

**Friction:** there is no single _parsed PURL_ concept; six modules each re-parse `pkg:` strings and
they **disagree**, so a parsing fix lands in one and the others drift (this is how the `epoch=`
qualifier fix in v0.3.6 touched only `rpmInstalledVersion`).

- `internal/adapter/parser/purl.go` — `ecosystemFromPURL`, `nameVersionFromPURL`, `decodePURLSegment`
  (the only one that percent-decodes, `libstdc%2B%2B` → `libstdc++`).
- `internal/adapter/vexfeed/purl.go` — `parsePURL` (only one modelling `{Type,Namespace,Name,Version}`;
  no percent-decode, no epoch fold).
- `internal/usecase/enrichment/redhat_vex.go` — `rpmPackageName`, `rpmInstalledVersion`,
  `rpmEpochQualifier` (only place that folds the `epoch=` qualifier into the version).
- `internal/domain/version_match.go` (`StripPURLVersionQualifiers`, `VersionedPURL`),
  `internal/domain/version_engine.go` (`RPMReleaseMajor`) — pure/tested, but _which field feeds
  `RPMReleaseMajor` is decided divergently at the call sites_ (`vexfeed/correlation_source.go` uses a
  5-way fallback; `redhat_vex.go` feeds only the PURL).

**Deletion test:** concentrates — a genuine normalized-identity concept exists and is scattered.
**Deepening:** one `domain.PURL` (`ParsePURL(s) → {Ecosystem, Namespace, Name, Epoch, Version,
Release, StreamMajor, Qualifiers}`); every parser becomes one call. Mirrors the CR-1
`version_engine` unification. **Leverage:** one interface, 6 call sites. **Locality:** epoch/decode/
stream bugs concentrate.

#### AD-2 — VEX-overlay effective-state policy spread across 4 modules (Strong; correctness)

**Friction:** deciding a finding's `effective_state` (suppressed/resolved/confirmed) crosses four
seams, so a policy change ("not_affected requires a justification", "fixed must clear the stream
check") touches three at once. The libtiff false-resolution (v0.3.6) required tracing all four.

- `internal/adapter/vexfeed/matcher.go` — `matchRPM`/`matchAlpineOSV`/`alpineRangeStatus` compute a
  status into `MatchOutcome.ResolvedStatus`.
- `internal/domain/redhat_vex.go` — `VerdictForStream` (Covered/NotAffected/FixedEVR).
- `internal/usecase/enrichment/redhat_vex.go` — `buildAssertion` re-decides Fixed/Affected with its
  own version compare.
- `internal/usecase/enrichment/service.go` — `SourceRank` (precedence), `PickWinningAssertion`,
  `ResolveEffectiveState` (status → state, source-conditional).

**Leaky seam:** `MatchOutcome` carries the rich result, but `vendorAssertionMatch` discards it and
rebuilds a flattened `VEXAssertionMatch` — the matcher's answer doesn't survive its own interface.
**Deletion test:** concentrates. **Deepening:** one policy module `Resolve(finding, assertions) →
(effective_state, reason)`; the interface becomes the test surface for VEX policy.

#### AD-3 — Eight near-identical feed schedulers → one deep scheduler (Worth exploring; boilerplate)

**Friction:** `internal/infrastructure/http/{correlation_feed, cvss_backfill, epsskev, exploitdb,
redhat_vex, vexfeed, watch}_scheduler.go` are 45–52 lines and structurally byte-identical (nil-guard,
`LoggerOrNop`, `FeedHealthRecorderOrNop`, interval default, run-once-then-tick, error→`RecordFeedFailure`
/ info→`RecordFeedSuccess`). Only four things vary: service type, method name
(`RunSync`/`RunCycle`/`RunBackfill`/`Refresh`), feed-name literal, logged fields. `triage_scheduler.go`
is the lone genuine variant (no health/logging) and stays.

**Deletion test:** moves (pure boilerplate — per-feed logic already lives in the services).
**Deepening:** `StartFeedScheduler(ctx, name, interval, log, health, cycle func(ctx)(result, error))`;
each feed becomes a one-line cycle func. Highest-confidence, most mechanical win. **Locality:** fix the
ticker/health loop once; delete ~7 shallow modules; one scheduler test instead of seven.

#### AD-4 — Store finding projection: positional SELECT↔Scan contract (Worth exploring; silent-corruption risk)

**Friction:** `internal/adapter/store/catalog.go` — `scanVulnerabilitySelect` lists 15 columns that
must line up **positionally** with 15 `rows.Scan` targets in `collectScanVulnerabilities` and the
`domain.ScanVulnerability` field order (the comment "order matches … Scan" admits the compiler can't
enforce it). Adjacent same-typed pointers (`*bool` exploit/kev; `*float64` risk/epss/blast) mean a
reorder or inserted column compiles clean and silently mis-populates. (The `select`/`joins` consts are
already shared across both query methods — good; only the string-list ↔ scan-slice coupling remains.)

**Deletion test:** concentrates (mildly). **Deepening:** scan into a `findingRow` struct by column
name (`pgx.RowToStructByName`) so the column name is the contract, not argument order. **Wins:**
removes a silent-corruption seam; column set defined once, by name.

---

### Phase 3 backlog

Phase 3 scope: Rate limiting, runtime observability, cosign/sigstore SBOM verification,
CI/CD ingestion (GitHub, GitLab, Bitbucket), deployment packaging, Redis queue, Web UI,
enterprise access control (RBAC/OIDC), high-availability deployment, admin CLI.

#### Rate limiting

**What:** Per-API-key rate limiter on all ingestion endpoints. Configurable burst and
steady-state limits. Return `429 Too Many Requests` with a `Retry-After` header.

**Why deferred from Phase 2:** A single-tenant Phase 2 deployment has no rate-limiting
need. Rate limiting becomes important when multiple teams or CI pipelines share an
instance — a Phase 3 concern once CI/CD integration lands.

**Phase 1 hooks:**

- chi middleware stack in `infrastructure/http/` is the right injection point
- API key model already scopes keys to products; rate limits can be per-key or per-product

---

#### Runtime observability

**What:** Structured log level configurable at runtime (no restart needed). Export OTel
traces to a configurable OTLP endpoint (Jaeger, Honeycomb, etc.). Add trace IDs to all
HTTP error responses.

**Why deferred from Phase 2:** `go.opentelemetry.io/otel` is already in `go.mod` and span
keys are defined in `domain/tracing.go`. The OTel exporter wiring is straightforward but
adds config surface area. Deferred to Phase 3 to keep Phase 2 config minimal.

**Phase 1 hooks:**

- OTel SDK and `domain/tracing.go` span key types already present
- `infrastructure/metrics/` has the OTel setup stub ready for the exporter wiring
- Zap logger already structured; adding `level` to config YAML is a 3-line change

---

#### Real signature verification (CosignVerifier)

**What:** Replace `StubVerifier` in `adapter/trust/` with a real cosign/sigstore verifier.
Verify SBOM artifact signatures against the Rekor transparency log. Strict trust policy
enforcement gains real cryptographic teeth — unsigned or tampered SBOMs are rejected.

**Why deferred from Phase 2:** Cosign adds a significant external dependency
(`github.com/sigstore/cosign/v2` pulls in the sigstore ecosystem). Phase 2 already
introduces AI model integrations and a new risk score formula. Deferring cosign keeps Phase
2 self-contained and gives the trust gate logic another phase of real-world use before
cryptographic enforcement is turned on.

**Phase 1 hooks:**

- `SignatureVerifier` interface is defined in `internal/domain/`
- `StubVerifier` implements it and records `trust_status` correctly — no API or pipeline
  changes needed, only the implementation at the DI root changes
- Trust policies (`strict`, `standard`, `permissive`) already enforced by the gate

---

#### CI/CD integration (GitHub, GitLab, Bitbucket)

**What:** SCM webhook receivers for GitHub (`push` / `release`), GitLab (`pipeline`), and
Bitbucket Cloud/Server (`repo:push`). Each webhook extracts or receives the committed SBOM
and submits it to the same `IngestionService.IngestSBOM` use case as manual upload. A new
`scm_webhook_configs` table stores per-product SCM configuration (provider, repo, SBOM path,
branch pattern). Git ref is recorded in `ingestion_jobs` metadata.

**Why deferred from Phase 2:** Phase 2 focuses on pure signal quality (AI enrichment,
EPSS/KEV, upstream VEX). CI/CD ingestion requires its own new infrastructure (SCM webhook
config table, branch-to-version mapping, SBOM discovery strategy) that is cleaner as a
focused Phase 3 workstream once the enriched risk signals are stable and the API contract
is settled.

**Phase 1 hooks:**

- `IngestionService.IngestSBOM` is format-agnostic — all ingestion sources call the same use case
- Webhook HMAC verification (`X-Themis-Signature`) middleware in `adapter/api/` is the pattern
- `ingestion_jobs` table can record the git ref as job metadata

---

#### Docker Compose deployment

**What:** `docker-compose.yml` that starts `themis` + PostgreSQL in one command. Multi-stage
Dockerfile that produces a minimal image (~15 MB via Alpine or distroless).

**Why deferred:** Phase 1 and 2 target the binary-on-bare-metal deployment model. Docker
packaging is a packaging concern, not a functionality concern. Adding it before the feature
set is stable means the image will change frequently.

**Phase 1 hooks:**

- Config loading (`infrastructure/config/`) uses env vars — Docker-native
- Database URL, API port, and all config are already env-var driven

---

#### Redis-backed job queue

**What:** Replace `InProcessQueue` with a Redis-backed queue. Workers can run in separate
processes. Supports horizontal scaling.

**Why deferred:** In-process queue with a goroutine pool handles Phase 1 and Phase 2 load.
Redis adds operational complexity (another service to deploy, monitor, and back up) that is
not justified until multi-instance deployment is needed (Phase 3).

**Phase 1 hooks:**

- `JobQueue` interface in `internal/domain/` is the swap point
- `InProcessQueue` in `internal/infrastructure/queue/` is one implementation
- Swap requires only a new struct implementing `JobQueue` + a DI root change in `cmd/themis/main.go`

---

#### Web UI (React SPA)

**What:** Native React SPA providing: product / version / image inventory views, SBOM upload
drag-and-drop, vulnerability dashboard with filters (severity, state, component), triage
workflow (accept, dismiss, escalate), notification rule editor.

**Why deferred:** Originally Phase 2 in `proposal-initial.md`. Moved to Phase 3 so that
Phase 2 can focus on AI enrichment and threat intelligence — the signal quality that makes a
dashboard useful. A dashboard of unscored noise is not worth building.

**Phase 1 hooks:**

- REST API is the only data source the UI will need
- OpenAPI spec (`api/openapi.yaml`) can generate a typed TypeScript client
- All list endpoints are already paginated (cursor-based)

---

#### RBAC + OIDC

**What:** Replace the Phase 1 `X-API-Key` auth with OIDC (OpenID Connect) tokens.
Role-based access control with roles: `reader`, `analyst`, `admin`. Integrate with
corporate identity providers (Okta, Azure AD, Google Workspace).

**Why deferred:** Single-tenant Phase 1/2 deployments don't need OIDC. Multi-tenant or
enterprise deployments do. Adding OIDC before the feature set is stable creates auth churn.

**Phase 1 hooks:**

- Auth middleware in `adapter/api/` is a single injection point
- API key auth and OIDC token auth can coexist via a middleware chain
- Product-scoped keys already establish the authorization model foundation

---

#### High-availability deployment

**What:** Kubernetes Helm chart. Horizontal pod autoscaling on ingestion workers.
Leader election for scheduled watch/EPSS jobs (only one pod runs the scheduler at a time).
Health endpoints already exist (`/health`, `/ready`).

**Why deferred:** Requires Redis queue (Phase 3) and Docker packaging (Phase 3). Phase 1/2
are single-instance deployments.

**Phase 1 hooks:**

- `/health` and `/ready` HTTP endpoints are already implemented
- All config is env-var driven — K8s ConfigMap/Secret compatible

---

#### Enhanced `themis-cli`

**What:** Expand the admin CLI (`infrastructure/cli/`) beyond `create-key` / `revoke-key`
to include: `list-products`, `trigger-rescan`, `export-vex`, `purge-stale-signals`. Package
as a standalone binary (`themis-cli`) distributed alongside the server.

**Why deferred:** Phase 1 admin CLI exists for key management only. Richer CLI operations
depend on Phase 2 features (EPSS, AI enrichment, VEX export) being available.

**Phase 1 hooks:**

- `infrastructure/cli/` package exists with the cobra/urfave command structure already in place
- DI root can expose the same use-case interfaces to CLI commands as to HTTP handlers

---

### Items from `proposal-initial.md` not yet assigned

These items appear in `proposal-initial.md` but were not included in Phase 1–3 planning.
They are captured here as unscheduled proposals.

| Item | Original location | Notes |
| ---- | ----------------- | ----- |
| Dependency graph visualisation | proposal ADR §7 | Requires UI (Phase 3 minimum) |
| Scan comparison (two `scan_reports` for same artifact) | proposal ADR §8 | Becomes `GET /api/v1/artifacts/{id}/scan-reports/{a}/diff?compare_to={b}` once `themis-core-model` lands; natural with the `scan_reports` table — no schema change required |
| Policy-as-code (OPA integration) | proposal ADR §9 | Replaces or extends trust policies in Phase 3+ |
| Notification webhook outbound (POST to 3rd party) | proposal feature | Currently SMTP + Teams only |
| CSV/Excel vulnerability export | proposal feature | Low priority; VEX export (Phase 2) covers the main case |
| CVE comment / annotation by analyst | proposal feature | Triage note field exists; no dedicated annotation endpoint |
