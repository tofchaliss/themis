# Themis — Backlog

The single project backlog. Two parts:

- **Part 1 — Greenfield (go-forward, ACTIVE):** the live tracker for the Phase-3 rebuild — start here.
  Milestones not yet implemented, full-pipeline verification, deferred follow-ups, observability, process.
- **Part 2 — Legacy PoC history (frozen — reference only):** the Phase 1/2/3 planning history and the
  Layer-0 refactor log from the v0.3.x monolith. Kept for provenance and defect IDs (D-NVD-2, D-FEED-2);
  do not action against the frozen tree.

## Part 1 — Greenfield (go-forward, ACTIVE)

**Updated:** 2026-07-30 · The one consolidated list of everything **not yet done** in the Phase-3 rebuild.
Status of what **is** done lives in `PHASE3-STATUS.md`; the monolith→greenfield capability diff lives in
[`engineering/PARITY-GAP.md`](engineering/PARITY-GAP.md). This file is only the open work. Each item states
**what**, **why it's open**, **where it plugs in**, and its **dependency**.

Snapshot: the four-context pipeline **plus M4 Intelligence Δ1+Δ2 and M5 (event bus) are merged to `main`**,
and the stack is **deployed end-to-end on a Linux VM under systemd** (2026-07-30). The first monolith→greenfield
**parity cluster (correlation + enrichment) is closed** — distro (rpm) correlation, NVD/EPSS/KEV/ExploitDB
enrichment, and a deterministic priority+score (PRs #60–#63). Open work: the **delivery/security parity
cluster** (notifications, org blast-radius graph, API auth — see PARITY-GAP.md §B), M4 Δ3–Δ4, and the
per-context follow-ups below.

---

### A. Milestones not yet implemented (in dependency order)

- [x] **M4 Δ1 — Intelligence (AI Gateway) walking skeleton** — `phase3-intelligence`, `EDR-INTELLIGENCE-01`
  (Revision 2, D1–D13). **IMPLEMENTED + gated** (2026-07-18): one reactive capability `recommend_position`
  (affected/not-affected triage) end-to-end, pure Go, **disable-able** (D13 no-op gate) — `internal/intelligence/
  {domain,app,adapters}` + `cmd/intelligence` (stateless) + the Governance caller seam (`adapters/intelligence`
  client + no-op + on-demand `POST /findings/{id}/recommend`). Ollama (OpenAI-compatible) + fake provider;
  3-stage validation; read-API grounding.
- [ ] **M4 Δ2–Δ4 — Intelligence, the rest of the harness** (`docs/engineering/THEMIS-AI-HARNESS.md`): **Δ2**
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

### B. Full-pipeline verification (blocked on M5)

- [ ] **SBOM → published-VEX pipeline e2e** — one wired end-to-end test across all four contexts. All
  contexts + cross-context seams are built and each seam is contract-tested per-context (inbound consumer
  tests + read-API-client httptest drive the exact wire JSON). The single wired run **awaits M5** (the bus).
  See the staged testing table in `PHASE3-STATUS.md`.

---

### C. Deferred follow-ups inside completed contexts

> **✅ The Knowledge feed items below are IMPLEMENTED under `openspec/changes/phase3-knowledge-feeds`**
> (19/19 tasks, gated, 2026-07-23): real OSV query-by-package + NVD modified-since fetch clients, **CVSS 4.0**
> in the NVD extraction (go-forward D-NVD-2), the **source-tier taxonomy** + tier-aware feed-health policy
> (go-forward D-FEED-2), and **scanner reports as advisory source Proposals** (EDR-KNOWLEDGE-01 D5/D6). The
> only remaining piece is the concrete Evidence `scanner-report` read adapter (a documented prerequisite,
> fakeable today). The v0.3.x monolith defects D-NVD-2 / D-FEED-2 themselves stay open (this is the Phase-3
> realization, not the v0.3.x fix).

- [ ] **(LOW) Δ3a — re-embed on `knowledge.faultline_enriched`.** The population consumer
  (`internal/intelligence/adapters/inbound`) indexes on Governance **Position** events only; a later Faultline
  severity change (which feeds `embed.SubjectText`) does not re-embed the affected findings until their next
  Position event. A freshness optimization, not correctness — the vector still matches on components. **Fix:**
  a second subscription (stream `knowledge`, interest `knowledge.faultline_enriched`) that re-embeds the
  faultline's findings. Surfaced building A4 (2026-08-04).
- [ ] **(LOW) Δ3a — use `text_hash` to skip unchanged re-embeds.** `position_embeddings.text_hash` is
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
- [ ] **(LOW) Feed-health omits the always-on OSV feed.** `RecordSuccess`/`RecordFailure` are called only by the
  opt-in schedulers (NVD watch, EPSS/KEV sweep), never by OSV correlation — so with only OSV running, the
  feed-health surface (B1) is empty even though the primary feed is healthy. Have correlation stamp OSV health on
  each discovery pass. `internal/knowledge/app` + `adapters/feed`. Surfaced 2026-07-31.
- [ ] **(LOW) Feed-health records only *after* a full poll.** The first NVD watch poll is a 120-day
  modified-since query (~12 min), so `nvd` health does not surface until it completes — a fresh node looks
  feed-dark for minutes. Stamp health at poll *start*, or use a smaller first window. `cmd/knowledge` `watchLoop`.
  Surfaced 2026-07-31.
- [ ] **(MED) VEX round-trip mismatch — Themis cannot re-ingest its own published OpenVEX.** The OpenVEX
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
- [ ] **(MED) Release-posture `effective_priority` ignores the governed stance.** `ReleasePosture`
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
- [ ] **(LOW) Wolfi distro unmapped in OSV discovery.** `osvDistroEcosystem` (`adapters/feed/osv_client.go`) maps
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
- [ ] **(MED) Risk score — add the release-scoped blast multiplier per-Finding in Governance.** The
  Knowledge Faultline now carries a CVE-intrinsic `priority`/`score` (Layer-1 level + severity+EPSS+KEV
  base, `internal/knowledge/domain/priority.go`). The monolith's composite also multiplied by a blast
  factor (1.0–2.0× off the unique-customer/affected-release count) — a *release-scoped* input that belongs
  on the Governance Finding, not the Faultline. Wire a per-Finding priority = Faultline base × blast, reading
  the Faultline score via the Knowledge read API and the release count via Governance's blast-radius
  projection. Depends on the org asset graph (Product→…→Customer) for the true customer-count multiplier;
  the affected-release count is a usable proxy meanwhile. Surfaced 2026-07-30. See [[feedback-backlog-surfaced-followups]].
- [ ] **(LOW) OpenVEX output identifies the product by bare release UUID, with no vulnerable subcomponent.**
  The Communication OpenVEX serializer renders `statements[].products` as the raw `release_id`
  (e.g. `2859e949-…`) and emits no `subcomponents`. A downstream OpenVEX consumer can't resolve a bare UUID,
  and the affected package (e.g. `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`) is not named. Prefer
  a resolvable product identifier and add the correlated component PURL as an OpenVEX `subcomponent`. Plugs
  into the Communication serializer registry (`internal/communication/adapters/.../openvex`). Surfaced
  2026-07-30 verifying the end-to-end deployment. See [[feedback-backlog-surfaced-followups]].
- [ ] **(LOW) `cmd/knowledge` default listen port collides with Registry.** `THEMIS_KNOWLEDGE_ADDR`
  defaults to `:8082` — the same as `cmd/registry` — but the rest of the system addresses Knowledge at
  `:8085` (Intelligence's `THEMIS_KNOWLEDGE_URL` default; `deploy/node.env.example`). Running Registry +
  Knowledge on defaults fails to bind the second one. Fix: change the `cmd/knowledge` default to `:8085`.
  Until then the INSTALLATION.md runbook sets `THEMIS_KNOWLEDGE_ADDR=:8085` explicitly. Plugs into
  `cmd/knowledge/main.go` `loadConfig`. Surfaced 2026-07-30 wiring the end-to-end deployment.
  See [[feedback-backlog-surfaced-followups]].
- [ ] **(MED) `cmd/registry` cannot self-migrate into the `evidence` DB it shares with Evidence.**
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
- [ ] **(LOW) Consolidate the inbox ctx-tx unit-of-work into a shared `platform/uow` helper.** The
  `txCtxKey` / `withTx` / `txFromCtx` + `InboxConsumer` are duplicated per consuming context (Governance,
  Communication, later Knowledge). It is business-agnostic infra and could collapse into one platform package
  (a third after `observability` + `eventbus`), trading a little context independence for less duplication.
  Deferred: adding a platform package is an architecture decision to justify against the EDR; revisit if the
  duplication grows or a third/fourth consumer lands. See [[feedback-backlog-surfaced-followups]].
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
- [ ] **Knowledge — NVD by-CVE backfill (targeted enrichment).** The modified-since watch only covers CVEs
  changed within NVD's 120-day window; a card whose CVE fell out of that window (or was created after the
  last relevant modification) never gets NVD's authoritative CVSS/severity. Add a `FetchByCVEID` path and a
  targeted per-card enrichment trigger (e.g. on `FaultlineCreated`, or a backfill pass over cards missing an
  NVD proposal). Plugs into `internal/knowledge/adapters/feed` + a new backfill worker. Surfaced 2026-07-30.

- [ ] **Knowledge — CVSS v4.0 in feed ACLs + Reconcile.** The feed ACLs and `Reconcile` headline-severity
  selection must parse **CVSS 4.0** (NVD `cvssMetricV40`; OSV v4.0 vectors), else recent CVEs land
  `severity=unknown` / `risk=0` — the go-forward equivalent of the v0.3.x **D-NVD-2** gap (root cause + fix in
  **Part 2 — D-NVD-2** below). Fold v4.0 into the source precedence when the real feed clients
  (above) land; prefer `v3.1 → v3.0 → v4.0 → v2`, Primary over Secondary.

- [ ] **Governance — structured AI-proposal fields.** Δ1 records an AI recommendation via existing fields
  (actor `{ai, "recommend_position@v1"}` = provenance; confidence + reasoning in the rationale). The additive
  follow-up gives `GovernanceProposal` first-class **confidence / evidence-refs / source (capability+version)**
  columns (nullable for non-AI proposals) — it ripples through domain + store schema + read API, hence
  deferred. Needed before the confidence-threshold auto-accept policy (EDR-INTELLIGENCE-01 D8).

- [ ] **Governance — accepted-risk expiry/timer worker.** A worker that, when an accepted-risk decision
  expires, raises a reopen/reconsider Governance Proposal (the PoC's `ListExpiredAcceptedRiskFindings`
  behavior). **Needs an accepted-risk-until field on the Enterprise Position** first. Plugs into
  `internal/governance/adapters` + a small domain addition.

- [ ] **Communication — concrete delivery channels.** Real **SMTP / Slack / webhook** push adapters + the
  **routing rules / digest / redaction** machinery (reuse the PoC `notify`: `routing.go`, `digest.go`,
  `retry.go`, `redact.go`, `smtp.go`, `teams.go`). Today a **logging deliverer + pass-through redactor** ship
  behind the `Deliverer` / `Redactor` ports; the exactly-once/idempotent/outcome-recorded mechanics are done.
  Plugs into `internal/communication/adapters/delivery`.

- [ ] **Communication — delegated auto-publish policy.** Currently **all** artifact creation is
  human-triggered (a deliberate stricter-than-CON-0015 initial scope). A Governance-defined delegated
  auto-publish policy becomes an alternate **trigger source** alongside the human trigger — no model change.
  (EDR-COMMUNICATION-01 D4 "for the time being".)

- [ ] **All contexts — store fault-injection coverage.** Lift the aggregate stores
  (evidence/knowledge/governance/communication ~80–83%, registry 89%) toward 90%+ by covering the DB-error
  branches via an **injectable `pgxpool` interface** (fault injection). Behavior is already proven by the
  embedded-Postgres integration tests; only error-path lines remain. The store tier is intentionally set to
  80% until this lands.

- [ ] **G-AI-1 — On-demand "fresh-CVE" gathering: the AI asks, the feeds gather.** _(Gap surfaced in the
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

- [ ] **G-AI-3 — Rank precedent decisions by release-to-release delta.** _(Gap surfaced in the M4 Δ2 grill,
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

- [ ] **G-AI-4 — Budget enforcement policy deferred; Δ2 measures only.** _(Gap surfaced in the M4 Δ2 grill,
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
  gate.** _(Gap surfaced in the M4 Δ2 grill, 2026-07-24.)_ Δ2's pre-invocation gate is deliberately minimal
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

- [ ] **G-AI-6 — `NeedFinding` is declared but never consulted; the grounding root is hardcoded.** _(Found in
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

- [ ] **TRUST-2 — The shipped-source list for the classification guard is manual.**
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

---

### D. Observability (R1) — remaining signals

- [ ] **OTel traces + metrics.** `internal/platform/observability` currently wires **logs** (zap console +
  OTel logs via the `otelzap` bridge, config-driven). R1/BCK-0051 covers all three OTel signals; the natural
  extension is a **TracerProvider + MeterProvider** in `Setup`, plus request/DB spans and operational
  counters. The Intelligence Gateway (M4) leans hardest on OTel and is a good driver for this.

---

### E. Process / optional refinements

- [ ] **Tracer-bullet reslice for Evidence** (optional). Fold these demoable vertical slices into
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

- [ ] **Domain glossary upkeep.** Grilling has not been maintaining a domain glossary; the real
  `/grill-with-docs` (`grilling` + `domain-modeling`) would start doing so on future EDRs.

- [ ] **Extend CI with the pipeline e2e (post-M5).** CI is **live on `main`** (PR #53):
  `.github/workflows/{pr,main}.yml` run a greenfield-scoped **`make check-ci`** (+ `make e2e-evidence` on
  `main`). When M5 lands `make e2e-pipeline` (`phase3-event-infrastructure` tasks 9.1 / 10.4), add an
  `e2e-pipeline` step to `main.yml` (mirroring `e2e-evidence`), and to `pr.yml` if pre-merge pipeline proof is
  wanted. Kept **out of `make check-ci`** deliberately (e2e is slow; consistent with `e2e-evidence`). Optional:
  a `make e2e` / `make ci` aggregate target.

- [ ] **Close the PR-gate e2e blind spot (LOW — revisit post-M5).** `make e2e-evidence` runs only on the
  post-merge `main.yml`, not on `pr.yml` (it carries the `e2e` build tag, excluded from `check`/`check-ci`), so
  a change that breaks e2e merges **green** and only reddens `main` afterward. This bit us: PR #55 renamed
  `evidence_outbox.evidence_id` → `subject` (M5 migration `000002`) without updating the e2e `outboxCount`
  helper; the PR passed, `main`'s Main run went red, fixed in PR #56 (`8c6a7c3`). **Decision:** stays
  backlogged at low priority — revisit **after M5**; implement only if it recurs or a green gate ends up with a
  straight dependency on pre-merge e2e proof. Natural fix is to run e2e on `pr.yml` too (folds into the
  pipeline-e2e item above once `make e2e-pipeline` exists).

- [ ] **Bump GitHub Actions off Node 20 (LOW).** `actions/checkout@v4` and `actions/setup-go@v5` are being
  force-migrated to Node 24 (runner deprecation warning on every run). Cosmetic today; bump to the Node-24
  action majors next time `.github/workflows/*` are touched.

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
