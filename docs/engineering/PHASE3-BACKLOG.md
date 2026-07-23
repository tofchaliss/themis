# Phase-3 Greenfield — Pending & Deferred Work (single backlog)

**Updated:** 2026-07-18 · The one consolidated list of everything **not yet done** in the Phase-3 rebuild.
Status of what **is** done lives in `PHASE3-STATUS.md`; this file is only the open work. Each item states
**what**, **why it's open**, **where it plugs in**, and its **dependency**.

Snapshot: the four-context pipeline **Evidence → Knowledge → Governance → Communication is implemented and
gated** (`make check` = exit 0, uncommitted on branch `phase3-evidence`). Open work is M4 Intelligence, the
M5 event bus, the full-pipeline e2e, and the per-context follow-ups below.

---

## A. Milestones not yet implemented (in dependency order)

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
  plane is disable-able.

- [ ] **M5 — Event Infrastructure (the shared outbox bus)** — not yet a scaffolded change. Today each context
  writes to its own transactional outbox and a relay drives a **logging-stand-in `Publisher`**; there is no
  real bus carrying events between contexts. M5 delivers the shared transport (+ subscription) the per-context
  inbound consumers already parse. **This is the blocker for the full-pipeline e2e (§B).** Dep: none new — the
  outbox tables + relays + inbound consumers are all in place.

---

## B. Full-pipeline verification (blocked on M5)

- [ ] **SBOM → published-VEX pipeline e2e** — one wired end-to-end test across all four contexts. All
  contexts + cross-context seams are built and each seam is contract-tested per-context (inbound consumer
  tests + read-API-client httptest drive the exact wire JSON). The single wired run **awaits M5** (the bus).
  See the staged testing table in `PHASE3-STATUS.md`.

---

## C. Deferred follow-ups inside completed contexts

> **✅ The Knowledge feed items below are IMPLEMENTED under `openspec/changes/phase3-knowledge-feeds`**
> (19/19 tasks, gated, 2026-07-23): real OSV query-by-package + NVD modified-since fetch clients, **CVSS 4.0**
> in the NVD extraction (go-forward D-NVD-2), the **source-tier taxonomy** + tier-aware feed-health policy
> (go-forward D-FEED-2), and **scanner reports as advisory source Proposals** (EDR-KNOWLEDGE-01 D5/D6). The
> only remaining piece is the concrete Evidence `scanner-report` read adapter (a documented prerequisite,
> fakeable today). The v0.3.x monolith defects D-NVD-2 / D-FEED-2 themselves stay open (this is the Phase-3
> realization, not the v0.3.x fix).

- [ ] **Knowledge — real feed-fetch HTTP clients.** The scheduled discovery/watch use real **OSV
  query-by-package** + **NVD modified-since** clients behind the existing `PackageVulnSource` /
  `ChangedVulnSource` ports (currently fakeable ports only). The G3 feed **ACLs already do the translation**;
  this is just the fetch adapters. Plugs into `internal/knowledge/adapters` behind the discovery/watch ports.

- [ ] **Knowledge — CVSS v4.0 in feed ACLs + Reconcile.** The feed ACLs and `Reconcile` headline-severity
  selection must parse **CVSS 4.0** (NVD `cvssMetricV40`; OSV v4.0 vectors), else recent CVEs land
  `severity=unknown` / `risk=0` — the go-forward equivalent of the v0.3.x **D-NVD-2** gap (root cause + fix in
  `docs/current-changes/project-backlog.md`). Fold v4.0 into the source precedence when the real feed clients
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

---

## D. Observability (R1) — remaining signals

- [ ] **OTel traces + metrics.** `internal/platform/observability` currently wires **logs** (zap console +
  OTel logs via the `otelzap` bridge, config-driven). R1/BCK-0051 covers all three OTel signals; the natural
  extension is a **TracerProvider + MeterProvider** in `Setup`, plus request/DB spans and operational
  counters. The Intelligence Gateway (M4) leans hardest on OTel and is a good driver for this.

---

## E. Process / optional refinements

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

---

## Not in scope (recorded so they are not mistaken for pending)

- The legacy `internal/` PoC tree is **reference only** and frozen at v0.3.x — not modified, not part of this
  backlog.
- `themis-ai-1` / `themis-phase-2` are archived as superseded (fold into M4 / reference).
