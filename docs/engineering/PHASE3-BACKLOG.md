# Phase-3 Greenfield — Pending & Deferred Work (single backlog)

**Updated:** 2026-07-24 · The one consolidated list of everything **not yet done** in the Phase-3 rebuild.
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
  plane is disable-able. **Δ2 is grilled + scaffolded (2026-07-24):** `EDR-INTELLIGENCE-01` **Revision 3**
  (Δ2 concrete cut, grounded component decisions C1–C7) + `openspec/changes/phase3-intelligence-d2`
  (proposal/design/tasks, 9 task groups) — **IMPLEMENTED + gated (9/9 groups, `make check` green, 2026-07-24)**.
  The grill narrowed Δ2 scope: budget =
  **meter only** (enforcement → G-AI-4), admission = **local-only** (classification/clearance → G-AI-5); plus
  the two-step `[Rule → LLM]` plan, the honest `insufficient` outcome, precedent-Positions grounding, and a
  which-step-decided provenance stamp.

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
  retrieval (RAG, Δ3). **Why open:** no release-diff capability today; ranking-by-similarity is Δ3 RAG-class.
  **Where it plugs in:** Intelligence Context Construction (grounding assembly) together with a Registry /
  Evidence release-comparison read-API and Δ3 RAG. **Dep:** builds on the Δ2 labeled-precedent grounding; needs
  release-diff together with Δ3 retrieval. **Scope:** Δ2 hands labeled precedent as-is; rank-by-delta is Δ3+.

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
