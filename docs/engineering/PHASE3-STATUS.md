# Phase-3 Greenfield Rebuild — Status & Resume Point

**Updated:** 2026-07-18 · **Read this first when resuming.**

Phase-3 is a **greenfield DDD rebuild** of Themis into four bounded contexts —
**Evidence → Knowledge → Governance → Communication** — plus an Intelligence Gateway, realized from the
architecture book (`docs/architecture/` Books I–III) and the **69 ADRs** (`docs/adr/`). It is the **sole
go-forward**; the current architecture is **frozen at v0.3.x**.

> **Resume snapshot (2026-07-18 session end):** **The whole four-context pipeline is IMPLEMENTED and gated** —
> M2 Kernel + M6 Evidence + M7 Knowledge + M8 Governance + **M9 Communication** (`make check` = exit 0). All
> work is **uncommitted on branch `phase3-evidence`** — nothing has been committed yet. **Next task: implement
> M4 Intelligence** (`phase3-intelligence`, the supporting AI Gateway beside the pipeline) — see "Next action"
> below. To verify green on resume: `make check` (whole repo) or the fast path
> `go build ./... && make arch-test`.

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
| **M4 — Intelligence** (AI Gateway) | `EDR-INTELLIGENCE-01` (Rev 2, D1–D13) | `phase3-intelligence` — **Δ1 IMPLEMENTED** (37/37, gated); Δ2–Δ4 remain | INTEL-01…12 |
| **M7+ — Knowledge feeds** (follow-on) | `EDR-KNOWLEDGE-01` (D5/D6) | `phase3-knowledge-feeds` — **IMPLEMENTED** (19/19, gated) | real OSV/NVD clients · CVSS 4.0 (go-fwd D-NVD-2) · source tiers (go-fwd D-FEED-2) · scanner Proposals |

All four docs lint-clean (`markdownlint-cli2`). Superseded work archived 2026-07-14:
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

**All six EDRs grilled + all six OpenSpec changes scaffolded.** Implementation is under way, in dependency
order:

- **M2 Shared Kernel — IMPLEMENTED (2026-07-16, 20/20, `make check` green).** `internal/kernel/{value,id,event}`
  (CVE-ID/PURL/fingerprint/CVSS/Severity, UUID+clock, event envelope+schema) + `internal/registry/{domain,app,
  adapters}` (Product→Project→Release, `ReleaseExists`, spec-first HTTP) + `cmd/registry`. Arch guarded by
  `TestKernelIsLeaf` + `TestRegistrySupportingContext`.
- **M6 Evidence — IMPLEMENTED (exemplar, 7/7).** 5-scenario e2e; see `EVIDENCE-VERIFICATION.md`.
- **Evidence SubjectRef — registry-backed.** `wiring.EvidenceAPI` takes the `SubjectRefValidator` port;
  `cmd/evidence` uses `registry.ReleaseExists` by default (allow-set stub only for dev/e2e).
- **M7 Knowledge — IMPLEMENTED (2026-07-16, 25/25, gated).** `internal/knowledge/{domain,app,adapters}`:
  Faultline aggregate + append-only Proposals + deterministic reconciliation (rapid property test caught a
  real order-dependence bug) + forward-only lifecycle; 6 feed ACLs → common Proposal; Postgres aggregate
  (optimistic concurrency) + transactional outbox + relay; correlation via the **Evidence read-API client**
  (`GetInventory`) emitting `ComponentMatched`; watch/discovery as fakeable ports; read API + affected-
  releases projection + first-class reconciler. domain/app 100%, adapters 83–98%.
- **M8 Governance — IMPLEMENTED (2026-07-17, 24/24, gated).** `internal/governance/{domain,app,adapters}` +
  `cmd/governance`: Finding aggregate (own identity, (Release, Faultline) key, matched-components content,
  **reopenable** Book II §7.5 lifecycle, append-only Governance Proposals + append-only immutable Enterprise
  Position versions, optimistic concurrency; rapid property test on the version/append-only invariants);
  inbound Knowledge-seam consumer (`ComponentMatched`→find-or-create Finding, `FaultlineEnriched`/
  `FaultlineSuperseded`→auto-raise a system proposal + flag for review, **never auto-decide**) via a
  non-owning coordinator; authority line (AI/system propose-only, human decides, Governance-owned policy
  auto-accept); Postgres aggregate + outbox + projections (release posture, Faultline blast-radius) + relay;
  spec-first triage + read HTTP API; state-based reconciler (outbox drain) + crash-resume durability.
  domain/app/inbound 100%, store 80.5%, http 97.9%.

- **M9 Communication — IMPLEMENTED (2026-07-18, 22/22, gated).** `internal/communication/{domain,app,adapters}`
  plus `cmd/communication`: **Publication** aggregate (own identity, Position-version reference + permanent
  lineage handles, immutable content + mutable delivery status, append-and-supersede, **capped/regenerable**
  payload); **deterministic materialization** with the hard **stance-equality invariant** (the artifact never
  restates a different conclusion than the Position); extensible **serializer registry** (OpenVEX /
  CycloneDX-VEX / CSAF / markdown advisory / json audit-report / channel-native text — golden-tested); inbound
  Governance Position-event consumer → **publishable-positions worklist** (Positions only, **no auto-publish**
  — D4); human-triggered `CreatePublication` (fetch Position via the Governance read-API client → materialize
  → serialize → record → supersede the prior current); Postgres aggregate + transactional outbox +
  projections + relay; **delivery worker** (exactly-once off the durable pending status, redaction hook,
  outcome recorded) + **retention/pruning** (regenerable) + first-class **reconciler**; spec-first
  publish/read/**preview** API. domain/app 100%, adapters 81–100%.

**Next:** implement **M4 Intelligence** (`phase3-intelligence`, INTEL-01…12) — the **supporting AI Gateway
beside the pipeline** (owns no truth): single exclusive provider entry, named capabilities → validated
structured **advisory Proposals** that Knowledge/Governance record + govern; **ship reactive-mode first**
(the autonomous engine second), both advisory-only. This closes the six-milestone set; the one wired
**SBOM → published-VEX pipeline e2e** then awaits **M5 Event Infrastructure** (the shared outbox bus). All
deferred per-context follow-ups (Communication channels, Governance expiry worker, Knowledge feed clients,
store fault-injection, OTel traces/metrics) are listed in [`PHASE3-BACKLOG.md`](PHASE3-BACKLOG.md).

Note (Option A in effect): `/grill-with-docs` is user-invoked, but the model can run the same via
`grilling` + `domain-modeling` directly — that is how `EDR-KNOWLEDGE-01` was grilled. Either works.

## Deferred / pending work

**All pending and deferred work lives in one place: [`PHASE3-BACKLOG.md`](PHASE3-BACKLOG.md).** It
consolidates the next milestones (M4 Intelligence, M5 event bus), the full-pipeline e2e (blocked on M5), the
per-context follow-ups (Knowledge real feed clients; Governance accepted-risk expiry worker; Communication
concrete channels + delegated auto-publish; store fault-injection coverage), the remaining observability
signals (OTel traces + metrics), and the optional Evidence tracer-bullet reslice. Update that file, not this
section, as items open or close.

## Key file pointers

- **Pending/deferred work (single backlog):** `docs/engineering/PHASE3-BACKLOG.md`
- EDRs (source of truth): `docs/engineering/decisions/EDR-{KERNEL,EVIDENCE,KNOWLEDGE,GOVERNANCE,COMMUNICATION,INTELLIGENCE}-01.md`
- **Tech stack + rationale (read before `/opsx:apply`):** `docs/engineering/STACK.md` — canonical stack;
  each change's `design.md` has a per-context **Stack** section pointing to it
- **Cross-cutting build rules (read before `/opsx:apply`):** `docs/engineering/CONVENTIONS.md` — R1 every
  node logs to console + OpenTelemetry; R2 config is self-documented in the config file with comments.
  **R1 is realized (2026-07-18) by `internal/platform/observability`** (zap console + OTel logs via the
  `otelzap` bridge, one `Setup`; config-driven level/format/OTLP endpoint via `ConfigFromEnv`; a
  `RequestLogger` correlation-id middleware; domain/app stay log-free by depguard). All four greenfield cmds
  wire it; example config at `deploy/node.env.example`.
- Changes: **none active** — all six to be scaffolded fresh from the EDRs; pre-scaffold Kernel/Evidence
  drafts archived at `openspec/changes/archive/2026-07-15-phase3-*-prescaffold/`
- Blueprints (to fill from Evidence exemplar): `docs/engineering/implementation-blueprint/01–06`
- Architecture source of truth: `docs/architecture/` (Books I–III) + `docs/adr/` (69 ADRs)
- Change status: `openspec/STATUS.md`
