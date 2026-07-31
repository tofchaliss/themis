# Phase-3 Greenfield Rebuild — Status & Resume Point

**Updated:** 2026-07-30 · **Read this first when resuming.**

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

**M4 Intelligence — IMPLEMENTED (Δ1 37/37 + Δ2 9/9, gated, merged to main).** The supporting AI Gateway
beside the pipeline (owns no truth): reactive `recommend_position` → typed `[Rule → LLM]` dispatch + the
admission spine; Δ3 (Python + RAG) and Δ4 (autonomy + LLMOps) deferred (see `docs/BACKLOG.md` §A).

**In progress: M5 — Event Infrastructure** (`phase3-event-infrastructure`, EB-01…EB-11) — the
**platform-owned event bus** carrying events between contexts (PostgreSQL channel now, Kafka-swappable later
behind stable ports), which unblocks the single wired **SBOM → published-VEX pipeline e2e**. Implementation
**started 2026-07-27** on branch `phase3-event-infrastructure` via `/opsx:apply phase3-event-infrastructure`
(**9/43 — Groups 1–2 done** as of 2026-07-28: the `eventbus` scaffold + `bus` DB, and the full `Envelope`
threaded end-to-end through every outbox + both inbound consumers; `make check` green); source of truth
`EDR-EVENTBUS-01` (D1–D11). Also newly on `main` this session: **CI**
(greenfield `make check-ci`, PR #53) and the **consolidated `docs/BACKLOG.md`** (PR #54). All deferred
per-context follow-ups (Communication channels, Governance expiry worker, store fault-injection, OTel
traces/metrics) are listed in [`docs/BACKLOG.md`](../BACKLOG.md).

Note (Option A in effect): `/grill-with-docs` is user-invoked, but the model can run the same via
`grilling` + `domain-modeling` directly — that is how `EDR-KNOWLEDGE-01` was grilled. Either works.

## Deferred / pending work

**All pending and deferred work lives in one place: [`docs/BACKLOG.md`](../BACKLOG.md) (Part 1).** It
consolidates the next milestones (M4 Intelligence, M5 event bus), the full-pipeline e2e (blocked on M5), the
per-context follow-ups (Knowledge real feed clients; Governance accepted-risk expiry worker; Communication
concrete channels + delegated auto-publish; store fault-injection coverage), the remaining observability
signals (OTel traces + metrics), and the optional Evidence tracer-bullet reslice. Update that file, not this
section, as items open or close.

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
  wire it; example config at `deploy/node.env.example`.
- Changes: **none active** — all six to be scaffolded fresh from the EDRs; pre-scaffold Kernel/Evidence
  drafts archived at `openspec/changes/archive/2026-07-15-phase3-*-prescaffold/`
- Blueprints (to fill from Evidence exemplar): `docs/engineering/implementation-blueprint/01–06`
- Architecture source of truth: `docs/architecture/` (Books I–III) + `docs/adr/` (69 ADRs)
- Change status: `openspec/STATUS.md`
