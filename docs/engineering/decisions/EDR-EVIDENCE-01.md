# EDR-EVIDENCE-01 — Evidence Context Realization

Status: **Grilled — ready for issue breakdown** (9 decisions locked; one forward dependency)
Date: 2026-07-13
Author: architecture grilling session

## Purpose

Engineering Decision Record that turns the Evidence-context **ADR cluster** (the *why/what*) into
concrete, implementation-ready engineering decisions (the *how*) for the Phase-3 greenfield rebuild.
This is the first EDR and doubles as the **exemplar** that seeds the six implementation-blueprint
stubs.

## Realizes (ADR traceability)

- **Constitution:** CON-0001 (single ownership), CON-0007 (immutable evidence), CON-0011/0012/0013
  (bounded-context ownership / event collaboration / local transactions), CON-0016 (traceability)
- **Domain:** DOM-0027 (stable identity), DOM-0031 (aggregate roots = consistency boundary),
  DOM-0033 (events = completed facts)
- **Backend:** BCK-0037, 0038, 0039, 0040, 0041, 0042, 0043, 0046, 0047, 0048, 0049, 0052

## Grilled against (PoC reference slice)

`internal/adapter/trust`, `internal/adapter/parser`, `internal/adapter/store`,
`internal/usecase/ingestion`. **Ground rule: ADR wins; the PoC is reference only.**

---

## Decisions (resolved)

### D1 — Evidence terminates at "persist + event" (Q1)

The Evidence context owns exactly four steps: **trust-gate → parse (translate) → store → publish
`EvidenceRegistered`**, and stops. Correlation, enrichment, finding creation, and notification move
**downstream**, triggered by the event. The PoC's single synchronous `run()` pipeline
(`ingestion/service.go`) is split along context lines. Cross-context flow becomes **eventually
consistent** (ADR-CON-0012/0013), not a synchronous return value.

*Rejected:* keeping correlation in-context for latency (thicker boundary) — violates the directional
four-stage model (Book I §9.7).

### D2 — One generic `Evidence` record in an Evidence Registry, returns a stable ID (Q2)

Every upload becomes **one `Evidence` record**, labelled by **kind** (SBOM / VEX / ScannerReport / …),
filed **unchanged** in the **Evidence Registry** (Book III §3.3). Registration **returns the stable
Evidence ID to the caller immediately** (ADR-DOM-0027); analysis happens afterward, and the caller
uses that ID to track outcomes.

*Rejected:* per-source aggregate roots (one per format) — re-introduces technical-shape partitioning
Book III §3.2 forbids and triplicates intake logic.

### D3 — Deduplicate by the file's bytes alone (Q3)

Fingerprint = **SHA-256 of the raw bytes**. **Same bytes → return the same existing ID** (idempotent,
ADR-BCK-0049); **any difference → new evidence, new ID**, old one untouched (immutable, ADR-CON-0007).

*Rejected:* dedup by bytes + subject — a byte-identical file is the same observation regardless of
what it's pointed at.

### D4 — Store raw frozen + one canonical inventory; standards only (Q4)

Keep the **raw file frozen forever** (audit record) **and** translate it once, at the door, into **one
common in-house format** — a normalized **component inventory + dependency links** (scanner-reported
vulns are ignored per the PoC's CR-9; Themis re-correlates). **Accepted formats = CycloneDX and SPDX
(standards only).** **Trivy and other scanners are *producers* (provenance), not formats** — expected
to export a standard (`trivy … --format cyclonedx`). Non-standard uploads get a **helpful rejection**
(error-UX). The translator ("border ACL", ADR-BCK-0052) stays extensible so adding a genuine standard
later is one localized change.

*Rejected:* keeping a Trivy-native-JSON parser — unnecessary tool-specific dialect; Trivy exports
standards natively.

### D5 — Evidence references the subject software; it does not own the catalog (Q5)

The record carries a **reference** to the **Release** it describes and **validates that the Release
exists**, but **never creates or edits** the Product → Project → Release catalog. The **image digest is
recorded as evidence provenance**, not a modeled entity (refined by `EDR-KERNEL-01` D2). **Unknown
Release → reject** ("register the release first"). Single ownership (ADR-CON-0001), and it respects the
one-way flow (the catalog sits above all four stages).

*Resolved (was a forward dependency):* the catalog owner is the **Shared Kernel registry**, which owns
Product → Project → Release identity only (`EDR-KERNEL-01` D1/D2). Evidence's `SubjectRef` validates a
Release against it.

### D6 — Thin `EvidenceRegistered` event + official read lookup (Q6)

The event carries the **Evidence ID + key headers** (kind, subject reference, fingerprint) — **not** the
full inventory. Downstream fetches the canonical inventory through Evidence's **official read
API / read-model** (ADR-BCK-0047/0048), **never** by reading Evidence's tables directly (Book III §3.5).
Small, stable event contract (ADR-BCK-0046); immutability means a later fetch always returns identical
bytes.

*Rejected:* fat event carrying the whole inventory — large messages; the autonomy upside is real given
immutability but not worth the payload size.

### D7 — Transactional outbox; event published only after an atomic save (Q7)

Registration writes the **Evidence record + an outbox note in one all-or-nothing local transaction**
(ADR-BCK-0040/CON-0013/DOM-0031). A background sender then delivers un-sent notes and marks them done,
retrying on failure. Guarantee: **every stored evidence is announced exactly once; no announcement ever
exists for un-stored evidence** (ADR-BCK-0041). This is the transaction boundary — *evidence + outbox
note, nothing more*; correlation/enrichment run in separate transactions in separate stages.

**Concurrent duplicate uploads:** the byte-fingerprint uniqueness (D3) + **optimistic concurrency**
(ADR-BCK-0043) mean one insert wins and the rest resolve to the same existing ID — no duplicate, no
lock-up. This is a genuine gap vs. the PoC, which calls notify synchronously with no such guarantee.

*Rejected:* announce as a separate step after save — loses the announcement on a crash-in-between
(silent evidence loss).

### D8 — Read-only counter; immutable in production; dev-only purge (Q8)

Evidence exposes three use-case operations (ADR-BCK-0048): **Register** (upload → returns Evidence ID),
**GetEvidence** (facts: kind, subject reference, fingerprint, provenance, trust status, filed-at), and
**GetInventory** (the canonical component-list read view). A **List evidence by software/release** read
view is included for discovery/tracking. **No edit; no findings** (those are downstream). Under the hood
the repository loads/stores the **whole Evidence aggregate as one unit** (ADR-BCK-0042); the inventory
and list read views are **separate read paths** (ADR-BCK-0047) independent of aggregate storage — this
resolves the repository-shape question.

**Delete:** production upholds immutability (ADR-CON-0007) — **no production delete or retire**. A hard
**purge is a development/test-only affordance**, environment/build-gated to reset test data; it is
**removed/disabled in production** and sits explicitly outside the production Evidence contract.

*Rejected:* a production soft-delete/tombstone (the PoC's sbom-management) — conflicts with immutability;
the only real need (resetting test data) is a dev concern, so it is gated to dev, not shipped.

### D9 — Context-first, three-ring layout; same module (Q9)

The Evidence context is a self-contained tree `internal/evidence/{domain,app,adapters}` (ADR-BCK-0037;
Book III §3.2). Rings: **domain/** (pure — Evidence aggregate, invariants, canonical inventory,
`EvidenceRegistered` event; depends on nothing; ADR-BCK-0039); **app/** (use-case services
Register/GetEvidence/GetInventory/List + ports for store/parser/trust/outbox; ADR-BCK-0038);
**adapters/** (store [Postgres record + outbox + read views], parser [CycloneDX/SPDX ACL], trust, http).
Dependencies point **inward only**; **no cross-context imports** — contexts collaborate solely via events
and read APIs (D6; Book III §3.5), enforced by `go-cleanarch` + an architecture test. Lives in the **same
Go module** as new top-level context folders. This is **the reusable template** every future context
copies, and seeds the six blueprint stubs.

*Rejected:* technical-layer-first layout (the PoC's `domain/usecase/adapter` at the top) — Book III §3.2
mandates context-first. Separate module — unnecessary overhead now.

---

## Remaining dependency

- **Resolved — Shared Kernel ownership** of Product/Release identity (from D5): owned by the Shared Kernel
  registry (`EDR-KERNEL-01` D1/D2). Evidence's `SubjectRef` validates a **Release**; the image digest is
  evidence provenance. No open dependency remains.

## Traceability → issues

One issue per implementable decision; each cross-references its decision + ADR. Suggested delivery: an
OpenSpec change `openspec/changes/phase3-evidence/` with these as `tasks.md` groups.

| # | Issue | Realizes | Blueprint |
| --- | --- | --- | --- |
| EVID-01 | Scaffold `internal/evidence/{domain,app,adapters}`; wire `go-cleanarch` + architecture test (inward-only, no cross-context imports) | D9 · BCK-0037 | 01/02/03/04 |
| EVID-02 | `domain`: Evidence aggregate root — kind label, stable ID, byte-fingerprint identity, subject reference, provenance/trust value objects, immutability invariant (+ invariant unit tests) | D2·D3·D5 · CON-0007/DOM-0027/0031 | 04 |
| EVID-03 | `domain`: canonical component-inventory model + thin `EvidenceRegistered` event (ID + kind + subject ref + fingerprint) | D4·D6 · DOM-0033/BCK-0046 | 06 |
| EVID-04 | `adapters/parser`: CycloneDX + SPDX → canonical inventory (standards only); extensible registry; helpful rejection for unsupported (+ golden-file tests) | D4 · BCK-0052 | 02 |
| EVID-05 | `adapters/trust`: trust-gate — SHA-256 fingerprint, schema validation, signature/provenance capture | D2·D3 · CON-0016 | — |
| EVID-06 | `adapters/store`: Postgres Evidence table (unique fingerprint, raw+canonical, provenance, subject ref) + outbox table; aggregate-root load/store; idempotent insert returns existing ID on fingerprint clash (+ concurrent-duplicate integration test) | D2·D3·D7 · BCK-0042/0043/0049 | 05 |
| EVID-07 | Outbox relay: background sender delivers un-sent notes, marks done, retries on failure (exactly-once-eventually; crash/retry tests) | D7 · BCK-0041 | 06 |
| EVID-08 | `app`: `RegisterEvidence` use case — orchestrate trust→parse→store(+outbox) in one local transaction; return ID; reject unknown subject; idempotent replay | D1·D2·D3·D4·D5·D7 · BCK-0038/0040 | 05 |
| EVID-09 | `app`: read use cases + read views — GetEvidence (facts), GetInventory (parts-list), List-by-software (separate read paths) | D6·D8 · BCK-0047 | — |
| EVID-10 | `adapters/http`: REST counter — POST register (returns ID), GET by-id, GET inventory, GET list; error-UX envelope + helpful rejection messages | D8 · BCK-0048 | — |
| EVID-11 | Dev-only purge — environment/build-gated test-data reset; disabled in production (+ guard test) | D8 · CON-0007 | — |
| EVID-12 | `app`: `SubjectRef` validation port — validates a **Release** exists against the Shared Kernel registry (EDR-KERNEL-01 D1/D2); rejects unknown; image digest stored as provenance | D5 · CON-0001 | — |
| EVID-13 | Write the six blueprint stubs from this realized exemplar (`docs/engineering/implementation-blueprint/01–06`) | D9 | 01–06 |
