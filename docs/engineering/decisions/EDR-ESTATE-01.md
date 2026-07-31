# EDR-ESTATE-01 — Enterprise Estate Graph & Blast-Radius Multiplier (parity C1/C2/C6)

Status: **Accepted — design confirmed 2026-07-31** (context placement decided by use-case analysis; see below)
Date: 2026-07-31
Author: parity-closure session (gap cluster C1/C2/C6)

## Purpose

Engineering Decision Record for the **enterprise estate graph** (Product→Microservice→Deployment→Customer)
and the **blast-radius multiplier** it powers — parity gaps **C1** (no org asset graph), **C2** (no per-Finding
blast multiplier), and **C6** (Knowledge's base score never reaches Governance). Today two Findings for the
*same* CVE score identically even when one sits in a throwaway dev tool and the other in a service deployed to
40 customers. This EDR restores the monolith's blast-radius risk model to the greenfield.

Ground rule: **ADR wins; the PoC (`internal/{domain,usecase,adapter,infrastructure}`) is reference only.** The
monolith's `adapter/assetgraph` + `domain/risk_phase2a.go` are the behavioural reference.

## Why this is a NEW decision (and how the home was chosen)

No ADR or EDR models an asset/estate graph; the greenfield has **zero** customer/microservice/deployment
concepts. The only governing ADR is **CON-0011 (Bounded Contexts Are the Unit of Architectural Ownership)** —
so this capability must get a context home, and that choice was made by **following the consumption**, not
intuition:

| Use case | Consumer | R/W | When |
| --- | --- | --- | --- |
| Blast multiplier on a Finding's priority (C2) | **Governance** | read | every finding / re-score |
| "Exposure for CVE-X?" blast-radius query | **Governance** | read | on-demand |
| Notify-routing ("who owns the service?") | Communication | read | **deferred (D2)** |
| Per-customer exposure report | Communication | read | deferred |
| Populate/maintain the topology | ops / CMDB / operator | **write** | as deployments change |
| Correlation / SBOM intake / release identity | Knowledge / Evidence / Registry | — | **never touch it** |

**Findings:** Governance is the dominant *and only near-term* reader; **no pipeline context writes the graph**
(its source of truth is external — ops/CMDB). Ownership follows *lifecycle/source-of-truth*, not read
frequency: Governance reads it constantly but does not *author* it, so it must not *own* it (that would be
storing topology it has no authority over). The graph is **supporting structural facts** — exactly Registry's
shape (Product→Project→Release: structural identity, read by the pipeline, never a pipeline stage). Hence the
placement below.

## Realizes (ADR traceability)

- **CON-0011** — the estate is owned by one context (Registry now; extractable to a dedicated `Estate` context
  later — D1).
- **ADR-BCK-0052** (external systems isolated through ACLs) — the graph's data comes from outside; population
  is an ingest concern (CRUD now, CMDB-sync ACL later — D3).
- **ADR-CON-0015 / ADR-INT-0066** (human authority; AI advises) — the multiplier is a deterministic policy on
  the Finding score, not an AI output.
- **Precedent:** the read-API client seam (Knowledge→Evidence, Communication→Governance) — Governance reads
  blast-radius from Registry the same way (D7); the transactional-outbox event carrying facts across contexts
  (C6, D6).

---

## Decisions

### D1 — The estate graph is a supporting-facts subdomain, realized in Registry now

Registry gains the estate entities alongside Product→Project→Release. This is chosen over (a) a new context
(unjustified until a *second* consumer — Communication routing — or a real CMDB sync makes it a first-class
subdomain) and (b) Governance ownership (rejected — Governance would own topology it doesn't author).
**Extraction path:** keep the estate as its own aggregate/module + its own migration + its own read-API seam,
so it lifts into a standalone `Estate` context later without a rewrite. The one accepted cost: Registry then
holds two ingestion sources (release identity from CI, estate topology from ops) — tolerable because both are
structural facts hanging off Product.

### D2 — Estate model: Product → Microservice → Deployment → Customer

Ported from the monolith's `domain/asset_graph.go`: a Microservice belongs to a Product; a Deployment places a
Microservice into an environment for a Customer; a Customer is the impact unit. Edges are explicit; the graph
is queried by traversal (D4). Release↔Microservice is the join that turns "this release has a Faultline" into
"these customers are exposed."

### D3 — Population via CRUD (system-of-record) now; CMDB-sync ACL later

Phase 1 exposes a spec-first CRUD API to register microservices / deployments / customers (scriptable, like
the monolith's `POST /products/{id}/microservices` etc.). A CMDB / service-catalog **sync ACL** (ADR-BCK-0052)
is the go-forward population path and a tracked follow-up; the read API (D4) is identical either way.

### D4 — Blast-radius = bounded unique-customer traversal

Registry serves a read API: given a **release** (or product), traverse Product→Microservice→Deployment→Customer
to the set of **unique customers reached**, returning the count. Traversal depth is bounded (ported:
`BlastRadiusTraversalDepth = 7`) so a cyclic/deep graph can never run away.

### D5 — The multiplier lives in Governance, applied to the Finding — the Faultline stays CVE-intrinsic

Governance computes `finding_priority = base_score × blast_multiplier`, preserving the C3 rule that the
Faultline score is CVE-intrinsic (identical everywhere). The multiplier is the monolith formula, ported
verbatim: **1.0–2.0×, +0.1 per unique customer beyond the first, capped at 10 customers**
(`ComputeBlastRadiusScore`). One customer or none ⇒ 1.0× (no-op), so an unpopulated graph changes nothing.

### D6 — C6 prerequisite: thread the Faultline base score to Governance

C2 cannot multiply a score Governance doesn't have. Today the `FaultlineEnriched` seam carries
`severity/KEV/exploit` but **not** Knowledge's computed 0–100 score. C6 adds the base score to that event's
payload and to Governance's Finding projection, so Governance has a number to multiply. **C6 ships first**, and
has standalone value (Governance can surface each Finding's base score even before the multiplier lands).

### D7 — Governance reads blast-radius via a read-API client seam

Governance does **not** import Registry. It reads blast-radius over HTTP through a small client seam
(mirroring `knowledge/adapters/evidence`), so the estate can later move to its own context behind the same
seam with no Governance change. When Registry is unreachable or the graph is empty, the multiplier degrades to
1.0 (fail-safe — a missing estate never inflates or blocks a score).

### D8 — Phasing

**Phase 1 (this EDR):** the estate model + CRUD population + the blast-radius read API (Registry) + C6 + the
multiplier on Finding priority (Governance). **Deferred to the D2 notification cluster:** team routing,
notify-on-high-blast, per-customer exposure reports.

## Not in scope (explicit non-goals)

Team/on-call routing and notifications (D2 cluster); CMDB/service-catalog sync (a follow-up ACL — CRUD is the
phase-1 population path); environment- or criticality-weighting of the multiplier (unique-customer count only,
per the monolith); a standalone `Estate` context (deferred until a second consumer justifies it).

## Implementation plan (phased PRs; `make check-ci` green each)

1. **C6** — add the base score to the `FaultlineEnriched` event payload (Knowledge) + Governance's inbound
   consumer + Finding projection. Small; standalone value. **First.**
2. **C1** — Registry estate: domain entities + edges, store + migration, spec-first CRUD API, and the
   bounded traversal + `GET .../blast-radius` (unique-customer count) read API.
3. **C2** — Governance: a Registry blast-radius client seam (D7) + apply `base × ComputeBlastRadiusScore` to
   the Finding's priority; expose the effective priority. Fail-safe to 1.0× when the estate is absent.
