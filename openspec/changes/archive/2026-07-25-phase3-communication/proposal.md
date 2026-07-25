# Proposal — phase3-communication (Communication bounded context)

## Why

**Communication** is the terminal context in the pipeline
(Evidence → Knowledge → Governance → Communication). It **materializes** Governance's authoritative
**Enterprise Positions** into audience-specific artifacts and publishes them — it **never establishes,
modifies, or reinterprets** enterprise truth (CON-0010, DOM-0025). Grounded in
**`docs/engineering/decisions/EDR-COMMUNICATION-01.md`** (D1–D12). Ground rule: **ADR wins; the
`internal/` PoC is reference only.**

## What

Implement the Communication context:

- a first-class immutable **Publication** record — permanent lineage metadata (Position → Finding →
  Faultline → Evidence) + a **capped, regenerable payload** (CON-0016);
- **deterministic materialization** of a Position into **four artifact types** — VEX document, security
  advisory, customer notification, audit report — under a hard **stance-equality invariant** (presentation
  may vary, the conclusion never; CON-0010 / DOM-0025);
- an extensible **serializer registry**, standards-first: VEX (CycloneDX / OpenVEX), advisory (CSAF +
  human-readable), audit report (structured), notification (channel-native);
- the **inbound seam**: subscribe to Governance's `PositionEstablished` / `PositionRevised`, fetch via the
  read API, consume **Positions only**, record lineage as references;
- **human-triggered** artifact creation (no automation for now — CON-0015); revision by
  **append-and-supersede**;
- **channel-per-artifact delivery** via the shared transactional outbox (exactly-once; routing / digest /
  redaction reused from the PoC `notify`);
- **terminal audit events** (`Publication*`), never fed upstream; read side (`GetPublication` /
  `ListPublications`) + projections (publishable-positions queue, release posture) + non-recording preview.

Full decision list with rationale: **EDR-COMMUNICATION-01 (D1–D12)**.

## Non-goals (other contexts / deferred)

- **Establishing / changing decisions** — owned by **Governance**; Communication only materializes an
  already-authoritative Position (CON-0010).
- **Delegated auto-publish** — deferred; for now every artifact is created on an explicit **human trigger**
  (CON-0015). The auto-publish policy path is designed for but not enabled.
- **Executive summary + other audiences** — out of current scope; the serializer/materializer set is
  extensible.
- **The existing `internal/` PoC tree** stays as legacy reference and is **not modified**.

## Realizes (ADRs / EDR)

CON-0010, DOM-0025, CON-0001, CON-0002, CON-0003, CON-0012, CON-0015, CON-0016, DOM-0031, DOM-0033,
BCK-0037, BCK-0041, BCK-0042, BCK-0043, BCK-0044, BCK-0045, BCK-0047, BCK-0050, BCK-0052 — via
**EDR-COMMUNICATION-01**.
