# Proposal — phase3-knowledge (Knowledge / Faultline bounded context)

## Why

**Knowledge** is the second context in the Phase-3 pipeline
(**Evidence → Knowledge → Governance → Communication**). It owns the enterprise's understanding of
security issues — the **Faultline** — reconciled from many source **Proposals** into an authoritative
enterprise view, and it correlates registered releases against that knowledge. Grounded in
**`docs/engineering/decisions/EDR-KNOWLEDGE-01.md`** (D1–D12). Ground rule: **ADR wins; the `internal/`
PoC is reference only.**

## What

Implement the Knowledge context:

- a **Faultline** aggregate — one enterprise knowledge card per canonical CVE, with its own internal
  identity (CVE is an alias/binding key), an append-only list of source **Proposals**, a materialized
  **enterprise view**, and a forward-only **lifecycle** ladder (Created → Enriched → Correlated → Mature →
  Superseded);
- one **ACL per feed** (NVD / OSV / Red Hat / EPSS / KEV / ExploitDB / vendor VEX) translating each into a
  common **Proposal** envelope, typed by kind (`vuln-facts` / `exploit-signal` / `applicability`);
- a fixed, explainable, source-agnostic **reconciliation/precedence rule** (distro-authoritative else NVD;
  AI/humans carry no special authority);
- **correlation** — react to Evidence's `EvidenceRegistered(SBOM)`, read the inventory via `GetInventory`,
  match components → Faultlines, and emit **`ComponentMatched`** (→ Governance creates a Finding);
- **lazy, relevance-bounded** card creation (SBOM-time OSV query-by-package + scheduled NVD watch);
- thin completed-fact events (`FaultlineCreated/Enriched/Matured/Superseded`, `ComponentMatched`) on
  enterprise-view change, via the shared transactional outbox;
- read side — `GetFaultline` (view + provenance) + disposable projections.

Full decision list with rationale: **EDR-KNOWLEDGE-01 (D1–D12)**.

## Non-goals (downstream / deferred)

- **Findings, Enterprise Positions, release posture** — owned by **Governance**, triggered by
  `ComponentMatched` / `FaultlineEnriched`. Not here.
- **Publication (VEX / advisories / notifications)** — owned by **Communication**. Not here.
- **AI Proposal ranking / special authority** — AI is just another Proposal source (CON-0002); its ranking
  is deferred to **EDR-INTELLIGENCE-01** (M4).
- **Full feed mirroring** — cards are created lazily, bounded by relevance, never a mirror of the whole CVE
  universe (D5).
- **The existing `internal/` PoC tree** stays as legacy reference and is **not modified**.

## Realizes (ADRs / EDR)

DOM-0020, DOM-0021, CON-0002, CON-0003, CON-0008, DOM-0026, DOM-0030, DOM-0031, DOM-0033, BCK-0041,
BCK-0042, BCK-0043, BCK-0044, BCK-0045, BCK-0047, BCK-0050, BCK-0052 — via **EDR-KNOWLEDGE-01**.
