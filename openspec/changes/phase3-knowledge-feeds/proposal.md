# Proposal — phase3-knowledge-feeds (Knowledge feed layer: real clients + CVSS 4.0 + tiers + scanner reports)

## Why

**Knowledge** (M7, `phase3-knowledge`) shipped its Faultline aggregate, feed ACLs, and reconciliation
**gated and complete** — but with the **feed-fetch clients as fakeable ports** (deferred, `PHASE3-BACKLOG.md`
§C) and two source-handling paths left open in the EDR. A **feed end-to-end verification** of the running
v0.3.x monolith (`docs/current-changes/FEED-E2E-VERIFICATION.md`, 2026-07-23) exercised the same feed surface
and surfaced concrete gaps the go-forward Knowledge layer must not repeat. This change makes the Knowledge
feed layer **production-real** and closes those gaps.

Ground rule: **ADR/EDR wins; the `internal/` PoC is reference only.** The v0.3.x feed defects it exposed —
**D-NVD-2** (CVSS 4.0) and **D-FEED-2** (source tiers), in `docs/current-changes/project-backlog.md` — are
tracked separately and **not** fixed here; this change is their **Phase-3 realization**.

## What

1. **Real feed-fetch HTTP clients** behind the existing `PackageVulnSource` / `ChangedVulnSource` ports
   (`internal/knowledge/adapters/feed`): OSV **query-by-package** + NVD **modified-since** watch. The M7 feed
   ACLs already translate the dialects — this delivers the fetch adapters (`PHASE3-BACKLOG.md` §C).
2. **CVSS v4.0** in the `vuln-facts` ACL + `Reconcile` (go-forward **D-NVD-2**): parse NVD `cvssMetricV40`
   and OSV `CVSS:4.0` vectors; headline-severity precedence **`v3.1 → v3.0 → v4.0 → v2`**, preferring
   **Primary** over **Secondary** — so a CVE scored only under v4.0 is no longer `unknown` / `risk 0`.
3. **Source-tier taxonomy** on the feed-ACL registry (go-forward **D-FEED-2**): each feed carries a **tier**
   (`openspec/intel-source-tiers.md`) driving **tier-aware** feed health + staleness (tier 1 → stale +
   escalate; tier 3 → informational), instead of treating every feed identically.
4. **Scanner reports as source Proposals** (EDR-KNOWLEDGE-01 **D5/D6**, previously *deferred*): a
   `scanner-report` Evidence kind translated by a **new feed ACL** into `vuln-facts` Proposals, reconciled by
   the same precedence rule — **advisory, never authoritative** (CON-0002). Evidence still ignores a scan
   report's verdicts at the door (EDR-EVIDENCE-01 D4); honoring them is a Knowledge **Proposal**, not truth.

Each item is **additive** behind the seams M7 already built (the feed ACL registry, `Reconcile`, the
discovery/watch ports) — no aggregate rewrite.

## Non-goals (deferred / out of scope)

- **The v0.3.x monolith fixes** — D-NVD-2 / D-FEED-2 stay v0.3.x backlog defects; this is the Phase-3
  Knowledge realization only.
- **The M5 event bus** — unchanged; feeds/relays keep the current logging stand-in.
- **Governance / Communication changes** — scanner-derived matches reach Findings via the existing
  `ComponentMatched` seam; no new downstream contract.
- **Scanner-report authority** — always advisory (CON-0002 / CON-0015); a scanner never sets truth.
- **The existing `internal/` PoC + its Trivy-native parser** — reference only; Phase-3 stays standards-only
  (CycloneDX / SPDX) per EDR-EVIDENCE-01 D4.

## Realizes (ADRs / EDR)

EDR-KNOWLEDGE-01 **D5/D6** (deferred feed-fetch + scanner-report Proposals), EDR-EVIDENCE-01 **D4** (scanner =
producer; standards-only), BCK-0052 (one ACL per feed), BCK-0051 (observability / feed tiers), CON-0002 /
CON-0003 (Proposal before truth; explainability). Closes the go-forward equivalents of **D-NVD-2** and
**D-FEED-2**.
