# EDR-ENHANCE-T1 — Enhancement Tier 1: basic polish

**Status: PROPOSED (2026-08-21) — no implementation until the user confirms.**
Part of the tiered enhancement roadmap (BACKLOG "Tiered enhancement roadmap"); companion tiers
T2–T5 in EDR-ENHANCE-T2…T5. This tier is deliberately the smallest-risk work on the board: each
item is contained, has a measured or filed defect behind it, and none changes an API surface or a
domain model.

## Scope (existing backlog IDs — this EDR adds no new items)

| Item | What | Why now |
| --- | --- | --- |
| **GUI-12** | Derive the browser translator's `observed_at` from the raw report's own `CreatedAt` (fallback: omit and let the server stamp), so byte-identical raw re-uploads dedup again | MEASURED live 2026-08-17: the same Trivy file re-uploaded produced a second scan row |
| **GUI-10** | Unit-test harness for the D16 in-browser translators | The only live-exercised-only code path in the GUI; blocked on a harness decision (below) |
| **GUI-4** ✅ | Per-distro feed-health rows (`osv/alpine`, `osv/rocky`, …) | ✅ SHIPPED 2026-08-13 (PR #95) — closed before this tier was filed; marker added 2026-08-27 |
| **KN-SCAN-3** | Canonicalize scanner-report component ecosystems in code (tool vocabulary → purl types) | Today the mapping lives in the recipe + one translator; a second tool re-implements it |
| **(docs)** | Record the GUI's vanilla-JS-no-framework choice as an explicit decision (one paragraph, EDR-GUI-01 or STACK.md) | The rationale exists but only implicitly across D1/D7/D8 |

## Decisions to confirm before code

1. **GUI-12 timestamp source**: report `CreatedAt` (deterministic bytes; dedup works; honest
   observation time) vs omit client-side and let Evidence stamp ingestion. Recommended:
   **report `CreatedAt` with server-stamp fallback** — it is the time the tool actually observed.
   *(✅ SHIPPED 2026-08-28 — with one correction found at implementation: the server-stamp
   fallback does not exist on the wire (the scanner ACL rejects a blank `observed_at`), so the
   no-CreatedAt fallback keeps the fresh stamp and SAYS SO in the file note instead.)*
2. **GUI-10 harness shape**: a node-based dev-dependency test runner is a build change ("Must ask",
   already flagged in the backlog) vs porting translator tests to Go via a JS engine. Recommended:
   **defer the toolchain; run translator functions under `node --test` invoked from a Makefile
   target that skips when node is absent** — no new dependency, the existing D7 gate already
   assumes node on dev machines.
3. **GUI-4 tier semantics**: per-distro rows stay informational tier (a quiet distro never reads as
   degraded) — carried over from EDR-KNOWLEDGE-01; no new decision, just confirmation. *(Moot —
   GUI-4 shipped 2026-08-13 in PR #95 with exactly these semantics.)*

## Delivery order

GUI-12 → KN-SCAN-3 → ~~GUI-4~~ (already shipped) → GUI-10 → docs paragraph. Each lands as its own
branch + gate; no sequencing dependencies between them.

## Impact

`cmd/dashboard/static/app.js`, `internal/knowledge/adapters/*` (scanner ACL + feed-health store/read),
`api/knowledge.openapi.yaml` (feeds response, additive), Makefile (GUI-10 only), docs. No migrations,
no event-contract changes.
