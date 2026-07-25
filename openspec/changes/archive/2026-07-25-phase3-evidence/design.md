# Design — phase3-evidence (Evidence bounded context)

## Source of truth

All engineering decisions (with rationale and rejected alternatives) live in
**`docs/engineering/decisions/EDR-EVIDENCE-01.md` (D1–D9)**. This document states the layout, import
rules, and quality gates only — it does not re-derive the decisions.

## Layout (D9 · ADR-BCK-0037; Book III §3.2)

Context-first, three rings, in the **same Go module** as new top-level context folders:

```text
internal/evidence/
├── domain/     RULES  — Evidence aggregate, invariants, canonical inventory, EvidenceRegistered event
├── app/        ACTIONS — Register/GetEvidence/GetInventory/List + ports (store, parser, trust, outbox,
│                         subject-ref)
└── adapters/   PLUMBING — store (Postgres record + outbox + read views), parser (CycloneDX/SPDX ACL),
                           trust, http (the REST counter)
```

## Import rules (ADR-BCK-0039/0038/0037; Book III §3.5)

- `domain/` imports **nothing** (pure core).
- `app/` imports `domain/` only.
- `adapters/` import `app/` and `domain/`.
- **No cross-context imports.** Evidence collaborates with other contexts **only** through published
  events and read APIs — never by importing them or sharing a database.
- Enforced by **`go-cleanarch` + depguard** and a dedicated **architecture test**.

## Persistence (D2 · D3 · D7)

- Evidence owns its tables (`evidence`, `evidence_outbox`) — no sharing (ADR-BCK-0042; Book III §3.5).
- **Aggregate-root-only** repository: the whole Evidence record loads/stores as one unit.
- **Identity/dedup** by SHA-256 of raw bytes; a byte-identical re-upload returns the same existing ID
  (ADR-BCK-0049) via unique constraint + optimistic concurrency (ADR-BCK-0043).
- **Transactional outbox**: the Evidence record and the `EvidenceRegistered` note are written in **one
  local transaction** (ADR-BCK-0040/0041; ADR-CON-0013); a background relay delivers the note. The relay
  is the reusable **Event Infrastructure (M5)** component seeded here (EDR-KERNEL-01 D4).

## Collaboration (D1 · D6)

- Registration terminates at **persist + publish `EvidenceRegistered`**. Correlation/enrichment/notify
  run downstream, triggered by the event.
- The event is **thin** (id, kind, subject ref, fingerprint); downstream fetches the canonical inventory
  through Evidence's **read API** `GetInventory` (ADR-BCK-0047/0048) — the seam Knowledge consumes
  (EDR-KNOWLEDGE-01 D4).

## Stack

Canonical stack + rationale: **`docs/engineering/STACK.md`** (read before implementing). Evidence-specific:
**pgx** + **golang-migrate** (own `evidence` + `evidence_outbox` tables), **`jsonschema/v6`** for the
SBOM/VEX trust-gate, a CycloneDX/SPDX **parser ACL** (standards only), **chi** + **oapi-codegen** for the
REST counter, a **Postgres-outbox relay** (the reusable M5 seed), **OpenTelemetry** + **zap**.

## Quality gates

The six Themis gates (`make check`) — build, unit tests, coverage, dead-code, integration tests,
clean-architecture — **extended to cover `internal/evidence/`**. Markdown artifacts pass
`markdownlint-cli2`.
