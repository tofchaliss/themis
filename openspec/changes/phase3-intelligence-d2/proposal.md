# Proposal — phase3-intelligence-d2 (Intelligence Gateway · Δ2: typed dispatch + Rule Engine + admission spine)

## Why

Δ1 shipped the Intelligence Gateway **walking skeleton**: one reactive capability (`recommend_position`)
end-to-end, pure Go, disable-able, on every real harness seam — but with a single LLM engine, **no
dispatcher**, and **no admission gate**. Δ2 is the next **additive** step toward the harness destination
(`docs/engineering/THEMIS-AI-HARNESS.md`): it makes the Gateway **typed and multi-engine** and adds the
**pre-invocation admission spine** — **without rewriting any Δ1 seam**.

Grounded in **`docs/engineering/decisions/EDR-INTELLIGENCE-01.md` — Revision 3** (the Δ2 concrete cut,
2026-07-24), which is the source of truth for every decision, rejected alternative, and **grounded component
choice (C1–C7)** referenced below. The authority spine (D1/D2/D7/D8/D10) is unchanged.

## What changes

- `recommend_position` becomes a **two-step `[Rule → LLM]` execution plan**, exercising a real **Engine
  Dispatcher**:
  - **Rule step — version-range applicability** (deterministic, no provider): provably-out-of-range → certain
    `not_affected` and the LLM never runs; certain in **one direction only** (never auto-`affected`); unknown
    ecosystem / no range → fall through. **Deterministic-first: the LLM runs only when there is no clear
    answer.**
  - **LLM step** — unchanged from Δ1, now the fallback.
- **Honest fourth outcome** `insufficient` ("can't determine — no recommendation") as a first-class,
  non-error result.
- **Richer grounding** — pull our own past **Enterprise Positions on the same CVE** (labeled,
  context-not-instruction) when the plan reaches the LLM step, via a Governance read-API extension plus the
  existing read-API-client seam.
- **Provenance stamp** — every result records **which step decided** (`rule:not_affected` / `llm:<stance>` /
  `insufficient`): the testability hook and the G-AI-2 metric source.
- **Admission spine (one pre-invocation gate):**
  - **Budget** — meter (OTel metrics) + runaway guard (timeout + input-size cap). **Measure now**; enforcement
    deferred (local model = free).
  - **Security/privacy** — authorize caller + scrub secrets/PII (Redactor) + **hard local-only**. Full
    classification/clearance deferred.

## Out of scope (later deltas / logged gaps in `PHASE3-BACKLOG.md` §C)

- **G-AI-1** on-demand fresh-CVE gathering (AI asks, feeds gather — a crawler = a new feed) — Δ3+.
- **G-AI-2** can't-determine as a metric / model-escalation / eval signal — Δ3–Δ4.
- **G-AI-3** rank precedent by release-delta — Δ3+.
- **G-AI-4** budget **enforcement** policy (4 scopes, degrade-not-fail) — Δ3+.
- **G-AI-5** data-classification → provider-clearance admission — Δ3+ (cloud providers).
- Python engine + RAG/pgvector (Δ3); autonomous engine + push seam + LLMOps (Δ4).

## Ground rules

ADR/EDR wins; the legacy `internal/` PoC is frozen reference — the version engine is **ported by design,
never imported** (C2). System of record = this change's `tasks.md`. Every software-component choice is
grounded (rule basis / named alternatives / why-better) in EDR Rev 3's **Component & Technology Decisions**
table (C1–C7). Δ2 adds **no new third-party dependency**.
