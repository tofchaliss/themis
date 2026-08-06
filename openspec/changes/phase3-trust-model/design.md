# Design — phase3-trust-model (evidence trust, deterministic inference, capability surface)

## Source of truth

All engineering decisions (rationale + rejected alternatives) live in
**`docs/engineering/decisions/EDR-TRUST-01.md` (T1–T12, ACCEPTED 2026-08-06)**, with realization detail in
**Book III Ch 16**, vocabulary in **Book II Ch 2 §2.7 + Domain Invariant 4**, and the AI contract in
**Book IV §2.1–2.3 + Principles 10–17**. This document states layout, import rules, seams, migration order
and gates only.

## Shape of this change

Unlike every prior `phase3-*` change, this one is **cross-context**: Knowledge, Governance and Intelligence
move together. The trust model is precisely the horizontal that per-context EDRs left ownerless. It still
adds **no new bounded context and no new deployable** (T11).

## Layout

```text
internal/kernel/value/
└── trust.go            TrustClass value object (Observed < Asserted < Inferred) + monotonic Max();
                        pure, stdlib-only — it is shared vocabulary, so it belongs to the kernel

internal/knowledge/
├── domain/             Proposal gains a derived TrustClass (from source); reconciliation propagates it
└── adapters/feed/      the source→class registry: each feed declares whether its output is reproducible
                        (Observed) or declared (Asserted)

internal/governance/
├── domain/             constitutional check (pure, non-configurable) evaluated BEFORE PolicyRule;
│                       Reservation derived from PositionInputs — no new lifecycle state
├── app/                deterministic inference over the evidence Governance owns (the existing
│                       reactToApplicability pattern, joined by the relocated version-range rule)
└── adapters/           projection endpoints (Domain Projections); read models surface reservations

internal/intelligence/
├── domain/             Selection{Type, IDs} + Capability{SelectionType, Min, Max, OutputClass};
│                       the version-range Rule is REMOVED (moves to Governance)
├── app/                Invoke(capabilityID, Selection, …); AssembleContext DELETED; shaping bounded by
│                       the four rules; Grounding Verification anchors to the received Domain Projection
└── adapters/readapi/   consumes Domain Projections; no fact-gathering
```

## Import rules (unchanged; ADR-BCK-0037/0038/0039)

- `domain/` imports stdlib + kernel; `app/` imports `domain/`; `adapters/` import `app/` + `domain/`.
- **No cross-context imports.** `TrustClass` lives in the **kernel** precisely so three contexts may speak it
  without importing each other.
- `go-cleanarch` + depguard + `tests/architecture` gates are extended, not relaxed.

## Cross-context seams

| Seam | Change |
| --- | --- |
| Knowledge → Governance | `component_matched` / `faultline_enriched` carry the reconciled trust class. Where a payload must change, mint `.v2.schema.json` + a new `schema_ref` — **never edit a frozen v1** |
| Governance → Intelligence | Governance serves **Domain Projections**; Intelligence's `readapi` consumes them and gathers nothing |
| Intelligence → Governance | the returned Decision Proposal is **Business-Verified** against current truth before it is recorded |

## Trust classification (T2)

Classification is a **per-source mapping**, reviewable in one place:

| Source | Class | Why |
| --- | --- | --- |
| SBOM parse (Evidence) | Observed | rescan the artifact, same answer |
| OSV / NVD ranges, EPSS, KEV, ExploitDB | Observed | public records, independently published |
| Red Hat / CSAF `not_affected` | **Asserted** | a judgment nothing can re-run — not a reliability claim |
| Hand-entered estate / platform metadata | **Asserted** | a declaration |
| Any Intelligence capability | **Inferred** | non-deterministic |

**Self-assertion is not observation:** a claim our own operators type is Asserted; the same claim backed by a
signed artifact Themis holds becomes Observed.

## Migration order (answers `EDR-TRUST-01` open question 2)

`recommend_position` must stay **behaviourally identical throughout**. The ordering that guarantees it:

1. Trust vocabulary and propagation land first — **no behaviour change**, pure addition.
2. The constitutional stage lands **before** any producer-identity branch is removed, so the `Inferred` bar
   is never momentarily absent.
3. The version-range rule is **added to Governance and proven equivalent** — same verdict on the same inputs,
   including the reconciled backport-aware range — **before** it is removed from Intelligence. Never the
   reverse: a window with neither is a window where a deterministic verdict silently disappears.
4. Domain Projections are **served before** the runtime stops gathering.
5. `Selection` accepts the deprecated `finding_id` alias for one release, so Governance's client keeps
   working while it migrates.

## Precision requirement (carried from T5)

The relocated version-range rule **must evaluate the reconciled, backport-aware range**, not a feed's
query-time filter. A distro backport — upstream flags the version, the distribution's build is not vulnerable
— is exactly the case the reconciled view catches. Getting this wrong produces silent, wrong `not_affected`
verdicts: the most dangerous defect class in this system.

## Stack

No new dependencies. `TrustClass` is stdlib-only. Projections reuse the existing pgx read path and the
`ReleasePosture` pattern. Schema evolution reuses `golang-migrate` + the existing `.vN.schema.json` +
`schema_ref` mechanism (`STACK.md`).

## Quality gates

Every task group ends green on **`make check-ci`** (build · test · lint · clean-arch · arch-test ·
coverage-greenfield · deadcode). Tier reminders that bite here: `domain`/`app` are **100%** — `TrustClass`,
the constitutional check, `Selection` and the reservation derivation each need complete branch coverage; a
**new package must be registered in `scripts/check-coverage.sh`** or coverage hard-fails. Behavioural parity
is proven by the existing `adapters/wiring/demo_e2e_test.go` and `adapters/http/llm_e2e_test.go` staying
green **unchanged in behaviour**, plus `make e2e-pipeline`.
