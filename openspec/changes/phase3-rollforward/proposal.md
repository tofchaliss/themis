# Proposal — phase3-rollforward (EDR-ROLLFORWARD-01)

## Why

The Phase 1 audit of auto-assessment and roll-forward (2026-10-14) found that Themis had no
deterministic road for the one thing VAMS does by hand and by copy: "this CVE was decided on the
previous release of this project; carry that decision to the new release". The only cross-release
reuse was the AI sweep — semantic, budget-gated, off by default — and its same-CVE road was dead
code until AI-RF-1. A new release of a project therefore re-opened every Finding its predecessor
had already judged, with nothing in the queue saying so.

## What changes

- **Governance** raises a system proposal `rollforward:<target>:<source>` on an undecided Finding
  when a sibling Finding on the same Faultline, in a release of the same project, holds a judged
  Position and the two Findings are alike at artifact or component level. The proposal rests on
  Inferred evidence; a person decides.
- The pass runs on the **release-evaluation worker** after a release's project is resolved, and
  in the **one-time re-judge pass** for existing Findings (`rollforward_raised` in its log line).
- A new store read, `UndecidedFindingsByRelease`.

## What does NOT change

- The authority line: no Position is copied, no policy can accept the proposal (Inferred).
- The AI road (`recommend_position`, Δ4b sweep) and the precedent index.
- The fixture CVE-2026-33006: a scope-only target gets no proposal.
- Event shapes, API contracts, schemas: none touched.

## Decision record

EDR-ROLLFORWARD-01 D1–D6. No `specs/` deltas; archive with `--skip-specs`.
