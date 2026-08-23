# EDR-ENHANCE-T5 — Enhancement Tier 5: AI capability build-out (the R1 cluster)

**Status: PROPOSED (2026-08-21) — no implementation until the user confirms.**
The largest body of work on the board and the only tier about capability rather than correctness —
which is exactly why the backlog keeps it (as R1) in a class that never competes with T2. Standing
constraints carried unchanged into every item: **AI is advisory** (proposes, never decides),
Information vs Decision output classes govern the path (T7), "Gathering Is Not Knowing", and every
capability degrades to a deterministic answer.

## Scope

| Item | Tracking | What |
| --- | --- | --- |
| **AI-CMP-1** *(new, filed with this roadmap)* | ← IDEA-1 consumer 3 | `compare_releases@v1` — an **Information** capability narrating the deterministic comparison read (EDR-GOVERNANCE-01 D16): what the fix achieved, what it missed, what to do next. Cheapest capability on the list — its hard half shipped in v0.4.2, its grouping is a server-side read, and being Information-class nothing reaches Governance |
| **G-AI-3** | R1 | Delta-aware precedent ranking: weight retrieved precedent by the release-to-release delta (via the same comparison machinery), not component similarity alone |
| **G-AI-1** | R1 | On-demand fresh-CVE gathering: the AI (or a human) asks about a CVE the feeds have not ingested; the feeds gather it now, bounded, and the answer waits for real data instead of hallucinating |
| **G-AI-2(c)** | R1 | "Can't determine" as an improvement signal: classify declines (consumes AI-204-2's taxonomy) and surface the distribution — the eval loop's raw material |
| **G-AI-4** | R1 | Budget **enforcement** policy (the meter exists; sound only after AI-TEL-1): per-capability windows, degrade-then-refuse, operator-visible |
| **G-AI-5** | R1 | Data-classification / provider-clearance admission: which data classes may reach which model tier; local-only remains the default posture |
| **Δ4 — autonomy + LLMOps** | R1 / M4 | Scheduled autonomous triage sweeps (bulk advisory proposals over the top-N undecided; the authority line does not move) and the **model evaluation harness**: grow the grounding gate + `make e2e-llm` into a scored regression suite replaying decided Findings against model/prompt changes, tuning the router's escalation/economy tiers on measurements |

## Decisions to confirm before any capability code

1. **Entry point**: recommended **AI-CMP-1 → G-AI-3** — both stand on the D16 comparison read that
   just shipped, both are Information-class (worst failure = a human disagrees), and together they
   exercise the retrieval + grounding paths the rest of the tier needs hardened.
2. **AI-CMP-1 contract**: input = (baseline, candidate) release ids; grounding = the comparison
   read verbatim (the model may only cite rows it was given — the existing Grounding Verification
   gate applies); output = prose + the cited buckets; 204 semantics per AI-204-1/2.
3. **Δ4 sweeps need a trigger decision**: reactive-only stays the default; a sweep is opt-in,
   scheduled, budgeted (G-AI-4 first), and every proposal it raises is indistinguishable from an
   on-demand one downstream. Sequencing: **eval harness before autonomy** — measure the model
   before letting it run on a timer.
4. **G-AI-1 boundary**: gathering stays relevance-bounded (D5) — "fetch this CVE now" never becomes
   "mirror the feed"; the fetched result lands as ordinary Proposals at feed trust, not as answers.
5. Each item confirmed here still gets its own EDR-INTELLIGENCE-01 / THEMIS-AI-HARNESS realization
   entry before code — this tier document sequences; it does not pre-decide contracts.

## Delivery order

AI-CMP-1 → G-AI-3 → AI-204-2-dependent G-AI-2(c) → G-AI-4 (after AI-TEL-1, T4) → G-AI-1 → G-AI-5 →
Δ4 (eval harness, then autonomy). T4 items interleave as prerequisites where named.

## Impact

`internal/intelligence` (capability registry, engines, prompts, index), `internal/governance`
read-seam consumption, `api/intelligence.openapi.yaml` per capability (spec-first), TESTING.md +
`make e2e-llm` growth. Every addition is disable-able and budget-metered; nothing here changes who
decides.
