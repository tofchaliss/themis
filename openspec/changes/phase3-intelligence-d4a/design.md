# Design — phase3-intelligence-d4a

Source of truth: `docs/engineering/decisions/EDR-INTELLIGENCE-01.md` § Δ4a (D-Δ4a-1…6). This file is the
build-shape, not new decisions.

## Store (D-Δ4a-1) — new migrations in the existing `intelligence` DB

Four tables, `adapters/store/migrations/000003…` onward:

- `invocation_log` — captured invocations (correlation_id, capability, prompt_version, model, tier,
  assembled-context JSON [REDACTED on write], raw output, reason, decline_class, tokens, occurred_at).
  **Retention-capped** (a `THEMIS_INTELLIGENCE_LOG_RETENTION` sweep, like publication retention). Disposable.
- `golden_entries` — human-promoted, durable. A frozen (context, expected-outcome) pair + a case label + the
  source correlation_id. **Backed up.**
- `eval_reports` — one row per eval run: run id, timestamp, git/version fingerprint, and per-entry results;
  aggregates by `(capability, prompt_version, model)`. **Backed up.**
- `prompt_versions` — content-hash → version label per capability (attribution history).

The backup obligation (golden_entries + eval_reports) is documented in INSTALLATION.md; the vector index and
invocation_log stay disposable.

## Version stamp (D-Δ4a-3)

At boot the prompt renderer computes a content hash per capability template and upserts `prompt_versions`;
the resolved `prompt_version` is threaded into `Outcome` and stamped on every `invocation_log` and
`eval_reports` row. Prompts are unchanged `go:embed`. No serving from the DB.

## Capture + redaction (D-Δ4a-5)

The Gateway (or the HTTP telemetry seam that already logs invocations) writes each invocation to
`invocation_log` AFTER the existing redactor runs — the redacted prompt/context is what persists. A capture
failure is non-fatal (best-effort, like telemetry). Promotion is an operator action:
`cmd/intelligence-eval promote <correlation_id> --label "<case>"`.

## Eval command (D-Δ4a-6)

`cmd/intelligence-eval run` (or a `make eval-llm` target, `//go:build llm`-tagged like `e2e-llm`): loads
`golden_entries`, replays each frozen input through the current Gateway/provider (real model), scores
deterministically (grounding-verify the cited refs against the frozen context; schema-validate; classify the
decline), plus acceptance-outcome for `recommend_position` (joined from the golden entry's recorded
Governance decision, when present), writes an `eval_reports` row, prints a `(capability, prompt_version,
model)` pass-rate table. LIVE-ONLY. Needs `THEMIS_LLM_*` like e2e-llm; skips with a clear message if no
endpoint answers.

## What is NOT built (guardrails made concrete)

No DB-served prompts · no live traffic-split · no `models` table · no automated promotion gate · no
scheduled eval loop · no CI eval net · no human-labeling UI. Each is a rejected/deferred EDR decision, not an
omission.

## Architecture / gates

New `adapters/store` migrations + methods (store tier ≥ 80% coverage, migration up/down reversible). The eval
`cmd` is thin composition over existing Gateway seams (no new domain). `make check-ci` green; `vet-tags`
covers the new `llm`-tagged eval. No new third-party dependency, no cross-context import (the eval reads
Governance decisions via the existing read-API client seam, never its tables).
