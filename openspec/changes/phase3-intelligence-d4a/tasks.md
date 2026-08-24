# Tasks — phase3-intelligence-d4a · Δ4a (operational store + LLMOps replay harness)

> **Scope: Δ4a only** — the operational store + LLMOps replay harness, grounded in
> `docs/engineering/decisions/EDR-INTELLIGENCE-01.md` § Δ4a (D-Δ4a-1…6). Out of scope: Δ4b autonomy
> (engine/scheduler/push seam/pool), DB-served prompts, live A/B, model registry, automated promotion,
> scheduled eval, CI eval net, human-labeled datasets — each rejected/deferred in the EDR. No new
> third-party dependency. Each group ends by making the Themis gates (`make check-ci` + `vet-tags`) green.

## 1. Store — new migrations in the existing `intelligence` DB (D-Δ4a-1)

- [x] 1.1 Migrations `000003…`: `invocation_log` (capped), `golden_entries` (durable), `eval_reports`
  (durable), `prompt_versions`. Up/down reversible.
- [x] 1.2 Store methods: append-invocation, list-for-replay, promote-to-golden, list-golden, write-report,
  upsert-prompt-version. Register the package in the coverage tiers; store ≥ 80%.
- [x] 1.3 Retention sweep for `invocation_log` (`THEMIS_INTELLIGENCE_LOG_RETENTION`), mirroring the
  publication-retention pattern.
- [x] 1.4 INSTALLATION.md: the `intelligence` DB now holds NON-DISPOSABLE state (golden_entries,
  eval_reports) → backup obligation; invocation_log + vector index stay disposable.
- [x] 1.5 Gate.

## 2. Prompt version stamp (D-Δ4a-3)

- [x] 2.1 At boot, hash each `go:embed` capability template; upsert `prompt_versions`; resolve a
  `prompt_version` per capability.
- [x] 2.2 Thread `prompt_version` into `Outcome`; stamp it on invocation_log + eval rows + the existing
  telemetry line. Prompts stay in-code (no DB serving).
- [x] 2.3 Tests: hash stability, version resolution, stamp presence. Gate.

## 3. Redacted capture → human promotion (D-Δ4a-5)

- [x] 3.1 Write each invocation to `invocation_log` AFTER the redactor (redacted context/output persists);
  best-effort (a capture failure never fails the invocation).
- [x] 3.2 `cmd/intelligence-eval promote <correlation_id> --label` — copy a log entry into `golden_entries`
  with its frozen expected-outcome.
- [x] 3.3 Tests incl. a redaction assertion: a secret in the context never lands in `invocation_log`. Gate.

## 4. Eval command — offline, live-model, deterministic scoring (D-Δ4a-2, D-Δ4a-6)

- [x] 4.1 `cmd/intelligence-eval run` (`//go:build llm`; `make eval-llm`): replay `golden_entries` through the
  current Gateway/provider (real model), score grounding + schema + decline honesty; acceptance-outcome for
  `recommend_position` only. LIVE-ONLY; skip cleanly with no endpoint.
- [x] 4.2 Write an `eval_reports` row; print the `(capability, prompt_version, model)` pass-rate table.
- [x] 4.3 Scoring is deterministic and reuses the existing grounding validator + schema validator (no
  re-implementation). Information-capability score = groundedness/well-formedness, NOT quality (documented in
  the report header).
- [x] 4.4 `vet-tags` covers the new `llm`-tagged eval; a fake-provider unit test exercises the scoring logic
  without a live model (the SCORING is unit-tested; the live run is human-only). Gate.

## 5. Docs + honest limits (D-Δ4a-2/4/6)

- [x] 5.1 TESTING.md: how to run `make eval-llm`, promote a golden case, read the report — with the three
  honest limits stated plainly: (a) Information capabilities measure groundedness not quality; (b) promotion
  is human-gated, nothing blocks a worse model but attention; (c) the eval is run-it-yourself, no CI net.
- [x] 5.2 BACKLOG: close/annotate G-AI-2(c) tuning-half progress; note Δ4b still holds autonomy + the AI
  push seam (G-AI-1b) + the autonomous pool (G-AI-4).
- [x] 5.3 `docs/engineering/PHASE3-STATUS.md` resume block → Δ4a done, Δ4b next. Gate: full `make check-ci`.

## Notes

- **NO `specs/` deltas** (phase3 change; `openspec validate` reporting "no deltas" is expected; archive with
  `--skip-specs -y`).
- Δ4a adds one `cmd` and store tables; it touches NO capability behavior and NO authority — purely
  attribution + a replay harness over existing seams.
