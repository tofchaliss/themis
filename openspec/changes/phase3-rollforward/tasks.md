# Tasks — phase3-rollforward

No `specs/` deltas — archive with `openspec archive phase3-rollforward --skip-specs -y`.

## Group 1 — Domain rules (D3, D4)

- [x] 1.1 `domain/rollforward.go`: `RollForwardEligibility`, `JudgedPosition`,
  `RollForwardProposalID`. Tests: the level table including the CVE-2026-33006 scope-only
  fixture, retired and empty purls; judged vs rule's verdict vs policy.

## Group 2 — App pass (D1, D2, D5)

- [x] 2.1 `app/rollforward.go`: `RollForward.ForRelease` / `.Sweep`,
  `FindingService.RollForwardFinding`; Inferred proposal, deterministic id, latest judgement
  wins, project hop last and cached.
- [x] 2.2 Worker hook: `ReleaseEvaluationWorker.WithRollForward`, runs before publish-and-mark;
  a failure defers the row. Re-judge hook: `RangeRejudge.WithRollForward`, `RollForwardRaised`.
- [x] 2.3 Tests: proposes in-project judgement at component and artifact level; never across
  projects, from a rule's verdict, across packages, on a scope-only target, from the same
  release; idempotent; every failure surfaces; worker defers and recovers; sweep counts.

## Group 3 — Store, wiring, docs

- [x] 3.1 `store.UndecidedFindingsByRelease` + integration test.
- [x] 3.2 Wiring under the Registry seam; `rollforward_raised` in the governance log line.
- [x] 3.3 EDR-ROLLFORWARD-01; BACKLOG RF-1; CLAUDE.md invariant; INSTALLATION re-judge note.
- [ ] 3.4 VM: run the re-judge pass, read `rollforward_raised`, open one `rollforward:` proposal
  in the GUI and confirm the rationale names source release, version, decider and level.
