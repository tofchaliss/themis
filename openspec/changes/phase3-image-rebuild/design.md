# Design — phase3-image-rebuild

The design is `docs/engineering/decisions/EDR-REBUILD-01.md` (D1 to D46, owner choices 1 to 10).
This file only records how the steps map to the code.

- **R1** lives in Governance only. `domain/rebuild_policy.go` holds the record, the mode order
  (off < ask < auto, an unknown mode reads as off) and `EvaluateRebuild`, a pure function over
  candidates the caller supplies. `app/rebuild_policy.go` is the service and its store port.
  `adapters/store` keeps `rebuild_policies` (the policy in force, one row per scope) and
  `rebuild_policy_history` (every version), written in one transaction. The API is
  `/rebuild-policy` and `/rebuild-policy/history`.
- R1 evaluates nothing against a Release and sends nothing. The rule is not wired to a trigger
  until R2, so the running system behaves as before.
- **R1a** uses the same two tables for all three levels. `domain.ResolveRebuildPolicy` picks the
  policy in force and the mode ceiling; the app service reads the Release's Product through
  the existing Registry seam and fails closed without it. A removal is a history entry, and
  the version of a scope is counted from its history under an advisory lock per scope.
