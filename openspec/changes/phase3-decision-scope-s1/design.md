# Design — phase3-decision-scope-s1

- **The Position row is the queue.** The EDR sketched a `scoped_decisions` table; S1 instead
  stores `scope` and `scope_applied_at` on `finding_positions`, written in the accept's own
  transaction. A scoped Position with `scope_applied_at IS NULL` is pending; the sweep marks it
  after one successful pass; any failure leaves it pending and the next sweep retries. A
  propagated Position is born applied (`scope_applied_at = established_at`), so it never
  re-enters the queue — that is the no-chains rule, structurally.
- **Scope on the Position, not on the Finding.** `DecisionScope` is a `PositionInputs` field;
  `release` is stored as `""` so every pre-record Position reads back as release-scoped without
  a data migration.
- **Propagation is an accept.** `FindingService.ApplyScopedPosition` raises
  `scoped:<target>:<source>:v<n>` (Asserted, in the person's name, rationale = the original
  rationale + "applied by scope … from release …") and accepts it with the source Position's
  terms (review_by, owner, treatment, proof) plus `PropagatedFrom {finding, version}`. The
  ordinary notes (ProposalRaised, ProposalAccepted, position note) fire, so Communication and the
  SLA clocks see it like any decision. Target already decided ⇒ no-op; duplicate proposal ⇒ no-op.
- **Two entry points, one target rule.** `ScopePropagation.Targets` (sweep + preview) walks the
  Faultline's siblings; `ForRelease` (worker) walks a release's undecided Findings and looks for
  a standing scoped source among their siblings — latest wins, disagreeing stances apply
  nothing and are counted as `conflicts`. Both resolve release → product/project through the
  Registry seam **last** and cache it per run. No Registry seam ⇒ the whole feature is off and
  the node says so at startup.
- **Preview** shares `Targets` with the sweep, so what the GUI will show (S2) is what the sweep
  will do.
