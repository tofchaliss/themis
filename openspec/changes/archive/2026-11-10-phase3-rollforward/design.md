# Design — phase3-rollforward

Two pure rules in the domain and one pass in the app; nothing crosses a context boundary that
did not already.

- `domain.RollForwardEligibility(target, precedent []MatchedComponent) RollForwardLevel` — the
  granularity rule (D3) over active carrier components: `artifact` (same purls), `component`
  (same package keys), `""` (not proposed).
- `Finding.JudgedPosition()` — the precedent filter (D4): a current Position taken by a person,
  not by a policy and not on a system-raised proposal.
- `app.RollForward` — `ForRelease(ctx, releaseID, projectID)` for the worker, `Sweep(ctx, lister)`
  for the one-time pass, both over `FindingService.RollForwardFinding`, which reads the target,
  walks `FindingsByFaultline`, filters (same release out, judged only, eligible only), places the
  sibling's release through the Registry seam LAST and only for a qualifying sibling (one call
  per release per pass, cached), picks the latest, and raises through `mutate` +
  `raiseAndMaybeAutoAccept` with `TrustInferred`.
- Failure posture: any Registry, store or write failure returns an error; the worker defers the
  row (existing backoff) and the pass aborts. A missing precedent is "no proposal", never an
  error.
- Wiring: when `THEMIS_REGISTRY_URL` is set, the worker and the re-judge pass get the pass; when
  it is not, neither runs (there is no project to compare).
