# Design — phase3-vendor-will-not-fix

- `reactToApplicabilityCounted` splits the card's statements into two selections: `not_affected`
  (unchanged, `vex:` proposals, stance not_affected) and no-fix (`will_not_fix`, `fix_deferred`,
  `out_of_support`; `vexwnf:` proposals, stance accepted_risk). Each selection goes through the
  same `coveringStatement` + `applicabilityOf` gate per Finding; both are Asserted. A Finding may
  receive both (the vendor says not_affected for one package and will_not_fix for another); a
  person picks.
- `watchDispositions` gains one drift beside KEV / exploit / EPSS: when the current Position's
  accepted proposal id starts with `vexwnf:` and the signal carries an applicable `fixed`
  statement for the package the proposal was raised for (the package key is in the id, the package
  name in the rationale), the Finding is marked re-surfaced with the fix's build and advisory in
  the reason. Same mark, same event, same "asked once".
- The accept script reads the stance from the proposal row and skips `accepted_risk` unless
  `--include-will-not-fix` is given; the apply path is unchanged (a human's decision through the
  API).
