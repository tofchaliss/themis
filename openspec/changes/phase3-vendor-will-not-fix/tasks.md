# Tasks — phase3-vendor-will-not-fix

No `specs/` deltas — archive with `openspec archive phase3-vendor-will-not-fix --skip-specs -y`.

- [x] 1.1 The no-fix selection and the `vexwnf:` accepted_risk raise (D18, D19); tests: raised for
  an applicable will_not_fix / fix_deferred / out_of_support; not for affected, under_investigation,
  fixed; not when the scope does not apply; waits for a human even under the Observed policy;
  idempotent; both proposals on one Finding.
- [x] 1.2 The vendor-fix drift (D20); tests: a Finding that accepted a `vexwnf:` proposal is
  re-surfaced by an applicable `fixed` for the same package, not by a fix for another package, not
  by a non-applicable fix, not when the Position rests on something else.
- [x] 1.3 `vex-accept-applicable.sh --include-will-not-fix` (D19).
- [x] 1.4 EDR amendment, BACKLOG VEX-WNF-1 closed, CLAUDE.md line.
- [x] 1.5 VM (2026-10-16): the first re-judge pass on the new binary raised **1008** `vexwnf:`
  accepted_risk proposals (its "done" line was lost to an overlapping restart; the second pass
  logged `vendor_raised: 0`, the idempotence). The two dry runs: 29 listed plus "1008 … not listed"
  without the flag, 1037 all `accept` with it. One proposal in the GUI: not yet opened. Whether
  to sign them is the user's call.
