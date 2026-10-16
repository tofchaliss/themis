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
- [ ] 1.5 VM: re-judge pass raises the `vexwnf:` proposals (`vendor_raised`); the accept script's
  dry run with and without the flag; one proposal in the GUI.
