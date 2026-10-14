# Proposal — phase3-vendor-statements (EDR-VEX-02, 2026-10-14 amendment D13–D17)

## Why

A Rocky Linux 8.10 release's finding for CVE-2022-30632 showed Red Hat statements for RHEL 9,
OpenStack and Satellite — all correctly "does not apply here" — and nothing for RHEL 8, which is
the release's own family. Red Hat's record says RHEL 8 is **fixed** in five packages and **will
not fix** in two. Themis kept only rows that say "Not affected" (`redhat_client.go`), turned fixed
rows into bare fix versions with no scope, and dropped the rest. The vendor's answer for the
operator's own release never reached the drawer.

The same loss hides the state of the scanner-reported packages the match census found open and
never cleared (`binutils` 87, `compat-libtiff3` 59, `libtiff` 42, `curl` 26): Red Hat marks them
"Will not fix" or "Affected" for RHEL 8, and the drawer cannot say so.

## What changes

- **Knowledge** keeps every Red Hat package row as a statement with its real status (closed set:
  `not_affected | affected | will_not_fix | fix_deferred | out_of_support | under_investigation |
  fixed`), and every main-stream advisory row as a `fixed` statement carrying the advisory id and
  the fixed build, each with its product scope. Restatements are detected against the set, not the
  latest proposal.
- **Governance** carries the new fields through the event, the client and the assessment, exposes
  them on `vendor_statements[]`, and keeps raising a proposal ONLY for an applicable
  `not_affected` statement.
- **The GUI** lists applicable statements first, folds the others under one line, and says in
  words when no statement covers the release.

## What does NOT change

- The auto-accept policy (EDR-VEX-02 D9) and the Observed floor.
- The `VulnFacts.Fixes` path and the verdict engine's inputs.
- The applicability states and the family+major match (D3–D6, D11, D12).
- Non-Red Hat sources beyond accepting the closed status set they already emit.

## Decision record

EDR-VEX-02 amendment D13–D17 (2026-10-14). No `specs/` deltas; archive with `--skip-specs`.
