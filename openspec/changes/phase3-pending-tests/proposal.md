# Proposal — phase3-pending-tests (test and verification backlog)

## Why

Several changes had their code built and merged but still carried unticked test and VM-check
tasks, so they could not be archived. Leaving them open hid which features are finished and which
are still being proven. The owner asked (2026-11-10) to collect that remaining test work in one
change and archive the rest.

## What changes

- **Nothing in the code.** This change holds tasks only.
- `phase3-report-intake`: task 4.6 and Groups 5–9 move here verbatim (live estate round, the
  intake contract test matrix, the three verification points, the two approval proof obligations,
  and the D10 follow-through, which includes one open owner question, 9.3).
- `phase3-decision-scope-s1`: task 4.3 (the GUI scope-picker VM check) moves here.
- Each source change keeps a one-line pointer where the task used to be, and is archived.

## Out of scope

- `phase3-outward-actions` stays open: its open items are owner decisions and the runtime
  poller (6.10), not tests.

## Impact

Docs only (`openspec/`). No API, schema, build or CI change.
