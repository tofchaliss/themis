# Design — phase3-pending-tests

## Decisions

- **Move, do not rewrite.** Tasks are copied verbatim with their original numbers, so every
  reference in an EDR, the BACKLOG or a PR still resolves. The source of truth for each task stays
  the EDR named in its section (EDR-INTAKE-01, EDR-SYNC-01).
- **A pointer is left behind.** The source `tasks.md` keeps a plain line (not a checkbox) naming
  this change, so reading the archived change still tells you where the work went and does not
  claim the task was done.
- **Archive when the gate is green.** When every task here is ticked and `make check` is green,
  archive with `openspec archive phase3-pending-tests --skip-specs -y`.
