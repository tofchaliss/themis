# Proposal — phase3-incident-b (EDR-INCIDENT-01, step B)

## Why

During a vulnerability wave the owner holds a list of identifiers — the CVEs in the news, the
RHSA ids Red Hat shipped — and the question is one table: for every release we run, where does
each of them stand today? Step A made Themis *tell* when a vendor fix lands; step B lets a
person *ask* with the list they already have, instead of opening one CVE page per id per
project.

## What changes

- **A Watch**: a named, operator-owned list of CVE ids and Red Hat advisory ids
  (RHSA-/RHBA-/RHEA-), append-only on its identifiers, deletable whole. Governance owns it
  (migration **000024**, table `watches`) because it already joins Knowledge's verdicts with
  Positions and Registry names.
- **The table, computed on read**: `GET /watches/{id}/status` returns one row per (release,
  CVE) over every release that has a Finding for any watched CVE, with the D2 state —
  `not_affected` · `open_no_fix` · `open_fix_available` · `fixed` · `accepted` · `unknown` —
  the open packages, the recorded fix versions that apply, the standing stance, and the
  release's newest evidence as "last proof". Nothing is stored but the CVE set the identifiers
  resolved to.
- **Advisory resolution**: Knowledge gains `GET /faultlines/by-advisory?id=` — the cards whose
  `fixed` vendor statements carry the advisory (EDR-VEX-02 D14). An advisory no card carries
  resolves to nothing and the table says `unknown`.
- **API**: `GET/POST /watches`, `GET/DELETE /watches/{id}` (delete is admin),
  `POST /watches/{id}/identifiers`, `GET /watches/{id}/status`.
- **GUI**: a Watches rail page — paste, name, open the table, filter by state, export CSV, add
  identifiers, delete.

## What does NOT change

- No Finding, Position or proposal changes because a Watch exists. A `fixed` row is a display
  state; the Finding closes through the evidence-driven path.
- D2a (`notify` → `governance.watch_changed.v1`) is **deferred**: the flag is stored, nothing
  emits on it yet.
- No new knob; the feature needs the Knowledge seam for the table (503 without it) and uses the
  Registry and Evidence seams for names and last proof when they are wired.

## Decision record

EDR-INCIDENT-01 D2 (D2a deferred), D5. No `specs/` deltas; archive with `--skip-specs`.
