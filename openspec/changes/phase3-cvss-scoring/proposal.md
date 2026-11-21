# Proposal — phase3-cvss-scoring (EDR-SCORING-01)

## Why

Themis shows one CVSS headline per CVE for the whole estate, takes the vendor's score for every
component, does not read CVE.org, computes only the 3.x Base score, and cannot take release
requirements (CR / IR / AR), temporal evidence or a person's change. The owner wants the score a
person sees to match what the CNA and the platform vendor published for that component, to be
changeable by an authorised person, and to explain itself in the GUI ("how Themis got this score").

## What changes

Built in steps S1-S8 of EDR-SCORING-01 section 12, one PR each, each on the owner's go:

- **S1** kernel CVSS 3.0 / 3.1 calculator (Base / Temporal / Environmental, X kept, Roundup).
- **S2** Knowledge source truth: observations, one rating per publication, rating events,
  validations, identity links; NVD Secondary + `source`, the Red Hat withdrawal fix; opt-in
  CVE.org feed; read API.
- **S3** Registry CR / IR / AR on Product, Project, Release.
- **S4** Governance ComponentAssessment revisions inside the Finding, selection, roll-up,
  provenance API. **Shadow**: priority, SLA, Jira and notifications unchanged.
- **S5** GUI read-only score panel on the Finding and source ratings on the CVE page.
- **S6** GUI users and roles, then governed changes (vector override, source selection override,
  environmental exception).
- **S7** shadow review, then the priority input switch.
- **S8** exports and the CVSS 4.0 calculator.

**Release scope (owner decision 2026-11-20):** Themis 0.5.x carries S1-S5 (read-only GUI, shadow). S6-S8 follow in a later release.

## Out of scope here

Deployment-level requirements (R-E5), per-component human `not_affected` (O9), two-person approval
(R-O8). The lifecycle and integration items in EDR-SCORING-01 section 10.3 are decided inside the
step that needs them.

## Impact

Domain model changes in kernel, Knowledge, Registry and Governance; new migrations in each; new
read APIs (spec-first); new GUI panel. S1-S5 change no existing behaviour. Every step keeps
`make check-ci` green and ends with `make vet-tags`.
