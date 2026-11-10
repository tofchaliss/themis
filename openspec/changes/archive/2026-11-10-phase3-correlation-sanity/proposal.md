# Proposal — phase3-correlation-sanity (EDR-CORRELATION-01 D9, 2026-10-17)

## Why

KN-GO-1 (one Go component, 165 CVEs, 155 false) was visible the day it happened and nothing
looked. The shape — one component, a version the comparator cannot read, a three-digit discovery
answer — is cheap to detect at correlation time.

## What changes

- **Knowledge** flags a component whose discovery returns ≥ N distinct CVEs for an unparseable
  version: a `correlation_sanity` row, `GET /sanity`, the census's section 0, and the reason on
  every open occurrence's verdict. N = `THEMIS_CORRELATION_FANOUT_SUSPECT_AT` (default 50; 0 off).
- Kernel: `value.VersionParsable`.

## What does NOT change

- No match is dropped, held or decided; verdict states are unchanged; Governance is untouched.

## Decision record

EDR-CORRELATION-01 D9. No `specs/` deltas; archive with `--skip-specs`.
