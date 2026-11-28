# Proposal — phase3-image-rebuild (EDR-REBUILD-01)

## Why

Themis knows when a fixed package is published for a component of a Release, and the usual fix
for an image is a rebuild. Today a person has to notice and start that build. The owner wants
Themis to ask for the rebuild itself, per Product, Project and Release, when a policy the owner
controls says it is worth it, and to prove afterwards what the rebuild fixed.

## What changes

Built in the steps of EDR-REBUILD-01 "Order of work", one PR each, each on the owner's go
(release freeze):

- **R1** the installation rebuild policy in Governance: the fixed-field record of D2, the pure
  evaluation rule, the store with a version and a change history, read and write API.
- **R1a** Product and Release policy overrides; the effective-policy read and the list read (D11).
- **R2** evaluation on `new_sbom` and on `fix_available`; tag scope; the standing recommendation.
- **R2a, R3, R4** the rebuild request, its signed event and the delivery, as the record orders them.
- **R5** the reference build connector, in its own repository.
- **R6** the VM check: one release tagged, one fix published, one build, one comparison.

## Out of scope here

Everything EDR-REBUILD-01 lists under "What this record does NOT decide": deploying the rebuilt
image, a per-Release attempt limit, and stopping an open cycle when the mode goes `off`.
