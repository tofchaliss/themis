# Themis intake fixtures

One directory per L6 constitution hash (first 12 hex). Each holds a
REAL completed harness record — a `remediate-dependency@4` walk under a
test anchor with the HTTP read door — plus the registries needed to
resolve it and a `provenance.json` naming the generator, the harness
commit, the constitution and anchor hashes, the task id, the
artifact-bound seq, and the commission id.

Generated only by `src/themis` `TestThemisIntakeFixture` with
`THEMIS_FIXTURE_GENERATE=1`; verified by the same test in default mode
(constitution hash must equal the compiled one, record VERIFIED and
COMPLETED, five production links present). Never edited by hand. The
Themis repository's intake tests reconstruct these records (D-I-7);
forged-record tests there use L6 primitives, never these files.
Regenerate whenever the L6 constitution hash moves; keep the old
directory only while a Themis-side historical test still cites it.
