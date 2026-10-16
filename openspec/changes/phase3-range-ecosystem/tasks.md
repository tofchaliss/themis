# Tasks — phase3-range-ecosystem

No `specs/` deltas — archive with `openspec archive phase3-range-ecosystem --skip-specs -y`.

- [x] 1.1 Kernel `RangeStatement` + `SelectRanges`; tests (package > ecosystem > universal,
  unknown world, no statements, none applicable).
- [x] 1.2 Knowledge domain: facts, reconcile, view `RangesFor`, event; codec; OSV tagging; match
  gate; tests (worlds kept, later statements replace, changed set is a new observation, codec
  round trip, OSV statements, the CVE-2019-17596 fixture at match time).
- [x] 1.3 [API] `affected_range_statements` on the Knowledge read API; regenerated; handler.
- [x] 1.4 Governance: DTO → coordinator → signal → rule → re-judge; client; tests (rule oracle
  extension, consumer wire, client mapping, re-judge pass).
- [x] 1.5 EDR-KNOWLEDGE-01 D13–D14, EDR-TRUST-01 note, BACKLOG, CLAUDE.md.
- [ ] 1.6 VM: deploy knowledge + governance; let the re-discovery sweep restate the Go cards (or
  force it with the fast-sweep settings); run the re-judge pass; the four old Go CVEs
  (CVE-2019-17596, -2020-15586, -2021-34558, -2021-36221) clear.
