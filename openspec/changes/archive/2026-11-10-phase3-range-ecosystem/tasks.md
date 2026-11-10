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
- [x] 1.6 VM (2026-10-16): deployed; a 20-minute fast sweep made OSV restate the cards; the
  enrichment event re-ran the rule and the four old Go CVEs (CVE-2019-17596, -2020-15586,
  -2021-34558, -2021-36221) cleared — 0 open / 2 decided each — before the re-judge pass even ran
  (it reported raised 0 over 448 undecided cards). Range verdicts accepted that afternoon: 8, on
  exactly those 4 CVEs; the drop in undecided cards came from the 1008 accepted_risk signings.
  Open Findings on the estate afterwards: 2223.
