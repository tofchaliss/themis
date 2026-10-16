# Design — phase3-range-ecosystem

- Kernel: `value.RangeStatement`, `value.SelectRanges(ecosystem, names, statements, fallback)` —
  package-specific > ecosystem-wide, plus world-less; unknown component world sees all; no
  statements → fallback; statements but none applicable → empty (undecidable downstream).
- Knowledge domain: `VulnFacts.RangeStatements` (part of `sameAs`), `rangeStatement` per source
  keeps statements, `EnterpriseView.RangeStatements` (sorted union) + `RangesFor`; event
  `RangeStatements` (additive, schema updated); codec `range_statements` on proposal and view.
- OSV translator tags each paired range with the affected entry's canonical ecosystem and package.
- Match-time gate (`correlate.go`) and Governance rule (`domain.ProvablyOutOfRange(…, statements...)`)
  select through the same function; Governance's inbound DTO, coordinator, `EnrichmentSignal`,
  `RejudgeVersionRange`, Knowledge client and `FaultlineKnowledge` carry the statements.
