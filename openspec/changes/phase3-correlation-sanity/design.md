# Design — phase3-correlation-sanity

- `CorrelationService.WithFanoutGuard(at, recorder)`; `flagFanout` runs per component in
  `PlanCorrelation` and `DiscoverComponents` after discovery; `PlannedMatch.Suspect` carries the
  reason; `applyDiscovered` stamps it on open verdicts only.
- Store: migration 000011 `correlation_sanity` (PK release_id+purl, upsert); `RecordSuspectFanout`,
  `SuspectFanouts`. Read API `GET /sanity` (`SanityFlag[]`), `X-Themis-Sanity: not-wired` when
  the handler has no reader. Census section 0 reads the table (replay seam skips it).
