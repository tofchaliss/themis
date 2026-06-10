## ADDED Requirements

### Requirement: EPSS and KEV daily sync
The system SHALL fetch FIRST.org EPSS probability scores and CISA KEV listings on
a daily schedule and store them in the `intelligence_signals` table with a TTL equal
to `sync_interval + 1 hour`. Each record SHALL include a `fetched_at` timestamp.
If a sync fails, the system SHALL retry 3 times with exponential backoff and set a
`stale` flag on affected `risk_context` rows after 25 hours without a successful sync.

#### Scenario: EPSS sync stores current scores
- **WHEN** the daily EPSS scheduler fires and the FIRST.org endpoint returns HTTP 200
- **THEN** the system SHALL upsert EPSS scores into `intelligence_signals` keyed by
  `cve_id`, overwriting the previous score, and set `fetched_at = NOW()`

#### Scenario: KEV sync marks actively exploited CVEs
- **WHEN** the daily KEV scheduler fires and the CISA KEV JSON returns a list of CVE IDs
- **THEN** the system SHALL upsert `kev_listed = true` for all listed CVE IDs in
  `intelligence_signals` and `kev_listed = false` for any CVE IDs previously listed
  but absent from the current feed

#### Scenario: Sync failure does not block ingestion
- **WHEN** the EPSS or KEV endpoint is unreachable or returns a non-200 status
- **THEN** the system SHALL log a WARNING with the HTTP status, retry up to 3 times,
  and continue operating with the last successfully fetched data; ingestion SHALL
  NOT be blocked

#### Scenario: Stale flag set after 25 hours without successful sync
- **WHEN** 25 hours have elapsed since the last successful EPSS or KEV sync
- **THEN** the system SHALL set `intelligence_signals.stale = true` for affected
  records and include `"signals_stale": true` in the `GET /api/v1/status` response

---

### Requirement: Retroactive ReEnrichJob on EPSS/KEV sync
After every successful EPSS or KEV sync the system SHALL enqueue a `ReEnrichJob`
for all `risk_context` rows where `effective_state IN ('DETECTED', 'IN_TRIAGE')`.
The job SHALL recompute the composite risk score using the updated signal values.

#### Scenario: ReEnrichJob enqueued after successful EPSS sync
- **WHEN** an EPSS sync completes successfully
- **THEN** the system SHALL enqueue a `ReEnrichJob` covering all open findings;
  each job batch SHALL contain at most 500 findings; continuation batches are
  enqueued until all open findings are covered

#### Scenario: Risk scores updated for existing findings after KEV listing
- **WHEN** a CVE that was previously not KEV-listed is added to the KEV feed
- **THEN** all `risk_context` rows for that CVE SHALL have `risk_score` recomputed
  to include the `+15 KEV adjustment` within one job-queue processing cycle

---

### Requirement: EPSS and KEV signals accessible on risk_context
The system SHALL expose `epss_score` (float, 0.0–1.0) and `kev_listed` (bool) on
every `risk_context` row. Both fields SHALL be populated from `intelligence_signals`
at enrichment time and updated by `ReEnrichJob`. Both fields SHALL default to
`NULL` / `false` until the first sync completes.

#### Scenario: risk_context includes EPSS score after enrichment
- **WHEN** a finding is enriched after EPSS data has been synced for its CVE
- **THEN** `risk_context.epss_score` SHALL equal the most recent score from
  `intelligence_signals` for that CVE ID

#### Scenario: risk_context kev_listed reflects current KEV state
- **WHEN** a CVE is added to the KEV list and `ReEnrichJob` runs
- **THEN** `risk_context.kev_listed` SHALL be `true` for all findings of that CVE
