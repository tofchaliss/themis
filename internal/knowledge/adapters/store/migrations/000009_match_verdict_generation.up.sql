-- The verdict-logic generation stamp (EDR-VERDICT-01 D6, KN-VERDICT-2).
--
-- verdict_card_version records "judged against card version N" -- but not against WHICH
-- judgement logic. So deploying a binary that changes judgeOccurrence or FixesFor re-judged
-- NOTHING: every row was stamp-current, the sweep honestly reported rejudged:0, and the new
-- rule's effect waited on unrelated feed drift. Measured on KN-FIX-4 (2026-09-10), where the
-- operator worked around it twice by hand with verdict_card_version = 0.
--
-- Same shape as the claim-class generation added in 000008, and for the same reason: a code
-- change advances no data version, so only a constant the query can compare against makes a
-- logic change count as staleness. "The query IS the state."
--
-- Defaults to 0, so every existing row reads as stale once and the catch-up sweep drains it.
ALTER TABLE faultline_matches ADD COLUMN IF NOT EXISTS verdict_generation INT NOT NULL DEFAULT 0;

-- The stale query filters on both stamps, so it reads them together.
CREATE INDEX IF NOT EXISTS idx_faultline_matches_verdict_stamps
    ON faultline_matches (verdict_generation, verdict_card_version);
