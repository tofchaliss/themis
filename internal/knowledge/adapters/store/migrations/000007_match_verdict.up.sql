-- Occurrence verdict state on the match record (EDR-VERDICT-01 D2/D6, KN-VERDICT-1).
--
-- A match previously had exactly two fates: recorded (live forever) or silently dropped at
-- correlation time when the fixed-verdict said the installed build carried the fix. That made
-- "checked and fine" indistinguishable from "never looked", left scanner-path matches entirely
-- unjudged, and gave the verdict exactly one chance to fire — bounds folding onto the card an
-- hour after correlation changed nothing, ever (measured: CVE-2025-47273 / MRF).
--
-- Now every examined occurrence is recorded WITH its verdict:
--   verdict_state        'open' | 'cleared_vendor_fix'; anything else reads as open (fail-safe).
--   verdict_grade        evidence strength behind a clearance: 'observed' | 'inferred' | ''.
--   verdict_reason       the plain-language premise, rendered verbatim by the drawer.
--   verdict_card_version the card version this row was last judged against (the D6 stamp).
--                        0 marks rows predating the feature — the catch-up sweep's primary
--                        target. Pre-feature rows default to 'open', which is what they were:
--                        recorded live matches.
ALTER TABLE faultline_matches ADD COLUMN IF NOT EXISTS verdict_state        TEXT   NOT NULL DEFAULT 'open';
ALTER TABLE faultline_matches ADD COLUMN IF NOT EXISTS verdict_grade        TEXT   NOT NULL DEFAULT '';
ALTER TABLE faultline_matches ADD COLUMN IF NOT EXISTS verdict_reason       TEXT   NOT NULL DEFAULT '';
ALTER TABLE faultline_matches ADD COLUMN IF NOT EXISTS verdict_card_version BIGINT NOT NULL DEFAULT 0;
