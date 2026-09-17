-- Re-classification stamps (EDR-CORRELATION-01 D3/D4, KN-CLAIM-1).
--
-- `claim_class` is NOT persisted in Knowledge. It is computed from the card's carrier products
-- when an event is built, and only Governance stores it (`finding_components.claim_class`).
-- So "which rows need re-classifying" has no per-match answer here -- it is a CARD-level
-- question, because the input that changes is the card's carrier set.
--
-- Two stamps, because two different things go stale independently:
--
--   reclassified_version    -- the card version last re-announced. A fold that changes the
--                              carrier set advances `version` and leaves this behind.
--   reclassified_generation -- the classification RULE generation last applied. A code change
--                              to the rules advances NO card version at all, so a
--                              version-only stamp would leave every existing occurrence
--                              carrying a class computed by the old rules: shipped and
--                              invisible. That is KN-VERDICT-2's failure shape, and it has
--                              already happened twice in claimclass.go (role suffixes
--                              2026-09-16, shared distinguishing token 2026-09-17).
--
-- Both default to 0, so every card that already exists reads as stale and the first sweeps
-- drain history -- the same self-targeting property the D6 verdict stamp has.
ALTER TABLE faultlines ADD COLUMN IF NOT EXISTS reclassified_version    BIGINT NOT NULL DEFAULT 0;
ALTER TABLE faultlines ADD COLUMN IF NOT EXISTS reclassified_generation INT    NOT NULL DEFAULT 0;

-- The sweep's selector and its ORDER BY. Ordering on the stamps rather than on updated_at
-- guarantees forward progress without touching the card: a stamped card sorts behind the
-- unstamped ones, so a bounded batch drains instead of re-reading the same head.
CREATE INDEX IF NOT EXISTS idx_faultlines_reclassify
    ON faultlines (reclassified_generation, reclassified_version);
