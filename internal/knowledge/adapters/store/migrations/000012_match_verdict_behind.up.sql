-- EDR-INCIDENT-01 D1: the vendor fix bounds an OPEN occurrence is behind, recorded beside its
-- verdict. The reason column already SAYS them as prose; this is the same fact as a set a
-- query can compare, so that a bound appearing here for the first time on a row already judged
-- reads as "a fix was published for something this release has open" — the fix-available
-- alert — and a bound that was already here reads as nothing new.
--
-- Defaults to the empty set. The judgement-logic generation moves to 5 in the same change, so
-- the catch-up sweep re-judges every row once and writes its bounds SILENTLY (the first
-- recording is not news); only a later growth of the set is announced.
ALTER TABLE faultline_matches ADD COLUMN IF NOT EXISTS verdict_behind TEXT[] NOT NULL DEFAULT '{}';
