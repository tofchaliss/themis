-- The full matched component, not just its PURL (KN-FIX-2).
--
-- A match previously recorded only `component_purl`, which is enough to say WHAT matched but not
-- enough to ASK A FEED ABOUT IT AGAIN: a re-query needs the ecosystem, the version and — for
-- distro packages — the source-package name that vulnerability databases key their fixes on.
--
-- Without these, a card folded before fix-attribution existed can only regain it when its release
-- is re-uploaded. Content-addressing means re-uploading identical bytes DEDUPS, so on a real
-- estate where releases are uploaded once, "just upload it again" is not available and the card
-- stays unattributed forever while the NVD backfill keeps appending unattributed fixes to it.
--
-- Additive with empty defaults: existing rows keep '' and are simply skipped by the sweep, which
-- is correct — a row we cannot re-query is one we must not guess about.
ALTER TABLE faultline_matches ADD COLUMN IF NOT EXISTS component_name      TEXT NOT NULL DEFAULT '';
ALTER TABLE faultline_matches ADD COLUMN IF NOT EXISTS component_version   TEXT NOT NULL DEFAULT '';
ALTER TABLE faultline_matches ADD COLUMN IF NOT EXISTS component_ecosystem TEXT NOT NULL DEFAULT '';
ALTER TABLE faultline_matches ADD COLUMN IF NOT EXISTS component_source    TEXT NOT NULL DEFAULT '';
