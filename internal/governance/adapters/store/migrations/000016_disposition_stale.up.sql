-- EDR-GOVERNANCE-01 D14 amendment (RF-2, 2026-10-16): a suppressing decision whose premise moved
-- or whose review-by date passed is RE-SURFACED, and the Finding itself records that, so the
-- queue and the drawer can show it and residual_priority can stop suppressing it. Before this,
-- governance.disposition_stale.v1 was emitted and nobody read it: a quiet CVE with an expired
-- review date never came back. NULL stale_since = not re-surfaced; a new Position clears it.
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS stale_since  TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS stale_reason TEXT NOT NULL DEFAULT '';
