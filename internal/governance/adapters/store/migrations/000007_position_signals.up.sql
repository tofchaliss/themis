-- The exploitability signals a Position was decided WITH (GOV-14b / EDR-GOVERNANCE-01 D14).
--
-- `residual_priority` zeroes a not_affected / accepted_risk Finding, removing it from the work
-- queue. That is only SAFE if something re-surfaces it when the premise of the decision drifts —
-- otherwise an acceptance is permanent in practice. Detecting drift needs to know what was
-- believed AT THE TIME; the current signal values alone cannot answer "has this moved?".
--
-- On the Position rather than the Finding, because a Position is immutable and versioned: each
-- decision records its own premise, so re-deciding later starts a fresh baseline instead of
-- overwriting the one the previous decision rested on.
--
-- Additive with safe defaults. An existing row reads as "decided when nothing was known", which
-- makes the watcher CONSERVATIVE on historical data: any positive signal now looks like drift and
-- re-surfaces the Finding. That is the right direction to be wrong in — a redundant review costs
-- attention, a missed one costs a breach.
ALTER TABLE finding_positions ADD COLUMN IF NOT EXISTS decided_kev            BOOLEAN          NOT NULL DEFAULT FALSE;
ALTER TABLE finding_positions ADD COLUMN IF NOT EXISTS decided_exploit_public BOOLEAN          NOT NULL DEFAULT FALSE;
ALTER TABLE finding_positions ADD COLUMN IF NOT EXISTS decided_epss           DOUBLE PRECISION NOT NULL DEFAULT 0;

-- The CURRENT exploitability picture per Finding, refreshed on every enrichment. Denormalized for
-- the same reason base_score is: a decision needs it AT THE MOMENT it is taken, and reaching across
-- to Knowledge then would make the record of WHY depend on a live read succeeding.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS signal_kev            BOOLEAN          NOT NULL DEFAULT FALSE;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS signal_exploit_public BOOLEAN          NOT NULL DEFAULT FALSE;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS signal_epss           DOUBLE PRECISION NOT NULL DEFAULT 0;
