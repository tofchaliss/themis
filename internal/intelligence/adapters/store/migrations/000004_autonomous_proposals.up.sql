-- Δ4b (EDR-INTELLIGENCE-01 D-Δ4b-5): the autonomous analyst's idempotence record. Before the
-- cross-release-consistency analyst pushes an advisory proposal, it checks here; after a
-- successful push it records the (finding, precedent) pair. On the next cadence tick it SKIPS
-- pairs it already proposed — re-proposing only when the precedent that grounded it CHANGED
-- (precedent_key encodes the precedent's identity + version). Without this, a cadence
-- accumulates identical advisory proposals until a human decides — proposal spam, the behavior
-- that makes operators disable the autonomous plane.
--
-- Operational state, NOT truth (like the invocation log): a wipe risks RE-proposing (annoying),
-- never MIS-proposing (wrong). Disposable.
CREATE TABLE IF NOT EXISTS autonomous_proposals (
    finding_id    TEXT NOT NULL,
    precedent_key TEXT NOT NULL,
    proposed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (finding_id, precedent_key)
);
