-- EDR-TRUST-01 T2/T3: the trust class of the evidence a Governance Proposal rests on. It is
-- what the constitutional check (T4) reads to decide whether the proposal is even eligible
-- for automatic acceptance — so it MUST round-trip: a proposal reloaded without its class
-- would read as Inferred and be silently barred from a policy that accepted it before.
--
-- Defaults to 'asserted' rather than empty on purpose. Empty reads as Inferred under
-- value.MaxTrust, which would retroactively bar every pre-existing proposal from policy
-- auto-acceptance on deploy. 'asserted' preserves current behaviour (policy still governs)
-- without claiming the stronger 'observed' for evidence nobody classified.
ALTER TABLE finding_proposals
  ADD COLUMN IF NOT EXISTS evidence_trust TEXT NOT NULL DEFAULT 'asserted';
