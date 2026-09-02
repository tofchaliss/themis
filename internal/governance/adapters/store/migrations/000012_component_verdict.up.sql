-- Mirrored occurrence verdict (EDR-VERDICT-01 D5/D7, KN-VERDICT-1).
--
-- Knowledge owns the verdict — "these files already carry the vendor's fix" is a fact about
-- software, computed where the card's fixes and the comparators live. Governance MIRRORS it here
-- so queue membership and priority can derive from the open-carrier set without a cross-context
-- read: a Finding leaves the triage queue only when every carrier occurrence is cleared or
-- covered by the Position, and cleared occurrences contribute zero to priority while open ones
-- are never discounted (D7).
--
-- Additive with empty defaults: '' reads as open everywhere — the fail-safe direction — so rows
-- predating the feature keep exactly their previous meaning (recorded live matches).
ALTER TABLE finding_components ADD COLUMN IF NOT EXISTS verdict_state  TEXT NOT NULL DEFAULT '';
ALTER TABLE finding_components ADD COLUMN IF NOT EXISTS verdict_grade  TEXT NOT NULL DEFAULT '';
ALTER TABLE finding_components ADD COLUMN IF NOT EXISTS verdict_reason TEXT NOT NULL DEFAULT '';
