package domain

import (
	"sort"
	"strings"
)

// Revision causes (EDR-SCORING-01 8.2). Each new revision names why it exists; the cause is
// derived from what differs between the current snapshot and the new one, so a re-delivered
// event or a periodic re-assessment that changes nothing creates no revision at all.
const (
	CauseComponentAdded         = "component_added"
	CauseComponentRemoved       = "component_removed"
	CauseEligibilityChanged     = "eligibility_changed"
	CauseApplicabilityChanged   = "applicability_changed"
	CauseClassificationChanged  = "classification_changed"
	CauseIdentityRelinked       = "identity_relinked"
	CauseSourceAdded            = "source_added"
	CauseSourceCorrected        = "source_corrected"
	CauseSourceWithdrawn        = "source_withdrawn"
	CauseRequirementChanged     = "requirement_changed"
	CauseTemporalAccepted       = "temporal_accepted"
	CauseTemporalPolicyChanged  = "temporal_policy_changed"
	CauseSelectionPolicyChanged = "selection_policy_changed"
	CauseCalculatorChanged      = "calculator_changed"
)

// ScoreCause names the first difference, in a fixed order, between the current snapshot (nil
// when the component has none) and the new one. Call it only when the two differ.
func ScoreCause(prev *ComponentScore, next ComponentScore) string {
	switch {
	case prev == nil:
		return CauseComponentAdded
	case prev.CalculatorVersion != next.CalculatorVersion:
		return CauseCalculatorChanged
	case prev.SelectionPolicy != next.SelectionPolicy || prev.ClassPolicy != next.ClassPolicy || prev.ApplicabilityPolicy != next.ApplicabilityPolicy:
		return CauseSelectionPolicyChanged
	case prev.TemporalPolicy != next.TemporalPolicy:
		return CauseTemporalPolicyChanged
	case prev.ClaimClass != next.ClaimClass:
		return CauseEligibilityChanged
	case prev.VerdictState != next.VerdictState:
		return CauseApplicabilityChanged
	case prev.Requirements != next.Requirements:
		return CauseRequirementChanged
	}
	before := map[string]CandidateEvaluation{}
	for _, c := range prev.Candidates {
		before[c.RatingID] = c
	}
	withdrawn, relinked, classified := false, false, false
	for _, c := range next.Candidates {
		p, ok := before[c.RatingID]
		if !ok {
			return CauseSourceAdded
		}
		switch {
		case c.Reason == ReasonInactive && p.Reason != ReasonInactive:
			withdrawn = true
		case c.IdentityKey != p.IdentityKey:
			relinked = true
		case c.Class != p.Class:
			classified = true
		}
	}
	switch {
	case withdrawn:
		return CauseSourceWithdrawn
	case relinked:
		return CauseIdentityRelinked
	case classified:
		return CauseClassificationChanged
	case temporalKey(prev.Temporal) != temporalKey(next.Temporal):
		return CauseTemporalAccepted
	}
	return CauseSourceCorrected
}

func temporalKey(ms []TemporalMetric) string {
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		parts = append(parts, m.Metric+"="+m.State+":"+m.Used)
	}
	return strings.Join(parts, "/")
}

// RollupCause names a roll-up revision's cause: component_removed when a component that was in
// the previous roll-up is no longer current, else the distinct causes of the component
// revisions written with it, sorted and joined; "recalculated" when none was written.
func RollupCause(removed bool, componentCauses []string) string {
	if removed {
		return CauseComponentRemoved
	}
	set := map[string]bool{}
	for _, c := range componentCauses {
		set[c] = true
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return "recalculated"
	}
	return strings.Join(out, ",")
}
