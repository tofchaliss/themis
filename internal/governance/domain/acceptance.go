package domain

import (
	"errors"
	"strings"
	"time"
)

// Risk-acceptance terms (EDR-REMEDIATION-01 D2, D8 Q3). An accepted_risk or deferred Position may
// say WHO is accountable for the risk (the owner — often not the person who signed it), HOW it is
// being treated, and WHERE the justification lives. They are inputs the decision rested on, so
// they live in PositionInputs and are immutable with the version: changing the owner or the
// treatment is a new Position version with the same stance, recorded against whoever changed it.

// Treatment is how an accepted risk is being handled. The set is closed.
type Treatment string

const (
	// TreatmentAccept: the risk is carried as is.
	TreatmentAccept Treatment = "accept"
	// TreatmentTransfer: someone else carries it (a supplier, an insurer, a customer contract).
	TreatmentTransfer Treatment = "transfer"
	// TreatmentAvoid: the exposure is being removed (the feature or deployment goes away).
	TreatmentAvoid Treatment = "avoid"
	// TreatmentMitigateLater: it will be fixed, in a later release.
	TreatmentMitigateLater Treatment = "mitigate_later"
)

// ValidTreatment reports whether t is in the closed set; empty is "not stated" and valid.
func ValidTreatment(t Treatment) bool {
	switch t {
	case "", TreatmentAccept, TreatmentTransfer, TreatmentAvoid, TreatmentMitigateLater:
		return true
	}
	return false
}

// AcceptanceTerms are the decider's inputs to one acceptance, beside the proposal it accepts.
type AcceptanceTerms struct {
	ReviewBy  time.Time
	Owner     string
	Treatment Treatment
	// Proof is a reference (URL or document id) to the justification. Stored as text, never
	// fetched.
	Proof string
}

var (
	// ErrOwnerRequired: a person accepting an accepted_risk must name the accountable owner (Q3).
	// A policy or vendor proposal may arrive without one; the person who signs it supplies it.
	ErrOwnerRequired = errors.New("governance: an accepted risk needs a named owner")
	// ErrInvalidTreatment: the treatment is outside the closed set.
	ErrInvalidTreatment = errors.New("governance: treatment must be accept, transfer, avoid or mitigate_later")
	// ErrTermsNotApplicable: owner, treatment or proof were given for a stance that carries no
	// risk acceptance (only accepted_risk and deferred do).
	ErrTermsNotApplicable = errors.New("governance: owner, treatment and proof apply only to accepted_risk and deferred")
)

// carriesAcceptance reports whether a stance is a risk acceptance the terms describe.
func carriesAcceptance(s Stance) bool { return s == StanceAcceptedRisk || s == StanceDeferred }

// checkTerms validates the terms for the stance being accepted and by whom, and returns them
// normalized.
func checkTerms(stance Stance, by Actor, t AcceptanceTerms) (AcceptanceTerms, error) {
	t.Owner, t.Proof = strings.TrimSpace(t.Owner), strings.TrimSpace(t.Proof)
	t.Treatment = Treatment(strings.TrimSpace(string(t.Treatment)))
	if !ValidTreatment(t.Treatment) {
		return t, ErrInvalidTreatment
	}
	if !carriesAcceptance(stance) {
		if t.Owner != "" || t.Treatment != "" || t.Proof != "" {
			return t, ErrTermsNotApplicable
		}
		return t, nil
	}
	if stance == StanceAcceptedRisk && by.Kind == ActorHuman && t.Owner == "" {
		return t, ErrOwnerRequired
	}
	return t, nil
}

// DefaultReviewWarning is how long before a review-by date the owner is warned (D2).
const DefaultReviewWarning = 14 * 24 * time.Hour

// ReviewDueSoon is the fact that a decision's review-by date is near (governance.review_due_soon.v1),
// emitted once per Position version. Like every re-surfacing fact it changes nothing: expiry
// still re-surfaces the Finding exactly as before (RF-2).
type ReviewDueSoon struct {
	FindingID       FindingID
	ReleaseID       string
	FaultlineID     string
	CVE             string
	Stance          string
	PositionVersion int
	ReviewBy        time.Time
	Owner           string
	OccurredAt      time.Time
}

// NewReviewDueSoon builds the warning for a Finding's current Position.
func NewReviewDueSoon(f Finding, pos Position, at time.Time) ReviewDueSoon {
	return ReviewDueSoon{
		FindingID: f.ID(), ReleaseID: f.ReleaseID(), FaultlineID: f.FaultlineID(), CVE: f.CVE(),
		Stance: string(pos.Stance()), PositionVersion: pos.Version(), ReviewBy: pos.Inputs().ReviewBy,
		Owner: pos.Inputs().Owner, OccurredAt: at,
	}
}

// ReviewDueWithin reports whether a Position's review-by date falls in (now, now+window]: near,
// and not yet passed (a passed date is expiry, which re-surfaces instead).
func ReviewDueWithin(pos Position, now time.Time, window time.Duration) bool {
	rb := pos.Inputs().ReviewBy
	return !rb.IsZero() && rb.After(now) && !rb.After(now.Add(window))
}
