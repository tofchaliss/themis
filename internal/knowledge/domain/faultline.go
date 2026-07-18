package domain

import (
	"errors"

	"github.com/themis-project/themis/internal/kernel/value"
)

// FaultlineID is the Faultline's own opaque, stable identity — never the CVE string and
// never a source-prefixed string (D1).
type FaultlineID string

// Faultline is the enterprise's single knowledge card for one security issue (D1): its
// own identity keyed by canonical CVE; an append-only list of source Proposals; a
// materialized enterprise view reconciled from them (D2); and a forward-only lifecycle
// stage (D7). It is one aggregate and one consistency boundary (D9), guarded by an
// optimistic version. State changes only through its domain operations.
type Faultline struct {
	id        FaultlineID
	cve       value.CVEID
	proposals []Proposal
	view      EnterpriseView
	stage     Stage
	version   int
}

// NewFaultline creates a card for a canonical CVE at stage Created with no proposals.
func NewFaultline(id FaultlineID, cve value.CVEID) (Faultline, error) {
	if id == "" {
		return Faultline{}, errors.New("faultline: empty id")
	}
	if cve.IsZero() {
		return Faultline{}, errors.New("faultline: zero cve")
	}
	return Faultline{
		id:    id,
		cve:   cve,
		stage: StageCreated,
		view:  EnterpriseView{Severity: value.SeverityUnknown},
	}, nil
}

// Reconstitute rebuilds a Faultline from persisted state (used by the store adapter).
// Persistence is trusted; no re-validation is performed.
func Reconstitute(id FaultlineID, cve value.CVEID, proposals []Proposal, view EnterpriseView, stage Stage, version int) Faultline {
	return Faultline{
		id:        id,
		cve:       cve,
		proposals: append([]Proposal(nil), proposals...),
		view:      view,
		stage:     stage,
		version:   version,
	}
}

// FoldResult reports the outcome of folding a Proposal (D8): the view-change flag gates
// whether the app publishes FaultlineEnriched — an event fires only on an actual change.
type FoldResult struct {
	ViewChanged bool
}

// FoldProposal appends a source Proposal (append-only, recorded for audit even if it
// changes nothing — D8), re-reconciles the enterprise view under the precedence rule
// (D2), advances the lifecycle to at least Enriched (D7), and bumps the version. It
// reports whether the enterprise view changed. Idempotency (not re-folding the same
// proposal) is an app/store concern (D11), not the aggregate's.
func (f *Faultline) FoldProposal(p Proposal, prec Precedence) FoldResult {
	prev := f.view
	f.proposals = append(f.proposals, p)
	f.view = Reconcile(f.proposals, prec)
	f.stage = f.stage.advanceTo(StageEnriched)
	f.version++
	return FoldResult{ViewChanged: !f.view.equal(prev)}
}

// MarkCorrelated advances the card to at least Correlated when a component match has
// been produced (D3/D7). It returns whether the stage changed and bumps the version if
// so.
func (f *Faultline) MarkCorrelated() bool { return f.advance(StageCorrelated) }

// MarkMature advances the card to at least Mature when corroboration criteria are met
// (D7). The exact threshold is an app-layer policy; the aggregate only records it.
func (f *Faultline) MarkMature() bool { return f.advance(StageMature) }

// Supersede moves the card to the terminal Superseded stage — merged/replaced, or its
// CVE withdrawn/rejected upstream (D7). It returns whether the stage changed.
func (f *Faultline) Supersede() bool { return f.advance(StageSuperseded) }

func (f *Faultline) advance(target Stage) bool {
	next := f.stage.advanceTo(target)
	if next == f.stage {
		return false
	}
	f.stage = next
	f.version++
	return true
}

// ID returns the card's stable identity.
func (f Faultline) ID() FaultlineID { return f.id }

// CVE returns the canonical CVE this card is keyed by.
func (f Faultline) CVE() value.CVEID { return f.cve }

// Proposals returns a copy of the append-only source proposals.
func (f Faultline) Proposals() []Proposal { return append([]Proposal(nil), f.proposals...) }

// View returns the reconciled enterprise view (the authoritative knowledge).
func (f Faultline) View() EnterpriseView { return f.view }

// Stage returns the current lifecycle stage.
func (f Faultline) Stage() Stage { return f.stage }

// Version returns the optimistic-concurrency version stamp.
func (f Faultline) Version() int { return f.version }
