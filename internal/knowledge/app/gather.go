package app

import (
	"context"
	"fmt"

	"github.com/themis-project/themis/internal/kernel/value"
)

// GatherSource is one named per-CVE source the on-demand gather may consult — the same
// CVEVulnSource shape the backfill sweep uses, so a source serves both without knowing which
// asked.
type GatherSource struct {
	Name string
	Src  CVEVulnSource
}

// SourceGather is one source's outcome for one gathered CVE.
type SourceGather struct {
	Source    string
	Found     bool
	Recorded  bool // a NEW Proposal folded (a restatement is dropped by the aggregate and reads false)
	Withdrawn bool
	Err       string // per-source failure, reported not fatal — one dead feed must not void the gather
}

// GatherResult is the on-demand gather's complete answer.
type GatherResult struct {
	CVE         string
	FaultlineID string // set when a card exists after the gather (found or pre-existing fold)
	Sources     []SourceGather
}

// ErrInvalidCVE reports a gather request whose id is not a CVE.
var ErrInvalidCVE = fmt.Errorf("knowledge: not a valid CVE id")

// GatherService is the ON-DEMAND half of G-AI-1: "the AI asks, the feeds gather" — realized
// first as an explicit, operator-triggered fetch of ONE brand-new CVE's facts through the same
// per-CVE sources and fold path the scheduled sweeps use.
//
// The boundary it keeps is Domain Invariant 3 ("Gathering Is Not Knowing"): what a source
// returns lands as ordinary source Proposals, reconciled by the same precedence as any feed —
// gathering on demand changes WHEN facts arrive, never WHO decides what they mean. And unlike
// the scheduled sweeps, which are opt-in because a silent outbound call is a policy decision,
// this fires only on an explicit authenticated POST: the operator IS the opt-in.
//
// The other half of G-AI-1 — the AI automatically emitting "need more data on CVE-X" and this
// endpoint consuming it — is the Δ4-class push seam and stays deferred; a human (or script)
// reading an `insufficient` with a thin-grounding detail is the loop until then.
type GatherService struct {
	sources []GatherSource
	fold    *FaultlineService
}

// NewGatherService wires the on-demand gather. No sources means the endpoint honestly refuses
// rather than pretending to have looked.
func NewGatherService(fold *FaultlineService, sources ...GatherSource) *GatherService {
	return &GatherService{sources: sources, fold: fold}
}

// Enabled reports whether any source is wired.
func (s *GatherService) Enabled() bool { return s != nil && len(s.sources) > 0 }

// GatherCVE consults every wired source for one CVE and folds what they return. Per-source
// failures are reported, not fatal; a store failure is fatal (the gather cannot claim to have
// recorded what it could not).
func (s *GatherService) GatherCVE(ctx context.Context, raw string) (GatherResult, error) {
	cve, err := value.NewCVEID(raw)
	if err != nil {
		return GatherResult{}, fmt.Errorf("%w: %q", ErrInvalidCVE, raw)
	}
	out := GatherResult{CVE: cve.String()}
	for _, src := range s.sources {
		sg := SourceGather{Source: src.Name}
		facts, ferr := src.Src.VulnsForCVE(ctx, cve)
		if ferr != nil {
			sg.Err = ferr.Error()
			out.Sources = append(out.Sources, sg)
			continue
		}
		// Withdrawal first, as everywhere: a rejected CVE is retired, not enriched.
		if facts.Withdrawn {
			sg.Withdrawn = true
			if _, serr := s.fold.SupersedeFaultline(ctx, cve, src.Name); serr != nil {
				return out, serr
			}
			out.Sources = append(out.Sources, sg)
			continue
		}
		if !facts.Found {
			out.Sources = append(out.Sources, sg)
			continue
		}
		sg.Found = true
		f, recorded, serr := s.fold.FoldProposal(ctx, facts.Proposal.CVE, facts.Proposal.Proposal)
		if serr != nil {
			return out, serr
		}
		sg.Recorded = recorded
		out.FaultlineID = string(f.ID())
		out.Sources = append(out.Sources, sg)
	}
	return out, nil
}
