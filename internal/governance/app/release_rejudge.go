package app

import (
	"context"
	"fmt"
)

// UndecidedFaultlineByReleaseLister names the Faultlines of one release that still have an
// undecided Finding — the cards a new release must be judged against (VEX-RAISE-2).
type UndecidedFaultlineByReleaseLister interface {
	UndecidedFaultlinesByRelease(ctx context.Context, releaseID string) ([]string, error)
}

// ReleaseRejudgeResult counts what one release's judgement did.
type ReleaseRejudgeResult struct {
	Faultlines   int
	Raised       int // version-range proposals
	VendorRaised int // vendor-statement proposals (not_affected / accepted_risk)
}

// ReleaseRejudge judges a release's open Findings against their cards as soon as the release's
// correlation completes (VEX-RAISE-2, 2026-10-17). Until now a Finding born AFTER its card was
// enriched got no version-range verdict and no vendor proposal until the next enrichment of that
// CVE — or until an operator ran the one-time re-judge pass. Measured 2026-10-14: 174 open
// compat-libtiff3 Findings, 3 of them real gaps, and every new release depending on the pass.
//
// It is the same rules — RejudgeVersionRange and RejudgeApplicability, idempotent through their
// proposal ids — run per release on the release-evaluation worker, where a Knowledge read may fail
// without stalling the pipeline (EDR-DELIVERY-01 N-M2b: a failure defers the row and retries).
// The one-time pass remains for the catch-up after an UPGRADE that changed a rule.
type ReleaseRejudge struct {
	svc       *FindingService
	undecided UndecidedFaultlineByReleaseLister
	knowledge FaultlineKnowledgeReader
}

// NewReleaseRejudge builds the per-release judgement over the write service, the lister and the
// Knowledge read seam.
func NewReleaseRejudge(svc *FindingService, undecided UndecidedFaultlineByReleaseLister, knowledge FaultlineKnowledgeReader) *ReleaseRejudge {
	return &ReleaseRejudge{svc: svc, undecided: undecided, knowledge: knowledge}
}

// ForRelease judges every open Finding of one release. A card that cannot be read is an error —
// the caller defers and retries — because "no proposal" and "could not look" must not read alike
// on a release's first evaluation.
func (r *ReleaseRejudge) ForRelease(ctx context.Context, releaseID string) (ReleaseRejudgeResult, error) {
	var res ReleaseRejudgeResult
	fls, err := r.undecided.UndecidedFaultlinesByRelease(ctx, releaseID)
	if err != nil {
		return res, fmt.Errorf("list undecided faultlines of %s: %w", releaseID, err)
	}
	for _, fl := range fls {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		k, err := r.knowledge.GetFaultline(ctx, fl)
		if err != nil {
			return res, fmt.Errorf("read card %s: %w", fl, err)
		}
		res.Faultlines++
		n, err := r.svc.RejudgeVersionRange(ctx, fl, k.AffectedRanges, k.RangeTrust, k.RangeStatements...)
		if err != nil {
			return res, fmt.Errorf("version range %s: %w", fl, err)
		}
		res.Raised += n
		v, err := r.svc.RejudgeApplicability(ctx, fl, k.Applicabilities)
		if err != nil {
			return res, fmt.Errorf("vendor statements %s: %w", fl, err)
		}
		res.VendorRaised += v
	}
	return res, nil
}
