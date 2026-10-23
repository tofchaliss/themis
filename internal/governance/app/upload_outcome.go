package app

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

// The upload outcome (EDR-REMEDIATION-01 D3): the worker reads this SBOM's inventory and the
// previous one's from Evidence and buckets the Release's Findings. Read-only on both sides.

// SBOMRef is one SBOM filed against a Release.
type SBOMRef struct {
	ID      string
	FiledAt time.Time
}

// UploadEvidence is the Evidence read seam the outcome needs.
type UploadEvidence interface {
	// SBOMsOfRelease lists the SBOM-kind evidence filed against a Release.
	SBOMsOfRelease(ctx context.Context, releaseID string) ([]SBOMRef, error)
	// InventoryPURLs returns the purls of one evidence document's canonical inventory.
	InventoryPURLs(ctx context.Context, evidenceID string) (map[string]bool, error)
}

// UploadFindingsReader reads a Release's Findings as the classifier needs them.
type UploadFindingsReader interface {
	UploadFindings(ctx context.Context, releaseID string) ([]domain.UploadFinding, error)
}

// ErrSBOMNotListed: the evaluated SBOM is not among the Release's SBOMs, so no baseline can be
// chosen and no outcome is stated.
var ErrSBOMNotListed = errors.New("governance: the evaluated SBOM is not listed for its release")

// UploadPresenceRecorder keeps each Finding's "no longer present since" mark (D6): set on the
// first evaluated SBOM that does not carry an open Finding, cleared when one carries it again.
// A projection column, never a decision.
type UploadPresenceRecorder interface {
	RecordPresence(ctx context.Context, gone, present []domain.FindingID, at time.Time) error
}

// UploadOutcomes computes the four buckets for one (Release, SBOM).
type UploadOutcomes struct {
	evidence UploadEvidence
	findings UploadFindingsReader
	presence UploadPresenceRecorder // may be nil: no presence marks kept
	clock    Clock
}

// WithPresence keeps the presence marks the time-to-remediation measure needs (D6).
func (u *UploadOutcomes) WithPresence(p UploadPresenceRecorder, clock Clock) *UploadOutcomes {
	u.presence, u.clock = p, clock
	return u
}

// NewUploadOutcomes wires the outcome over the Evidence seam and the Finding reader.
func NewUploadOutcomes(ev UploadEvidence, f UploadFindingsReader) *UploadOutcomes {
	return &UploadOutcomes{evidence: ev, findings: f}
}

// previousSBOM is the SBOM filed immediately before id on the Release, by filing order with the
// id as tie-break (the same rule Communication's loop uses — N-M2e).
func previousSBOM(refs []SBOMRef, id string) (SBOMRef, bool, error) {
	sort.SliceStable(refs, func(i, j int) bool {
		if !refs[i].FiledAt.Equal(refs[j].FiledAt) {
			return refs[i].FiledAt.Before(refs[j].FiledAt)
		}
		return refs[i].ID < refs[j].ID
	})
	for i, r := range refs {
		if r.ID == id {
			if i == 0 {
				return SBOMRef{}, false, nil
			}
			return refs[i-1], true, nil
		}
	}
	return SBOMRef{}, false, ErrSBOMNotListed
}

// For computes the outcome of sbomID on releaseID.
func (u *UploadOutcomes) For(ctx context.Context, releaseID, sbomID string) (domain.UploadOutcome, error) {
	refs, err := u.evidence.SBOMsOfRelease(ctx, releaseID)
	if err != nil {
		return domain.UploadOutcome{}, err
	}
	prevRef, hasPrev, err := previousSBOM(refs, sbomID)
	if err != nil {
		return domain.UploadOutcome{}, err
	}
	current, err := u.evidence.InventoryPURLs(ctx, sbomID)
	if err != nil {
		return domain.UploadOutcome{}, err
	}
	var baseline *domain.UploadBaseline
	if hasPrev {
		purls, err := u.evidence.InventoryPURLs(ctx, prevRef.ID)
		if err != nil {
			return domain.UploadOutcome{}, err
		}
		baseline = &domain.UploadBaseline{PURLs: purls, FiledAt: prevRef.FiledAt}
	}
	fs, err := u.findings.UploadFindings(ctx, releaseID)
	if err != nil {
		return domain.UploadOutcome{}, err
	}
	out := domain.ClassifyUpload(fs, current, baseline)
	if u.presence != nil {
		if err := u.presence.RecordPresence(ctx, out.GoneIDs, out.PresentIDs, u.clock.Now()); err != nil {
			return domain.UploadOutcome{}, err
		}
	}
	return out, nil
}

// UploadOutcomeRecord is the latest stated outcome of a Release, as published.
type UploadOutcomeRecord struct {
	SBOMID      string
	EvaluatedAt time.Time
	Outcome     domain.UploadOutcome
}

// UploadOutcomeReader reads the latest published upload outcome for a Release from the
// release-evaluated feed (no new table: the outcome is stored with the event).
type UploadOutcomeReader interface {
	LatestUploadOutcome(ctx context.Context, releaseID string) (UploadOutcomeRecord, bool, error)
}

// WithUploadOutcomeReader attaches the reader behind GET /releases/{id}/upload-outcome.
func (s *ReadService) WithUploadOutcomeReader(r UploadOutcomeReader) *ReadService {
	s.outcomes = r
	return s
}

// LatestUploadOutcome serves what the Release's most recent new SBOM changed; found=false when
// no outcome has been stated yet. An unwired reader refuses (ErrEventFeedUnavailable) rather
// than answering "none".
func (s *ReadService) LatestUploadOutcome(ctx context.Context, releaseID string) (UploadOutcomeRecord, bool, error) {
	if s.outcomes == nil {
		return UploadOutcomeRecord{}, false, ErrEventFeedUnavailable
	}
	return s.outcomes.LatestUploadOutcome(ctx, releaseID)
}
