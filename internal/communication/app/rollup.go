package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/themis-project/themis/internal/communication/domain"
)

// Release-scoped VEX rollup use cases (EDR-COMMUNICATION-01 D13, COMM-VEX-1). The whole
// document is a pure function over exactly two reads (D13.5): Governance's release posture
// (which carries stances, position versions, rationales and per-component verdicts) and
// Registry's name chain. Nothing here composes further reads.

// ErrIncompleteIdentity is the D13.4 fail-closed outcome: the Registry name chain could not
// be resolved, so no customer document is produced — a rollup whose product line is a UUID
// is not degraded, it is useless.
var ErrIncompleteIdentity = errors.New("communication: release identity unresolved — rollup refused (D13.4)")

// RollupComponentRow is one component of a posture row, with the occurrence-verdict fields
// the annotations are built from (EDR-VERDICT-01).
type RollupComponentRow struct {
	PURL          string
	ClaimClass    string
	VerdictState  string
	VerdictGrade  string
	VerdictReason string
}

// RollupPostureRow is one finding of the release posture — the app-local mirror of the
// fields the rollup consumes.
type RollupPostureRow struct {
	FindingID         string
	FaultlineID       string
	CVE               string
	HasPosition       bool
	Stance            string
	PositionVersion   int
	PositionRationale string
	Components        []RollupComponentRow
}

// ReleasePostureReader reads Governance's release posture (D13.5's first read).
type ReleasePostureReader interface {
	ReleasePosture(ctx context.Context, releaseID string) ([]RollupPostureRow, error)
}

// ReleaseIdentityReader resolves the Registry name chain (D13.5's second read). It returns
// ErrIncompleteIdentity (possibly wrapped) when any hop is missing — the caller never
// receives a partially named product.
type ReleaseIdentityReader interface {
	ReleaseIdentity(ctx context.Context, releaseID string) (domain.RollupProductRef, error)
}

// RollupStore persists rollup publications with the D5 append-and-supersede discipline.
type RollupStore interface {
	// CurrentRollup returns the latest non-superseded rollup for (release, format, audience);
	// found=false if none.
	CurrentRollup(ctx context.Context, releaseID, format, audience string) (domain.RollupPublication, bool, error)
	// SaveRollup records the new rollup and, when prior is non-nil, supersedes it
	// (version-guarded by priorPrevVersion → ErrConcurrent on mismatch) — atomically.
	SaveRollup(ctx context.Context, pub domain.RollupPublication, prior *domain.RollupPublication, priorPrevVersion int) error
	// GetRollup loads one rollup by id (domain.ErrRollupNotFound when missing).
	GetRollup(ctx context.Context, id domain.RollupPublicationID) (domain.RollupPublication, error)
	// ListRollups returns a release's rollups, newest first.
	ListRollups(ctx context.Context, releaseID string) ([]domain.RollupPublication, error)
}

// RollupSerializers renders a rollup artifact for a format (the serializer registry).
type RollupSerializers interface {
	RenderRollup(format string, art domain.RollupArtifact) ([]byte, error)
}

// RollupService orchestrates the rollup use cases. Human-triggered like every publication
// (D4); staleness is computed and surfaced, never auto-acted on (D13.2).
type RollupService struct {
	posture     ReleasePostureReader
	identity    ReleaseIdentityReader
	store       RollupStore
	serializers RollupSerializers
	ids         IDGenerator
	clock       Clock
}

// NewRollupService wires the rollup ports.
func NewRollupService(posture ReleasePostureReader, identity ReleaseIdentityReader, store RollupStore,
	serializers RollupSerializers, ids IDGenerator, clock Clock) *RollupService {
	return &RollupService{posture: posture, identity: identity, store: store, serializers: serializers, ids: ids, clock: clock}
}

// buildEntries turns posture rows into rollup entries: live carriers become subcomponents;
// cleared copies and scope-only membership become ANNOTATIONS (D13.1/D13.3). Pure.
func buildEntries(rows []RollupPostureRow) []domain.RollupEntry {
	out := make([]domain.RollupEntry, 0, len(rows))
	for _, r := range rows {
		e := domain.RollupEntry{
			FindingID: r.FindingID, FaultlineID: r.FaultlineID, CVE: r.CVE,
			HasPosition: r.HasPosition, Stance: domain.Stance(r.Stance),
			PositionVersion: r.PositionVersion, Rationale: r.PositionRationale,
		}
		scopeOnly := 0
		for _, c := range r.Components {
			switch {
			case c.VerdictState == "cleared_vendor_fix":
				note := c.PURL + " cleared by vendor fix"
				if c.VerdictGrade != "" {
					note += " (" + c.VerdictGrade + ")"
				}
				if c.VerdictReason != "" {
					note += ": " + c.VerdictReason
				}
				e.Annotations = append(e.Annotations, note)
			case c.ClaimClass == "scope":
				scopeOnly++
			default:
				e.OpenComponents = append(e.OpenComponents, c.PURL)
			}
		}
		if scopeOnly > 0 && len(e.OpenComponents) == 0 {
			// The whole finding is rebuild-set membership: say so, sized truthfully (D13.3) —
			// "under_investigation" alone would overstate what is believed.
			e.Annotations = append(e.Annotations,
				fmt.Sprintf("%d component(s) listed via a module-stream rebuild set only; no evidence any carries the flaw", scopeOnly))
		}
		out = append(out, e)
	}
	return out
}

// materialize runs the two reads and the pure transform — shared by publish and preview.
//
// Withdrawn-CVE exclusion (D13.3) is NOT implemented yet: the posture carries no withdrawal
// signal, so WithdrawnExcluded is always 0 and no finding is excluded. Recorded as a
// deviation in the change's tasks — the field and preamble slot are plumbed, the signal is a
// small Governance follow-up.
func (s *RollupService) materialize(ctx context.Context, releaseID string) (domain.RollupArtifact, []domain.RollupEntry, error) {
	rows, err := s.posture.ReleasePosture(ctx, releaseID)
	if err != nil {
		return domain.RollupArtifact{}, nil, err
	}
	product, err := s.identity.ReleaseIdentity(ctx, releaseID)
	if err != nil {
		return domain.RollupArtifact{}, nil, err
	}
	entries := buildEntries(rows)
	art, err := domain.MaterializeRollup(product, s.clock.Now(), entries, 0)
	if err != nil {
		return domain.RollupArtifact{}, nil, err
	}
	return art, entries, nil
}

// CreateRollup is the human-triggered publish (D4): two reads, one pure transform, one
// serialize, one atomic record-and-supersede (D5). Returns the new rollup's id.
func (s *RollupService) CreateRollup(ctx context.Context, releaseID, format, audience string) (domain.RollupPublicationID, error) {
	art, _, err := s.materialize(ctx, releaseID)
	if err != nil {
		return "", err
	}
	payload, err := s.serializers.RenderRollup(format, art)
	if err != nil {
		return "", err
	}
	for attempt := 0; attempt < maxSaveRetries; attempt++ {
		prior, hasPrior, err := s.store.CurrentRollup(ctx, releaseID, format, audience)
		if err != nil {
			return "", err
		}
		id := domain.RollupPublicationID(s.ids.NewID())
		var supersedes domain.RollupPublicationID
		if hasPrior {
			supersedes = prior.ID()
		}
		pub, err := domain.NewRollupPublication(id, art, format, audience, payload, supersedes, s.clock.Now())
		if err != nil {
			return "", err
		}
		var priorPtr *domain.RollupPublication
		priorPrev := 0
		if hasPrior {
			priorPrev = prior.Version()
			if err := prior.Supersede(id); err != nil {
				return "", err
			}
			priorPtr = &prior
		}
		switch err := s.store.SaveRollup(ctx, pub, priorPtr, priorPrev); {
		case err == nil:
			return id, nil
		case errors.Is(err, ErrConcurrent):
			continue // a concurrent republish superseded the prior first — reload and retry
		default:
			return "", err
		}
	}
	return "", ErrConcurrent
}

// PreviewRollup renders the document without recording anything (the D10 preview shape).
func (s *RollupService) PreviewRollup(ctx context.Context, releaseID, format string) ([]byte, error) {
	art, _, err := s.materialize(ctx, releaseID)
	if err != nil {
		return nil, err
	}
	return s.serializers.RenderRollup(format, art)
}

// RollupStatus is the worklist row (D13.2): the current rollup for the identity tuple and
// its computed drift against the live posture.
type RollupStatus struct {
	Found         bool
	PublicationID domain.RollupPublicationID
	AsOf          string // RFC3339; presentation-ready, computed in one place
	Statements    int
	Stale         bool
	Summary       string
	Drift         domain.RollupDrift
}

// Status computes the staleness row for (release, format, audience) — the same posture read
// a fresh rollup would use, diffed against the recorded input set, so drift zero means a
// republish would reproduce the recorded document's assertions.
func (s *RollupService) Status(ctx context.Context, releaseID, format, audience string) (RollupStatus, error) {
	current, found, err := s.store.CurrentRollup(ctx, releaseID, format, audience)
	if err != nil {
		return RollupStatus{}, err
	}
	if !found {
		return RollupStatus{Found: false, Summary: "no rollup published"}, nil
	}
	rows, err := s.posture.ReleasePosture(ctx, releaseID)
	if err != nil {
		return RollupStatus{}, err
	}
	drift := domain.ComputeRollupDrift(current.InputSet(), buildEntries(rows))
	return RollupStatus{
		Found:         true,
		PublicationID: current.ID(),
		AsOf:          current.AsOf().Format(rfc3339),
		Statements:    current.Statements(),
		Stale:         drift.Stale(),
		Summary:       drift.String(),
		Drift:         drift,
	}, nil
}

// GetRollup loads one recorded rollup (payload + meta).
func (s *RollupService) GetRollup(ctx context.Context, id domain.RollupPublicationID) (domain.RollupPublication, error) {
	return s.store.GetRollup(ctx, id)
}

// ListRollups lists a release's rollups, newest first.
func (s *RollupService) ListRollups(ctx context.Context, releaseID string) ([]domain.RollupPublication, error) {
	return s.store.ListRollups(ctx, releaseID)
}

const rfc3339 = "2006-01-02T15:04:05Z07:00"
