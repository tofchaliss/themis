package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

// Owner-set severity (EDR-SCORING-01 section 7.1, OS1-OS4). A named person sets the severity
// that counts for one Finding, and may apply the same to the Findings of the same CVE they pick
// in the same product. The original score is never changed; the record is append-only.

var (
	// ErrSeverityTargetInvalid is returned when a picked Finding is not another Finding of the
	// same CVE in the same product.
	ErrSeverityTargetInvalid = errors.New("governance: a severity target must be another Finding of the same CVE in the same product")
	// ErrSeverityTargetsUnavailable is returned when the releases of the product cannot be
	// listed (no Registry seam).
	ErrSeverityTargetsUnavailable = errors.New("governance: the releases of the product cannot be listed (no Registry seam)")
	// ErrNoOwnerSeverity is returned when there is no owner-set severity to remove.
	ErrNoOwnerSeverity = errors.New("governance: this Finding has no owner-set severity")
)

// OriginalSeverity is what the sources say about one Finding: the original score and the vector
// Themis selected for it. Either may be missing.
type OriginalSeverity struct {
	Score  *float64
	Vector string
}

// OwnerSeverityRecord is one row of the history: the severity, and how it ended (if it did).
type OwnerSeverityRecord struct {
	domain.OwnerSeverity
	// EndedAt is zero while the severity is in force. EndCause is "replaced" or "removed".
	EndedAt  time.Time
	EndedBy  string
	EndCause string
}

// OwnerSeverityWrite is one Finding's new owner-set severity.
type OwnerSeverityWrite struct {
	FindingID domain.FindingID
	Severity  domain.OwnerSeverity
}

// OwnerSeverityStore keeps the records. SaveOwnerSeverities ends the severity in force on each
// Finding (cause "replaced") and records the new one, all in one transaction: either every
// picked Finding has the new severity or none has.
type OwnerSeverityStore interface {
	CurrentOwnerSeverities(ctx context.Context, ids []domain.FindingID) (map[domain.FindingID]domain.OwnerSeverity, error)
	OwnerSeverityHistory(ctx context.Context, id domain.FindingID) ([]OwnerSeverityRecord, error)
	OriginalSeverities(ctx context.Context, ids []domain.FindingID) (map[domain.FindingID]OriginalSeverity, error)
	SaveOwnerSeverities(ctx context.Context, writes []OwnerSeverityWrite) error
	// EndOwnerSeverity ends the severity in force (cause "removed"); false when there was none.
	EndOwnerSeverity(ctx context.Context, id domain.FindingID, actorID string, at time.Time) (bool, error)
}

// SeverityCandidates lists every other Finding of the same CVE in the same product
// (ScopePropagation.CopyCandidates: the list of EDR-SYNC-01 D10).
type SeverityCandidates interface {
	CopyCandidates(ctx context.Context, sourceID domain.FindingID) ([]CopyCandidate, error)
}

// SeverityView is one Finding's severity as a person reads it.
type SeverityView struct {
	FindingID domain.FindingID
	CVE       string
	Original  OriginalSeverity
	Owner     *domain.OwnerSeverity
	History   []OwnerSeverityRecord
}

// SeverityTarget is one row of the pick list: where the Finding lives and the owner-set
// severity it carries now (which a pick would replace).
type SeverityTarget struct {
	ScopeTarget
	Owner *domain.OwnerSeverity
}

// SetSeverityInput is one request to set a severity: exactly one of Level and Vector.
type SetSeverityInput struct {
	Level, Vector, Reason string
	Actor                 domain.Actor
	// ApplyTo are the other Findings the person picked (OS3).
	ApplyTo []domain.FindingID
}

// SetSeverityResult counts what one request did.
type SetSeverityResult struct {
	// Applied is how many Findings got the severity (the Finding itself included); Replaced how
	// many of them already had one.
	Applied, Replaced int
}

// SeverityService sets, removes and reads owner-set severities.
type SeverityService struct {
	findings   FindingLoader
	store      OwnerSeverityStore
	candidates SeverityCandidates
	clock      Clock
}

// NewSeverityService builds the service. candidates may be nil (no Registry seam): a severity
// can still be set on the Finding itself, and the pick list is unavailable.
func NewSeverityService(findings FindingLoader, store OwnerSeverityStore, candidates SeverityCandidates, clock Clock) *SeverityService {
	return &SeverityService{findings: findings, store: store, candidates: candidates, clock: clock}
}

// View reads one Finding's original severity, the owner-set one in force, and the history.
func (s *SeverityService) View(ctx context.Context, id domain.FindingID) (SeverityView, error) {
	f, err := s.findings.GetByID(ctx, id)
	if err != nil {
		return SeverityView{}, err
	}
	originals, err := s.store.OriginalSeverities(ctx, []domain.FindingID{id})
	if err != nil {
		return SeverityView{}, err
	}
	history, err := s.store.OwnerSeverityHistory(ctx, id)
	if err != nil {
		return SeverityView{}, err
	}
	v := SeverityView{FindingID: id, CVE: f.CVE(), Original: originals[id], History: history}
	for i := range history {
		if history[i].EndedAt.IsZero() {
			cur := history[i].OwnerSeverity
			v.Owner = &cur
		}
	}
	return v, nil
}

// Preview computes what the given level or vector would give on this Finding, and records
// nothing.
func (s *SeverityService) Preview(ctx context.Context, id domain.FindingID, level, vector string) (domain.OwnerSeverity, error) {
	if _, err := s.findings.GetByID(ctx, id); err != nil {
		return domain.OwnerSeverity{}, err
	}
	originals, err := s.store.OriginalSeverities(ctx, []domain.FindingID{id})
	if err != nil {
		return domain.OwnerSeverity{}, err
	}
	return domain.ComputeOwnerScore(level, vector, originals[id].Score)
}

// Targets lists every other Finding of the same CVE in the same product, with the owner-set
// severity each carries now.
func (s *SeverityService) Targets(ctx context.Context, id domain.FindingID) ([]SeverityTarget, error) {
	if s.candidates == nil {
		return nil, ErrSeverityTargetsUnavailable
	}
	candidates, err := s.candidates.CopyCandidates(ctx, id)
	if err != nil {
		return nil, err
	}
	ids := make([]domain.FindingID, 0, len(candidates))
	for _, c := range candidates {
		ids = append(ids, c.FindingID)
	}
	current, err := s.store.CurrentOwnerSeverities(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]SeverityTarget, 0, len(candidates))
	for _, c := range candidates {
		t := SeverityTarget{ScopeTarget: c.ScopeTarget}
		if o, ok := current[c.FindingID]; ok {
			t.Owner = &o
		}
		out = append(out, t)
	}
	return out, nil
}

// Set records the severity on the Finding and on every picked Finding. Every pick is checked
// first (same CVE, same product); one bad pick refuses the whole request and nothing is
// recorded. A level is computed for each Finding from its own original score.
func (s *SeverityService) Set(ctx context.Context, id domain.FindingID, in SetSeverityInput) (SetSeverityResult, error) {
	if _, err := s.findings.GetByID(ctx, id); err != nil {
		return SetSeverityResult{}, err
	}
	picks, err := s.checkedPicks(ctx, id, in.ApplyTo)
	if err != nil {
		return SetSeverityResult{}, err
	}
	all := append([]domain.FindingID{id}, picks...)
	originals, err := s.store.OriginalSeverities(ctx, all)
	if err != nil {
		return SetSeverityResult{}, err
	}
	own, err := domain.NewOwnerSeverity(in.Level, in.Vector, originals[id].Score, in.Reason, in.Actor, s.clock.Now())
	if err != nil {
		return SetSeverityResult{}, err
	}
	current, err := s.store.CurrentOwnerSeverities(ctx, all)
	if err != nil {
		return SetSeverityResult{}, err
	}
	writes := []OwnerSeverityWrite{{FindingID: id, Severity: own}}
	for _, pick := range picks {
		writes = append(writes, OwnerSeverityWrite{FindingID: pick, Severity: own.For(id, originals[pick].Score)})
	}
	if err := s.store.SaveOwnerSeverities(ctx, writes); err != nil {
		return SetSeverityResult{}, err
	}
	return SetSeverityResult{Applied: len(writes), Replaced: len(current)}, nil
}

// checkedPicks returns the picked Findings without repeats, after checking each one.
func (s *SeverityService) checkedPicks(ctx context.Context, id domain.FindingID, picked []domain.FindingID) ([]domain.FindingID, error) {
	if len(picked) == 0 {
		return nil, nil
	}
	if s.candidates == nil {
		return nil, ErrSeverityTargetsUnavailable
	}
	candidates, err := s.candidates.CopyCandidates(ctx, id)
	if err != nil {
		return nil, err
	}
	allowed := map[domain.FindingID]bool{}
	for _, c := range candidates {
		allowed[c.FindingID] = true
	}
	seen := map[domain.FindingID]bool{}
	var out []domain.FindingID
	for _, p := range picked {
		if !allowed[p] {
			return nil, fmt.Errorf("%w: %s", ErrSeverityTargetInvalid, p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// Remove ends the owner-set severity of one Finding: the original counts again and the history
// stays. Only a named person removes it.
func (s *SeverityService) Remove(ctx context.Context, id domain.FindingID, actor domain.Actor) error {
	if actor.Kind != domain.ActorHuman || actor.ID == "" {
		return domain.ErrOwnerSeverityActor
	}
	if _, err := s.findings.GetByID(ctx, id); err != nil {
		return err
	}
	ended, err := s.store.EndOwnerSeverity(ctx, id, actor.ID, s.clock.Now().UTC())
	if err != nil {
		return err
	}
	if !ended {
		return ErrNoOwnerSeverity
	}
	return nil
}
