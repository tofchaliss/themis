package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/themis-project/themis/internal/evidence/domain"
)

// ErrUnknownSubject is returned when the referenced Release does not exist.
var ErrUnknownSubject = errors.New("evidence: unknown subject release")

// ErrRejected is returned when the trust gate rejects the artifact.
var ErrRejected = errors.New("evidence: artifact rejected by trust gate")

// RegisterCommand is the input to Register.
type RegisterCommand struct {
	Raw              []byte
	Kind             domain.Kind
	Format           string // SBOM format (used only for the SBOM kind)
	SpecVersion      string
	SubjectReleaseID string
	ExpectedChecksum string
	Provenance       domain.Provenance
}

// RegisterResult is the outcome of Register.
type RegisterResult struct {
	ID      domain.EvidenceID
	Created bool
}

// EvidenceService orchestrates the Evidence use cases over its ports.
type EvidenceService struct {
	trust   TrustGate
	parser  Parser
	subject SubjectRefValidator
	repo    Repository
	ids     IDGenerator
	clock   Clock
}

// NewEvidenceService wires the use-case ports.
func NewEvidenceService(trust TrustGate, parser Parser, subject SubjectRefValidator, repo Repository, ids IDGenerator, clock Clock) *EvidenceService {
	return &EvidenceService{trust: trust, parser: parser, subject: subject, repo: repo, ids: ids, clock: clock}
}

// Register runs the Evidence intake — validate subject → trust-gate → parse →
// build aggregate → persist(+outbox) — terminating at persist + event (D1). It
// returns the stable Evidence id; a byte-identical re-upload returns the existing
// id with Created=false (D3).
func (s *EvidenceService) Register(ctx context.Context, cmd RegisterCommand) (RegisterResult, error) {
	// 1. The subject Release must exist; reject unknown (D5).
	ok, err := s.subject.ReleaseExists(ctx, cmd.SubjectReleaseID)
	if err != nil {
		return RegisterResult{}, err
	}
	if !ok {
		return RegisterResult{}, fmt.Errorf("%w: %q", ErrUnknownSubject, cmd.SubjectReleaseID)
	}

	// 2. Trust gate: fingerprint + validate (D2/D3).
	outcome, err := s.trust.Admit(TrustInput{
		Raw: cmd.Raw, Kind: cmd.Kind, ExpectedChecksum: cmd.ExpectedChecksum, Provenance: cmd.Provenance,
	})
	if err != nil {
		return RegisterResult{}, err
	}
	if outcome.Status != domain.TrustAccepted {
		return RegisterResult{}, fmt.Errorf("%w: %s", ErrRejected, outcome.Reason)
	}

	// 3. Parse an SBOM into the canonical inventory (D4); other kinds carry none.
	inv := domain.NewInventory(nil, nil)
	if cmd.Kind == domain.KindSBOM {
		parsed, _, perr := s.parser.Parse(ctx, cmd.Format, cmd.SpecVersion, cmd.Raw)
		if perr != nil {
			return RegisterResult{}, perr
		}
		inv = parsed
	}

	// 4. Build the immutable aggregate.
	e, err := domain.NewEvidence(s.ids.NewID(), cmd.Kind, outcome.Fingerprint,
		domain.SubjectRef{ReleaseID: cmd.SubjectReleaseID}, outcome.Provenance, outcome.Status, inv, s.clock.Now())
	if err != nil {
		return RegisterResult{}, err
	}

	// 5. Persist + emit EvidenceRegistered atomically (D6/D7).
	id, created, err := s.repo.Save(ctx, e, cmd.Raw, domain.NewEvidenceRegistered(e, s.clock.Now()))
	if err != nil {
		return RegisterResult{}, err
	}
	return RegisterResult{ID: id, Created: created}, nil
}
