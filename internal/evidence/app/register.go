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

// ContentFiledElsewhereError refuses a filing whose byte-identical content is already
// filed against a DIFFERENT release. D3 holds — one observation, one record — but the
// refusal must be LOUD: silently returning the existing id left the new release with no
// evidence and nobody told (measured live 2026-08-19, the fix-verification candidate).
// Same-release re-uploads still dedup benignly.
type ContentFiledElsewhereError struct {
	EvidenceID string // the existing record the content resolves to
	ReleaseID  string // the release that record is filed against
}

func (e *ContentFiledElsewhereError) Error() string {
	return "evidence: byte-identical content is already filed against release " + e.ReleaseID +
		" (evidence " + e.EvidenceID + ") — this release received nothing; a new build needs its own document"
}

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
	// report surfaces parse outcomes (EDR-IDENTITY-01 D6). Optional; nil = no reporting.
	report ParseReporter
}

// NewEvidenceService wires the use-case ports.
// ParseReporter receives the outcome of one SBOM parse (EDR-IDENTITY-01 D6): how many
// components reached the inventory, and every warning the parser raised — chiefly the entries a
// document named but did not identify.
//
// It exists because the app ring never logs and those warnings were being thrown away at the
// call site. A component that never reaches the inventory can never be correlated, so a silent
// drop is a false negative manufactured by a parse rule.
type ParseReporter interface {
	Parsed(format string, components int, warnings []string)
}

// WithParseReporter wires the parse-outcome reporter. Optional; nil = no reporting, which keeps
// every existing caller and test unaffected.
func (s *EvidenceService) WithParseReporter(r ParseReporter) *EvidenceService {
	s.report = r
	return s
}

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
	//
	// The parser's warnings were DISCARDED here (`_`), which is what made a dropped component
	// silent: the parser was honest, the caller was not. Measured 2026-09-16 — a document
	// carrying the same httpd package twice lost the unidentified entry and its edges, and
	// nothing anywhere said so. The same shape as KN-SCAN-OBS-1, one ring further out.
	inv := domain.NewInventory(nil, nil)
	if cmd.Kind == domain.KindSBOM {
		parsed, warnings, perr := s.parser.Parse(ctx, cmd.Format, cmd.SpecVersion, cmd.Raw)
		if perr != nil {
			return RegisterResult{}, perr
		}
		inv = parsed
		// Reported on EVERY parse including a clean one (EDR-IDENTITY-01 D6): "nothing
		// unresolved" and "the parser stopped checking" must not look alike. The app ring never
		// logs (CONVENTIONS R1), so the warnings leave through a port an adapter owns.
		if s.report != nil {
			s.report.Parsed(cmd.Format, len(inv.Components()), warnings)
		}
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
