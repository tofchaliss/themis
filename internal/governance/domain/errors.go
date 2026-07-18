package domain

import "errors"

// Domain sentinel errors. Callers (the app ring) may test with errors.Is to map to
// transport-level responses; the messages never leak into API bodies (error-UX envelope).
var (
	errEmptyFindingID    = errors.New("governance: empty finding id")
	errEmptyReleaseID    = errors.New("governance: empty release id")
	errEmptyFaultlineID  = errors.New("governance: empty faultline id")
	errInvalidActorKind  = errors.New("governance: invalid actor kind")
	errEmptyActorID      = errors.New("governance: empty actor id")
	errEmptyProposalID   = errors.New("governance: empty proposal id")
	errInvalidStance     = errors.New("governance: invalid stance")
	errEmptyComponentURL = errors.New("governance: empty component purl")
	errZeroTime          = errors.New("governance: zero timestamp")

	// ErrProposalNotFound is returned when a decision names a proposal absent from the
	// Finding.
	ErrProposalNotFound = errors.New("governance: proposal not found")
	// ErrProposalNotOpen is returned when accepting/rejecting a proposal that has already
	// been decided (a proposal's status resolves exactly once), or when raising a proposal
	// that is not in the Proposed state.
	ErrProposalNotOpen = errors.New("governance: proposal already decided")
	// ErrDuplicateProposal is returned when raising a proposal whose id already exists on
	// the Finding (append-only, ids unique within a Finding — makes re-delivery idempotent).
	ErrDuplicateProposal = errors.New("governance: duplicate proposal id")
	// ErrIllegalTransition is returned when a lifecycle operation is not a legal governed
	// transition from the current stage (D7); Archived is terminal.
	ErrIllegalTransition = errors.New("governance: illegal lifecycle transition")
)
