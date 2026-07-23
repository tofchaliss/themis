package domain

import "errors"

// Domain sentinel errors. The app ring may test with errors.Is to map to transport
// responses; messages never leak into API bodies (error-UX envelope).
var (
	errEmptyPublicationID = errors.New("communication: empty publication id")
	errUnknownArtifact    = errors.New("communication: unknown artifact type")
	errInvalidStance      = errors.New("communication: invalid stance")
	errEmptyFinding       = errors.New("communication: position snapshot missing finding id")
	errEmptyFormat        = errors.New("communication: empty serialization format")

	// ErrAlreadySuperseded is returned when superseding a Publication that already has a
	// successor (supersession links are set once — append-and-supersede, never mutate).
	ErrAlreadySuperseded = errors.New("communication: publication already superseded")
)
