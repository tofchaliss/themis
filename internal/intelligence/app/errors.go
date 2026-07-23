package app

import "errors"

// ErrUnknownCapability is returned when a caller invokes an id not in the Registry —
// a client error (the caller asked for a capability that does not exist).
var ErrUnknownCapability = errors.New("intelligence: unknown capability")

// ErrIncompleteGrounding signals that Context Construction could not assemble the
// grounding a capability declared it needs (missing Finding/Faultline). The Gateway
// treats it as a graceful "no proposal" outcome (D13 disabled ≡ unavailable), never
// a hard failure of the pipeline.
var ErrIncompleteGrounding = errors.New("intelligence: incomplete grounding")
