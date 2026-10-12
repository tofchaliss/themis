package app

import "errors"

// ErrAmbiguousName reports that an exact-name lookup matched MORE THAN ONE row, so the
// registry abstains instead of picking a winner (EDR-INTAKE-01 amendment B4).
//
// It is a statement about the NAME, not about the estate: the thing being looked up is
// registered — twice — and reporting that as "not registered" sends the operator hunting
// for a typo that is not there. Zero matches stays an empty id and a nil error, because
// "not found" is an answer and the two must not collapse into one.
//
// It lives in the application ring rather than beside the queries that return it because
// it is the registry's vocabulary for abstention: the store raises it, and a caller that
// reads it (the composition root wiring Evidence's read seam) translates it into its own
// context's sentinel rather than letting a registry error value cross the seam.
//
// The guard survives the uniqueness indexes migration 000003 adds — which make `>1`
// unreachable — on purpose: an un-migrated estate still has the old shape, and a guard
// that only holds because of an index is a guard that disappears with the index.
var ErrAmbiguousName = errors.New("registry: ambiguous name")
