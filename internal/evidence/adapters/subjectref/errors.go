package subjectref

import "errors"

// ErrAmbiguousName reports that a name lookup on the [Registry] seam matched MORE THAN
// ONE row, so the registry abstained rather than picking a winner (EDR-INTAKE-01
// amendment B4).
//
// It is owned by THIS context. The registry has a sentinel of its own, and the
// composition root translates one into the other, because an error value is part of a
// package's surface: letting the registry's cross the seam would be a cross-context
// import wearing a different hat, and it would make every consumer of this seam depend
// on the registry to say what "ambiguous" means. The seam carries primitives, and this
// is the one error value it carries.
var ErrAmbiguousName = errors.New("subjectref: ambiguous name")
