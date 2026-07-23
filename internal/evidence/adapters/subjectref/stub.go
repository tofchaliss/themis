// Package subjectref provides an allow-set SubjectRefValidator for the Evidence
// context (EDR-KERNEL-01 D1/D2; EDR-EVIDENCE-01 D5). Production wires a
// registry-backed validator instead (registry.ReleaseExists — see cmd/evidence); the
// stub remains the dev/test path (fast, no registry DB), selected via
// THEMIS_EVIDENCE_KNOWN_RELEASES. The app depends only on the port, so the two are
// interchangeable.
package subjectref

import "context"

// Stub validates a Release against a static allow-set. An unknown Release is
// reported as non-existent (the Register use case then rejects it).
type Stub struct {
	known map[string]struct{}
}

// NewStub builds a stub that recognizes the given release ids.
func NewStub(releaseIDs ...string) *Stub {
	known := make(map[string]struct{}, len(releaseIDs))
	for _, id := range releaseIDs {
		known[id] = struct{}{}
	}
	return &Stub{known: known}
}

// ReleaseExists reports whether the release id is in the allow-set.
func (s *Stub) ReleaseExists(_ context.Context, releaseID string) (bool, error) {
	_, ok := s.known[releaseID]
	return ok, nil
}
