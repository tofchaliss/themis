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

// The name half of the [Registry] seam. A stub knows release IDS and nothing else,
// so every name lookup finds nothing — and says so honestly, as an empty id rather
// than as an error. The consequence is deliberate and visible: on a dev estate the
// {product, project, version} road reports `unknown_release`, which is exactly what
// it is without a registry, instead of resolving onto whichever release happened to
// be in the allow-set.

// ProductIDByName finds nothing: the stub holds no names.
func (s *Stub) ProductIDByName(context.Context, string) (string, error) { return "", nil }

// ProjectIDByName finds nothing: the stub holds no names.
func (s *Stub) ProjectIDByName(context.Context, string, string) (string, error) { return "", nil }

// ReleaseIDByVersion finds nothing: the stub holds no names.
func (s *Stub) ReleaseIDByVersion(context.Context, string, string) (string, error) { return "", nil }

// ProductOfRelease finds nothing: the stub holds release ids, not the estate graph
// above them. The consequence is deliberate and FAIL-CLOSED — on a node wired with
// the stub, a `product:<id>` key is refused even for a release in the allow-set,
// because the stub cannot establish who owns it, and an unverifiable confinement is
// not a confinement (EDR-INTAKE-01 B7). An `admin` key and an auth-disabled node are
// unaffected: neither asks this question.
func (s *Stub) ProductOfRelease(context.Context, string) (string, error) { return "", nil }
