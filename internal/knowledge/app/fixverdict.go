package app

import (
	"context"
	"errors"
	"strings"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// The release fix-verdict read (EDR-REBUILD-01 D19, D30): for every live occurrence of one
// release, whether a published fix exists that the install has not picked up. It serves the
// RECORDED verdict — the state and the bounds the occurrence was judged behind — so that a
// consumer in another context never orders version strings itself. Nothing is judged here and
// nothing is written.

// ErrFixVerdictsUnavailable is returned when no lister is wired.
var ErrFixVerdictsUnavailable = errors.New("the fix-verdict read is not available on this node")

// ErrInvalidRelease is returned for a blank release id.
var ErrInvalidRelease = errors.New("a release id is required")

// MatchVerdict is one live (not retired) match row with its recorded verdict.
type MatchVerdict struct {
	FaultlineID string
	CVE         string
	PURL        string
	Version     string
	Ecosystem   string
	State       domain.VerdictState
	Behind      []string
}

// FixVerdict is a MatchVerdict with its fix standing derived.
type FixVerdict struct {
	MatchVerdict
	Fix domain.FixStanding
}

// FixVerdictLister is the store port: the live match rows of one release.
type FixVerdictLister interface {
	ReleaseMatchVerdicts(ctx context.Context, releaseID string) ([]MatchVerdict, error)
}

// WithFixVerdicts attaches the lister.
func (s *ReadService) WithFixVerdicts(l FixVerdictLister) *ReadService {
	s.fixVerdicts = l
	return s
}

// ReleaseFixVerdicts returns the fix standing of every live occurrence of a release, in the
// store's order (card, then purl). A release Knowledge holds no match for is an empty list.
func (s *ReadService) ReleaseFixVerdicts(ctx context.Context, releaseID string) ([]FixVerdict, error) {
	releaseID = strings.TrimSpace(releaseID)
	if releaseID == "" {
		return nil, ErrInvalidRelease
	}
	if s.fixVerdicts == nil {
		return nil, ErrFixVerdictsUnavailable
	}
	rows, err := s.fixVerdicts.ReleaseMatchVerdicts(ctx, releaseID)
	if err != nil {
		return nil, err
	}
	out := make([]FixVerdict, 0, len(rows))
	for _, r := range rows {
		fix := domain.FixStandingOf(r.State, r.Ecosystem, r.Version, r.Behind)
		// A fix that lives only in another module stream is not one a rebuild picks up
		// (KN-BEHIND-MODULE-1). Derived here from the recorded bounds, so no stored row changes.
		if fix == domain.FixKnown && value.ClassifyEcosystem(r.Ecosystem) == value.VersionClassRPM &&
			boundsOnlyInAnotherStream(r.Version, r.Behind) {
			fix = domain.FixOtherStream
		}
		out = append(out, FixVerdict{MatchVerdict: r, Fix: fix})
	}
	return out, nil
}
