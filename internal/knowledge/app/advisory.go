package app

import (
	"context"
	"errors"
	"strings"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

// The advisory read (EDR-INCIDENT-01 D2): which cards a vendor advisory id names. The alias is
// the `advisory` a `fixed` vendor statement carries (EDR-VEX-02 D14) — the Red Hat feed records
// it on the statement, and the reconciled view keeps it — so an advisory Themis has not seen on
// any card resolves to nothing, and a Watch says so rather than guessing.

// ErrAdvisoryUnavailable is returned when no lister is wired.
var ErrAdvisoryUnavailable = errors.New("advisory lookup is not available on this node")

// ErrInvalidAdvisory is returned for a blank id.
var ErrInvalidAdvisory = errors.New("an advisory id is required")

// AdvisoryLister is the store port: the cards whose statements carry the advisory.
type AdvisoryLister interface {
	FaultlinesByAdvisory(ctx context.Context, advisory string) ([]domain.Faultline, error)
}

// WithAdvisory attaches the lister.
func (s *ReadService) WithAdvisory(a AdvisoryLister) *ReadService {
	s.advisory = a
	return s
}

// ByAdvisory returns the cards an advisory id names, in CVE order; empty when none does. The
// id is matched upper-cased and trimmed, the way feeds record it.
func (s *ReadService) ByAdvisory(ctx context.Context, advisory string) ([]domain.Faultline, error) {
	advisory = strings.ToUpper(strings.TrimSpace(advisory))
	if advisory == "" {
		return nil, ErrInvalidAdvisory
	}
	if s.advisory == nil {
		return nil, ErrAdvisoryUnavailable
	}
	return s.advisory.FaultlinesByAdvisory(ctx, advisory)
}
