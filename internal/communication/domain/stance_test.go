package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/communication/domain"
)

func TestStanceValid(t *testing.T) {
	for _, s := range []domain.Stance{
		domain.StanceAffected, domain.StanceNotAffected, domain.StanceUnderInvestigation,
		domain.StanceMitigated, domain.StanceAcceptedRisk, domain.StanceDeferred,
	} {
		if !s.Valid() {
			t.Errorf("%q should be valid", s)
		}
	}
	if domain.Stance("bogus").Valid() {
		t.Error("unknown stance should be invalid")
	}
}

func TestStancePhrase(t *testing.T) {
	cases := map[domain.Stance]string{
		domain.StanceAffected:           "affected",
		domain.StanceNotAffected:        "not affected",
		domain.StanceUnderInvestigation: "under investigation",
		domain.StanceMitigated:          "mitigated",
		domain.StanceAcceptedRisk:       "affected — risk accepted",
		domain.StanceDeferred:           "deferred",
		domain.Stance("weird"):          "weird", // default → verbatim
	}
	for s, want := range cases {
		if got := s.Phrase(); got != want {
			t.Errorf("%q.Phrase() = %q, want %q", s, got, want)
		}
	}
}

func TestStanceVEXStatus(t *testing.T) {
	cases := map[domain.Stance]string{
		domain.StanceNotAffected:        "not_affected",
		domain.StanceMitigated:          "fixed",
		domain.StanceUnderInvestigation: "under_investigation",
		domain.StanceDeferred:           "under_investigation",
		domain.StanceAffected:           "affected",
		domain.StanceAcceptedRisk:       "affected",
	}
	for s, want := range cases {
		if got := s.VEXStatus(); got != want {
			t.Errorf("%q.VEXStatus() = %q, want %q", s, got, want)
		}
	}
}
