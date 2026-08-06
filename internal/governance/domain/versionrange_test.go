package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/governance/domain"
)

func comp(purl, version, ecosystem string) domain.MatchedComponent {
	return domain.MatchedComponent{PURL: purl, Version: version, Ecosystem: ecosystem}
}

// The equivalence oracle: the same cases the Intelligence rule (internal/intelligence/
// domain/rule_test.go) is pinned to. Group 7 deletes that rule, so this is what carries its
// guarantee forward — if the two ever disagreed, a verdict the AI plane used to produce
// would silently stop being produced.
//
// One difference is deliberate and not a divergence: Intelligence parses purls to recover
// (ecosystem, version), so a malformed purl makes it defer. Governance's MatchedComponent
// already carries both as fields, parsed once at correlation, so those purl-shape cases
// cannot arise here. The behavioural rule is identical: decide not_affected only when EVERY
// component is provably out of range; defer on anything else.
func TestProvablyOutOfRange_MatchesTheIntelligenceRuleOracle(t *testing.T) {
	inRange := []string{">= 1.0, < 3.0"}

	cases := []struct {
		name       string
		components []domain.MatchedComponent
		ranges     []string
		want       bool
	}{
		// Defer cases, one per oracle entry.
		{"no reconciled range", []domain.MatchedComponent{comp("pkg:pypi/foo@2.0", "2.0", "pypi")}, nil, false},
		{"no matched components", nil, inRange, false},
		{"component carries no version", []domain.MatchedComponent{comp("pkg:apk/openssl", "", "apk")}, inRange, false},
		{"component in range", []domain.MatchedComponent{comp("pkg:pypi/foo@2.0", "2.0", "pypi")}, inRange, false},
		{"undecidable range", []domain.MatchedComponent{comp("pkg:pypi/foo@2.0", "2.0", "pypi")}, []string{"none"}, false},
		{
			"one out, one in → defer",
			[]domain.MatchedComponent{comp("pkg:pypi/foo@5.0", "5.0", "pypi"), comp("pkg:pypi/bar@2.0", "2.0", "pypi")},
			inRange, false,
		},
		// The one deciding case.
		{"every component provably out of range", []domain.MatchedComponent{comp("pkg:pypi/foo@5.0", "5.0", "pypi")}, inRange, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := domain.ProvablyOutOfRange(c.components, c.ranges); got != c.want {
				t.Fatalf("ProvablyOutOfRange = %v, want %v", got, c.want)
			}
		})
	}
}

// The precision requirement carried from EDR-TRUST-01 T5, and the reason the rule must see
// the RECONCILED range rather than a feed's query-time filter.
//
// Upstream flags every 1.1.1 build as vulnerable. Red Hat backported the fix into
// 1.1.1k-51.el8, so the reconciled range excludes that build. Handed the reconciled range,
// the rule correctly proves not-affected; handed the raw upstream range it would not — and
// the release would sit in a review queue over a vulnerability it does not have.
//
// The inverse matters more: a WRONG reconciled range here yields a silent, wrong
// not_affected. That is why this case is pinned rather than left to the general oracle.
func TestProvablyOutOfRange_ReconciledRangeCatchesADistroBackport(t *testing.T) {
	backported := comp("pkg:rpm/redhat/openssl@1.1.1k-51.el8", "1.1.1k-51.el8", "rpm")

	// The reconciled, backport-aware view: fixed at the distro build.
	if !domain.ProvablyOutOfRange([]domain.MatchedComponent{backported}, []string{"< 1.1.1k-51.el8"}) {
		t.Error("the reconciled range excludes this build — the rule must prove not-affected")
	}
	// The raw upstream view admits it, so the rule correctly declines to decide.
	if domain.ProvablyOutOfRange([]domain.MatchedComponent{backported}, []string{">= 1.1.1, < 1.1.2"}) {
		t.Error("an unreconciled range must NOT yield a not_affected verdict")
	}
}

// Certain in one direction only: being IN range is never this rule's verdict. A component
// squarely inside the affected range must defer, not decide "affected" — that judgment
// belongs to a human or the AI plane, never to arithmetic that only proves absence.
func TestProvablyOutOfRange_NeverDecidesAffected(t *testing.T) {
	if domain.ProvablyOutOfRange([]domain.MatchedComponent{comp("pkg:pypi/foo@2.0", "2.0", "pypi")}, []string{">= 1.0, < 3.0"}) {
		t.Error("an in-range component must defer; this rule only ever proves out-of-range")
	}
}
