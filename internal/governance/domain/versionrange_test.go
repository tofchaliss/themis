package domain_test

import (
	"github.com/themis-project/themis/internal/kernel/value"
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

// KN-RANGE-ECO-1: with statements on the card, a component is judged against its own world's
// ranges. A foreign product's range neither holds nor clears it; a card that speaks only about
// other worlds leaves the verdict undecidable; a world-less statement applies to everything.
func TestProvablyOutOfRange_JudgesAComponentAgainstItsOwnWorld(t *testing.T) {
	stdlib := domain.MatchedComponent{PURL: "pkg:golang/stdlib@1.27.1", Name: "stdlib", Version: "go1.27.1", Ecosystem: "golang"}
	flat := []string{"<1.13.2", "<21.1.1.1.0"}
	goStmt := value.RangeStatement{Ecosystem: "go", Package: "stdlib", Range: "<1.13.2"}
	oracle := value.RangeStatement{Ecosystem: "oracle", Package: "weblogic", Range: "<21.1.1.1.0"}
	if domain.ProvablyOutOfRange([]domain.MatchedComponent{stdlib}, flat) {
		t.Fatal("the flat union must still hold the component (the measured defect)")
	}
	if !domain.ProvablyOutOfRange([]domain.MatchedComponent{stdlib}, flat, goStmt, oracle) {
		t.Fatal("judged against the Go statement, go1.27.1 is provably out of range")
	}
	if domain.ProvablyOutOfRange([]domain.MatchedComponent{stdlib}, []string{"<21.1.1.1.0"}, oracle) {
		t.Fatal("a card that speaks only about Oracle must not clear a Go component")
	}
	// A flat range no statement accounts for came from a source that stated no world: it applies.
	if !domain.ProvablyOutOfRange([]domain.MatchedComponent{stdlib}, flat, oracle) {
		t.Fatal("the unstated Go range still applies and clears the component")
	}
	// NVD's CPE bound for another product: no ecosystem, but a named product that is not ours.
	cpe := value.RangeStatement{Package: "weblogic_server", Range: "<21.1.1.1.0"}
	if !domain.ProvablyOutOfRange([]domain.MatchedComponent{stdlib}, flat, goStmt, cpe) {
		t.Fatal("a world-less bound for another named product must not hold a Go component")
	}
	universal := value.RangeStatement{Range: "<21.1.1.1.0"}
	if domain.ProvablyOutOfRange([]domain.MatchedComponent{stdlib}, flat, goStmt, universal) {
		t.Fatal("a world-less range applies to everything and still holds the component")
	}
	// The purl name serves when the component carries no Name.
	nameless := domain.MatchedComponent{PURL: "pkg:golang/stdlib@1.27.1", Version: "go1.27.1", Ecosystem: "golang"}
	if !domain.ProvablyOutOfRange([]domain.MatchedComponent{nameless}, flat, goStmt, oracle) {
		t.Fatal("the purl's name must match the statement's package")
	}
	if domain.ProvablyOutOfRange([]domain.MatchedComponent{{PURL: "pkg:golang", Version: "go1.27.1", Ecosystem: "golang"}}, []string{"<21.1.1.1.0"}, oracle) {
		t.Fatal("a purl with no name segment yields no name, and the Oracle-only card stays undecidable")
	}
	if domain.ProvablyOutOfRange([]domain.MatchedComponent{{PURL: "stdlib", Version: "go1.27.1", Ecosystem: "golang"}}, []string{"<21.1.1.1.0"}, oracle) {
		t.Fatal("a non-purl identifier yields no purl name, and the Oracle-only card stays undecidable")
	}
}
