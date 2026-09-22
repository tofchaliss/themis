package app_test

import (
	"context"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// The Attribution projection states BOTH SIDES of the carrier question (EDR-ATTRIBUTION-01 D10).
//
// The measured case it is built from: CVE-2026-33006 names carrier `http_server`, the release has
// `httpd` installed, every component is scope-class, and the drawer could say only "attribution
// gap" — because `carrier_products` did not cross the Knowledge→Governance seam at all. Naming
// the carrier it could not place is the difference between a label and a fact a human can act on.
func TestGetFindingAssessment_AttributionNamesBothSidesOfAnUnresolvedGap(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2026-33006")
	if _, err := f.AbsorbComponent(domain.MatchedComponent{
		PURL: "pkg:rpm/rocky/httpd@2.4.37", Name: "httpd", Version: "2.4.37",
		ClaimClass: domain.ClaimScope,
	}); err != nil {
		t.Fatalf("absorb: %v", err)
	}
	repo.seed(f)

	kn := stubKnowledge{k: app.FaultlineKnowledge{
		FaultlineID: "fl-1", CVE: "CVE-2026-33006",
		CarrierProducts: []string{"http_server"},
	}}
	read := app.NewReadService(repo, fakeProjection{}, nil, 0).WithKnowledge(kn)

	a, err := read.GetFindingAssessment(context.Background(), "fnd-1")
	if err != nil {
		t.Fatalf("assessment: %v", err)
	}
	if a.Attribution.Status != app.AttributionUnresolved {
		t.Fatalf("status = %q, want %q — every component is scope-class", a.Attribution.Status, app.AttributionUnresolved)
	}
	if got := strings.Join(a.Attribution.Carriers, ","); got != "http_server" {
		t.Errorf("carriers = %q, want the card's carrier named", got)
	}
	if got := strings.Join(a.Attribution.Components, ","); got != "httpd" {
		t.Errorf("components = %q, want the installed side named", got)
	}
	joined := strings.Join(a.Attribution.UnresolvedBecause, " | ")
	for _, want := range []string{"http_server", "httpd", "identity"} {
		if !strings.Contains(joined, want) {
			t.Errorf("unresolved_because = %q, want it to mention %q", joined, want)
		}
	}
	// D11: what evidence would RESOLVE this is identical on all 227 instances, so it is
	// documentation, not data. A field whose value never varies carries no information.
	if strings.Contains(strings.ToLower(joined), "cpe mapping") {
		t.Error("unresolved_because must carry only what VARIES per Finding (D11)")
	}
	// The knowledge half carries the same list unchanged, so a consumer that does not want the
	// derivation can still see what the card said.
	if got := strings.Join(a.Knowledge.CarrierProducts, ","); got != "http_server" {
		t.Errorf("knowledge.carrier_products = %q, want the card's list carried through", got)
	}
}

// "No source named a carrier" is a DIFFERENT gap from "carrier named, none matched", and the
// two are counted apart on purpose — `vm-verify` reports the whole population as the latter,
// which cannot be true of a card that named none (EDR-ATTRIBUTION-01 D13's measurement).
func TestGetFindingAssessment_AttributionSeparatesAMissingCarrierFromAnUnmatchedOne(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	if _, err := f.AbsorbComponent(domain.MatchedComponent{
		PURL: "pkg:rpm/rocky/python3-ply@3.11", Name: "python3-ply", ClaimClass: domain.ClaimScope,
	}); err != nil {
		t.Fatalf("absorb: %v", err)
	}
	repo.seed(f)
	read := app.NewReadService(repo, fakeProjection{}, nil, 0).
		WithKnowledge(stubKnowledge{k: app.FaultlineKnowledge{FaultlineID: "fl-1", CVE: "CVE-2024-1"}})

	a, err := read.GetFindingAssessment(context.Background(), "fnd-1")
	if err != nil {
		t.Fatalf("assessment: %v", err)
	}
	if a.Attribution.Status != app.AttributionUnresolved {
		t.Fatalf("status = %q, want unresolved", a.Attribution.Status)
	}
	if len(a.Attribution.Carriers) != 0 {
		t.Errorf("carriers = %v, want empty — no source named one", a.Attribution.Carriers)
	}
	if n := len(a.Attribution.UnresolvedBecause); n != 1 {
		t.Fatalf("unresolved_because has %d lines, want the single no-carrier statement", n)
	}
	if !strings.Contains(a.Attribution.UnresolvedBecause[0], "nothing to match against") {
		t.Errorf("unresolved_because = %q, want it to say no carrier was named at all",
			a.Attribution.UnresolvedBecause[0])
	}
}

// An unknown claim class ACTS AS CARRIER (EDR-CORRELATION-01): a gap in attribution evidence must
// never hide a live vulnerability, so it resolves the attribution rather than reporting a gap.
func TestGetFindingAssessment_AttributionTreatsUnknownAsAttributed(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	for _, c := range []domain.MatchedComponent{
		{PURL: "pkg:rpm/rocky/python3-ply@3.11", Name: "python3-ply", ClaimClass: domain.ClaimScope},
		{PURL: "pkg:pypi/requests@2.28.0", Name: "requests"}, // "" = unknown
	} {
		if _, err := f.AbsorbComponent(c); err != nil {
			t.Fatalf("absorb: %v", err)
		}
	}
	repo.seed(f)
	read := app.NewReadService(repo, fakeProjection{}, nil, 0).
		WithKnowledge(stubKnowledge{k: app.FaultlineKnowledge{
			FaultlineID: "fl-1", CVE: "CVE-2024-1", CarrierProducts: []string{"requests"},
		}})

	a, err := read.GetFindingAssessment(context.Background(), "fnd-1")
	if err != nil {
		t.Fatalf("assessment: %v", err)
	}
	if a.Attribution.Status != app.AttributionAttributed {
		t.Errorf("status = %q, want attributed — unknown counts as carrier", a.Attribution.Status)
	}
	if len(a.Attribution.UnresolvedBecause) != 0 {
		t.Errorf("unresolved_because = %v, want empty on an attributed Finding", a.Attribution.UnresolvedBecause)
	}
}

// A Finding with no components is not a gap: a gap requires something INSTALLED to have gone
// unattributed. And an unreachable Knowledge leaves the whole projection absent rather than
// asserting an answer — an outage must not read as "the carrier question was settled".
func TestGetFindingAssessment_AttributionNoComponentsAndNoKnowledge(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))

	read := app.NewReadService(repo, fakeProjection{}, nil, 0).
		WithKnowledge(stubKnowledge{k: app.FaultlineKnowledge{FaultlineID: "fl-1", CVE: "CVE-2024-1"}})
	a, err := read.GetFindingAssessment(context.Background(), "fnd-1")
	if err != nil {
		t.Fatalf("assessment: %v", err)
	}
	if a.Attribution.Status != app.AttributionNoComponents {
		t.Errorf("status = %q, want no_components", a.Attribution.Status)
	}

	bare := app.NewReadService(repo, fakeProjection{}, nil, 0)
	a, err = bare.GetFindingAssessment(context.Background(), "fnd-1")
	if err != nil {
		t.Fatalf("assessment: %v", err)
	}
	if a.Attribution.Status != "" {
		t.Errorf("status = %q, want absent when no Knowledge seam answered", a.Attribution.Status)
	}
}
