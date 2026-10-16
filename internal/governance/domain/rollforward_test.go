package domain_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

func rfComp(purl, class string, retired bool) domain.MatchedComponent {
	return domain.MatchedComponent{PURL: purl, ClaimClass: class, Retired: retired}
}

// EDR-ROLLFORWARD-01 D2/D3: the three VAMS levels as rules over the carrier components.
func TestRollForwardEligibility(t *testing.T) {
	libtiff38 := rfComp("pkg:rpm/rocky/libtiff@4.0.9-38.el8_10", "carrier", false)
	libtiff38q := rfComp("pkg:rpm/rocky/libtiff@4.0.9-38.el8_10?arch=x86_64&distro=rocky-8.9", "", false)
	libtiff39 := rfComp("pkg:rpm/rocky/libtiff@4.0.9-39.el8_10", "carrier", false)
	curl := rfComp("pkg:rpm/rocky/curl@7.61.1-34.el8_10.13", "", false)
	httpdScope := rfComp("pkg:rpm/rocky/httpd@2.4.37-65.module+el8.10.0", domain.ClaimScope, false)
	cases := []struct {
		name           string
		target, preced []domain.MatchedComponent
		want           domain.RollForwardLevel
	}{
		{"same build purl for purl", []domain.MatchedComponent{libtiff38}, []domain.MatchedComponent{libtiff38}, domain.LevelArtifact},
		{"unknown class acts as carrier", []domain.MatchedComponent{libtiff38q}, []domain.MatchedComponent{libtiff38q}, domain.LevelArtifact},
		{"same package, other version", []domain.MatchedComponent{libtiff39}, []domain.MatchedComponent{libtiff38}, domain.LevelComponent},
		{"same package, qualifiers differ", []domain.MatchedComponent{libtiff38q}, []domain.MatchedComponent{libtiff39}, domain.LevelComponent},
		{"different package: vulnerability level only, not proposed", []domain.MatchedComponent{curl}, []domain.MatchedComponent{libtiff38}, ""},
		{"extra package on the target", []domain.MatchedComponent{libtiff38, curl}, []domain.MatchedComponent{libtiff38}, ""},
		// The CVE-2026-33006 fixture: a scope-only target has no subject — no proposal, whatever
		// was decided elsewhere.
		{"scope-only target (fixture)", []domain.MatchedComponent{httpdScope}, []domain.MatchedComponent{libtiff38}, ""},
		{"scope-only precedent", []domain.MatchedComponent{libtiff38}, []domain.MatchedComponent{httpdScope}, ""},
		{"retired matches take no part", []domain.MatchedComponent{libtiff38, rfComp("pkg:rpm/rocky/curl@1", "", true)}, []domain.MatchedComponent{libtiff38}, domain.LevelArtifact},
		{"empty purl ignored", []domain.MatchedComponent{libtiff38, rfComp("  ", "", false)}, []domain.MatchedComponent{libtiff38}, domain.LevelArtifact},
		{"nothing on either side", nil, nil, ""},
	}
	for _, tc := range cases {
		if got := domain.RollForwardEligibility(tc.target, tc.preced); got != tc.want {
			t.Errorf("%s: level = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A judgement is a Position a person took, or took on the AI's proposal; a rule's verdict —
// policy-decided, or a human confirming a system proposal — is not carried (AI-RF-4/4b).
func TestJudgedPosition(t *testing.T) {
	human := domain.Actor{Kind: domain.ActorHuman, ID: "alice"}
	policy := domain.Actor{Kind: domain.ActorPolicy, ID: "auto"}
	system := domain.Actor{Kind: domain.ActorSystem, ID: "version-range"}

	undecided := newFinding(t)
	if _, ok := undecided.JudgedPosition(); ok {
		t.Fatal("no Position is no judgement")
	}

	judged := newFinding(t)
	if err := judged.RaiseProposal(proposal(t, "p-human", human, domain.StanceNotAffected)); err != nil {
		t.Fatal(err)
	}
	if _, err := judged.AcceptProposal("p-human", human, epoch); err != nil {
		t.Fatal(err)
	}
	if pos, ok := judged.JudgedPosition(); !ok || pos.Stance() != domain.StanceNotAffected {
		t.Fatalf("human decision on a human proposal must be a judgement, got %+v ok=%v", pos, ok)
	}

	ruled := newFinding(t)
	if err := ruled.RaiseProposal(proposal(t, "range:x", system, domain.StanceNotAffected)); err != nil {
		t.Fatal(err)
	}
	if _, err := ruled.AcceptProposal("range:x", human, epoch); err != nil {
		t.Fatal(err)
	}
	if _, ok := ruled.JudgedPosition(); ok {
		t.Fatal("a human confirming a system proposal is the rule's verdict, not a judgement")
	}

	byPolicy := newFinding(t)
	if err := byPolicy.RaiseProposal(proposal(t, "range:y", system, domain.StanceNotAffected)); err != nil {
		t.Fatal(err)
	}
	if _, err := byPolicy.AcceptProposal("range:y", policy, epoch.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, ok := byPolicy.JudgedPosition(); ok {
		t.Fatal("a policy's decision is not a judgement")
	}
}

func TestRollForwardProposalID(t *testing.T) {
	if got := domain.RollForwardProposalID("t1", "s1"); got != "rollforward:t1:s1" {
		t.Fatalf("id = %q", got)
	}
}

// RF-2: the re-surfacing mark on the Finding — set once on a suppressing Position, idempotent,
// cleared by a new Position, refused without a suppressing Position or with a zero time.
func TestMarkDispositionStale(t *testing.T) {
	human := domain.Actor{Kind: domain.ActorHuman, ID: "alice"}
	f := newFinding(t)
	if f.MarkDispositionStale("x", epoch) {
		t.Fatal("no Position: nothing to re-surface")
	}
	if err := f.RaiseProposal(proposal(t, "p-aff", human, domain.StanceAffected)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.AcceptProposal("p-aff", human, epoch); err != nil {
		t.Fatal(err)
	}
	if f.MarkDispositionStale("x", epoch) {
		t.Fatal("an affected Position suppresses nothing — not this mark's business")
	}
	if err := f.RaiseProposal(proposal(t, "p-na", human, domain.StanceNotAffected)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.AcceptProposal("p-na", human, epoch.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	v := f.Version()
	if f.MarkDispositionStale("x", time.Time{}) {
		t.Fatal("a zero time cannot mark")
	}
	if !f.MarkDispositionStale("  the CVE entered KEV ", epoch.Add(time.Hour)) {
		t.Fatal("a suppressing Position must take the mark")
	}
	since, reason, ok := f.DispositionStale()
	if !ok || !since.Equal(epoch.Add(time.Hour)) || reason != "the CVE entered KEV" || f.Version() != v+1 {
		t.Fatalf("mark = %v %q ok=%v version %d (was %d)", since, reason, ok, f.Version(), v)
	}
	if f.MarkDispositionStale("later drift", epoch.Add(2*time.Hour)) {
		t.Fatal("a second mark must not rewrite the first reason")
	}
	if err := f.RaiseProposal(proposal(t, "p-again", human, domain.StanceNotAffected)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.AcceptProposal("p-again", human, epoch.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := f.DispositionStale(); ok {
		t.Fatal("a new Position answers the question and clears the mark")
	}
	g := newFinding(t)
	domain.RestoreDispositionStale(&g, time.Time{}, "ignored")
	if _, _, ok := g.DispositionStale(); ok {
		t.Fatal("restoring a zero time restores nothing")
	}
	domain.RestoreDispositionStale(&g, epoch, "restored")
	if since, reason, ok := g.DispositionStale(); !ok || !since.Equal(epoch) || reason != "restored" {
		t.Fatalf("restored mark = %v %q ok=%v", since, reason, ok)
	}
}
