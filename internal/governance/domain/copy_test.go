package domain_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/themis-project/themis/internal/governance/domain"
)

// A decision records its copy targets as an input: trimmed, blanks and repeats dropped, order
// kept. Together with a propagating scope it is refused before anything is written.
func TestAcceptProposalWith_CopyTo(t *testing.T) {
	f := newFinding(t)
	if err := f.RaiseProposal(proposal(t, "p1", human, domain.StanceNotAffected)); err != nil {
		t.Fatal(err)
	}
	both := domain.AcceptanceTerms{Scope: domain.ScopeProduct, CopyTo: []domain.FindingID{"t1"}}
	if _, err := f.AcceptProposalWith("p1", human, epoch, both); !errors.Is(err, domain.ErrScopeAndCopy) {
		t.Fatalf("scope and copy together = %v, want ErrScopeAndCopy", err)
	}
	if _, decided := f.CurrentPosition(); decided {
		t.Fatal("a refused decision was recorded")
	}
	pos, err := f.AcceptProposalWith("p1", human, epoch, domain.AcceptanceTerms{
		Scope: domain.ScopeRelease, CopyTo: []domain.FindingID{" t2 ", "t1", "", "t2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := pos.CopyTo(); !reflect.DeepEqual(got, []domain.FindingID{"t2", "t1"}) {
		t.Fatalf("copy targets = %v", got)
	}
	if !pos.IsCopySource() {
		t.Error("a direct decision with targets is a copy source")
	}
	// The returned list is a copy: changing it does not change the Position.
	pos.CopyTo()[0] = "changed"
	if pos.CopyTo()[0] != "t2" {
		t.Error("CopyTo leaks the Position's own slice")
	}
}

// A copy names its source and no targets, so it is never copied further; a plain decision is
// not a source either.
func TestPosition_IsCopySource(t *testing.T) {
	plain := domain.ReconstitutePosition(1, domain.StanceAffected, "", human, domain.PositionInputs{}, epoch)
	if plain.IsCopySource() || len(plain.CopyTo()) != 0 {
		t.Error("a decision without targets is not a copy source")
	}
	odd := domain.ReconstitutePosition(1, domain.StanceAffected, "", human, domain.PositionInputs{
		CopyTo:         []domain.FindingID{"t1"},
		PropagatedFrom: domain.PropagationSource{FindingID: "src", Version: 1},
	}, epoch)
	if odd.IsCopySource() {
		t.Error("a Position applied from another is never a source")
	}
}

// The proposal id is the same for the same triple; the rationale keeps the person's words and
// says where the stance came from, falling back to the release id when no name is known.
func TestCopiedProposalIDAndRationale(t *testing.T) {
	if got := domain.CopiedProposalID("tgt", "src", 3); got != "copied:tgt:src:v3" {
		t.Errorf("proposal id = %q", got)
	}
	f := newFinding(t)
	with := domain.ReconstitutePosition(2, domain.StanceNotAffected, " built without the codec ", human, domain.PositionInputs{}, epoch)
	want := "built without the codec — copied from alpha 1.0 (Finding " + string(f.ID()) + "), Position v2, artifact level"
	if got := domain.CopiedRationale(f, " alpha 1.0 ", with, domain.LevelArtifact); got != want {
		t.Errorf("rationale = %q\nwant        %q", got, want)
	}
	bare := domain.ReconstitutePosition(1, domain.StanceNotAffected, "", human, domain.PositionInputs{}, epoch)
	want = "copied from release " + f.ReleaseID() + " (Finding " + string(f.ID()) + "), Position v1, component level"
	if got := domain.CopiedRationale(f, "", bare, domain.LevelComponent); got != want {
		t.Errorf("rationale = %q\nwant        %q", got, want)
	}
}

// The level of a copy target: the roll-forward levels when the component is shared, and
// vulnerability (cannot be copied to) when it is not.
func TestCopyLevel(t *testing.T) {
	comp := func(purl string) []domain.MatchedComponent {
		return []domain.MatchedComponent{{PURL: purl, Name: "n", Version: "1", ClaimClass: "carrier"}}
	}
	a, b := comp("pkg:rpm/rocky/libtiff@4.0.9-38.el8_10"), comp("pkg:rpm/rocky/libtiff@4.0.9-39.el8_10")
	if got := domain.CopyLevel(a, a); got != domain.LevelArtifact {
		t.Errorf("same purl = %q", got)
	}
	if got := domain.CopyLevel(b, a); got != domain.LevelComponent {
		t.Errorf("same package, other version = %q", got)
	}
	if got := domain.CopyLevel(comp("pkg:rpm/rocky/httpd@2.4.37-65"), a); got != domain.LevelVulnerability {
		t.Errorf("other package = %q", got)
	}
	if got := domain.CopyLevel(nil, a); got != domain.LevelVulnerability {
		t.Errorf("no component = %q", got)
	}
}
