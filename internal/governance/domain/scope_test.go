package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/governance/domain"
)

// The closed set, with blank reading as release so every pre-record decision keeps its meaning.
func TestParseDecisionScope(t *testing.T) {
	for in, want := range map[string]domain.DecisionScope{
		"": domain.ScopeRelease, "release": domain.ScopeRelease, " Project ": domain.ScopeProject, "PRODUCT": domain.ScopeProduct,
	} {
		got, err := domain.ParseDecisionScope(in)
		if err != nil || got != want {
			t.Errorf("parse %q = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := domain.ParseDecisionScope("estate"); !errors.Is(err, domain.ErrInvalidScope) {
		t.Errorf("estate accepted: %v", err)
	}
	if domain.ScopeRelease.Propagates() || !domain.ScopeProject.Propagates() || !domain.ScopeProduct.Propagates() {
		t.Error("propagates: release no, project and product yes")
	}
}

// Who a scope reaches: the same project, the same product; never across, never on a blank owner.
func TestDecisionScope_Covers(t *testing.T) {
	cases := []struct {
		name               string
		scope              domain.DecisionScope
		prod, proj, tp, tj string
		want               bool
	}{
		{"project same", domain.ScopeProject, "P", "A", "P", "A", true},
		{"project other", domain.ScopeProject, "P", "A", "P", "B", false},
		{"project blank", domain.ScopeProject, "P", "", "P", "", false},
		{"product same, other project", domain.ScopeProduct, "P", "A", "P", "B", true},
		{"product other", domain.ScopeProduct, "P", "A", "Q", "A", false},
		{"product blank", domain.ScopeProduct, "", "A", "", "A", false},
		{"release never", domain.ScopeRelease, "P", "A", "P", "A", false},
	}
	for _, c := range cases {
		if got := c.scope.Covers(c.prod, c.proj, c.tp, c.tj); got != c.want {
			t.Errorf("%s: covers = %v, want %v", c.name, got, c.want)
		}
	}
}

// The decision records its scope as an input; release normalizes to the pre-record blank; an
// unknown scope is refused before anything is written; a propagated Position names its source,
// the proposal id is deterministic, and the rationale says where the stance came from.
func TestAcceptProposalWith_ScopeAndPropagation(t *testing.T) {
	f := newFinding(t)
	if err := f.RaiseProposal(proposal(t, "p1", human, domain.StanceNotAffected)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.AcceptProposalWith("p1", human, epoch, domain.AcceptanceTerms{Scope: "estate"}); !errors.Is(err, domain.ErrInvalidScope) {
		t.Fatalf("bad scope accepted: %v", err)
	}
	pos, err := f.AcceptProposalWith("p1", human, epoch, domain.AcceptanceTerms{Scope: "Product"})
	if err != nil {
		t.Fatal(err)
	}
	if pos.Scope() != domain.ScopeProduct || !pos.IsScopedSource() {
		t.Errorf("scope = %q source=%v", pos.Scope(), pos.IsScopedSource())
	}
	if src, ok := pos.PropagatedFrom(); ok || !src.IsZero() {
		t.Errorf("a direct decision names a source: %+v", src)
	}
	// Release, spelled or blank, is the blank mark — a pre-record Position reads the same.
	g := newFinding(t)
	_ = g.RaiseProposal(proposal(t, "p1", human, domain.StanceAffected))
	rel, err := g.AcceptProposalWith("p1", human, epoch, domain.AcceptanceTerms{Scope: domain.ScopeRelease})
	if err != nil || rel.Inputs().Scope != "" || rel.Scope() != domain.ScopeRelease || rel.IsScopedSource() {
		t.Errorf("release scope = %+v err=%v", rel.Inputs(), err)
	}
	// The propagated Position: same stance, the source named, never a source itself.
	tgt, _ := domain.NewFinding("fnd-2", "rel-2", "fl-1", "CVE-2024-1")
	pid := domain.ScopedProposalID(tgt.ID(), f.ID(), pos.Version())
	if pid != "scoped:fnd-2:fnd-1:v1" {
		t.Errorf("proposal id = %s", pid)
	}
	_ = tgt.RaiseProposal(proposal(t, pid, human, domain.StanceNotAffected))
	prop, err := tgt.AcceptProposalWith(pid, human, epoch, domain.AcceptanceTerms{
		Scope: pos.Scope(), PropagatedFrom: domain.PropagationSource{FindingID: f.ID(), Version: pos.Version()}})
	if err != nil {
		t.Fatal(err)
	}
	if src, ok := prop.PropagatedFrom(); !ok || src.FindingID != "fnd-1" || src.Version != 1 {
		t.Errorf("propagated from = %+v %v", src, ok)
	}
	if prop.Scope() != domain.ScopeProduct || prop.IsScopedSource() {
		t.Errorf("a propagated Position must carry the scope but never be a source: %q %v", prop.Scope(), prop.IsScopedSource())
	}
	r := domain.ScopedRationale(f, "", pos, domain.LevelComponent)
	for _, want := range []string{"because", "applied by scope product", "release rel-1", "Finding fnd-1", "Position v1", "component level"} {
		if !strings.Contains(r, want) {
			t.Errorf("rationale %q lacks %q", r, want)
		}
	}
	// A resolved label replaces the bare release id — the line reads like the GUI, not the DB.
	if r := domain.ScopedRationale(f, " oamp 20.1.0.0-180 ", pos, domain.LevelComponent); !strings.Contains(r, "from oamp 20.1.0.0-180 (Finding fnd-1)") || strings.Contains(r, "rel-1") {
		t.Errorf("labelled rationale = %q", r)
	}
	bare := domain.ReconstitutePosition(2, domain.StanceAffected, "  ", human, domain.PositionInputs{Scope: domain.ScopeProject}, epoch)
	if r := domain.ScopedRationale(f, "", bare, domain.LevelArtifact); strings.HasPrefix(r, " —") || !strings.HasPrefix(r, "applied by scope project") {
		t.Errorf("bare rationale = %q", r)
	}
}
