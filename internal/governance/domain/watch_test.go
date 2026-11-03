package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

// Pasted text in, recognised identifiers out: CVE and Red Hat advisory ids in any case, split on
// any separator, de-duplicated; everything else reported, never dropped silently.
func TestParseWatchIdentifiers(t *testing.T) {
	ok, bad := domain.ParseWatchIdentifiers(" cve-2026-1111, RHSA-2026:0001;rhba-2026:12345\n CVE-2026-1111\tfoo bar-1 CVE-26-1 ")
	if len(ok) != 3 || ok[0] != "CVE-2026-1111" || ok[1] != "RHSA-2026:0001" || ok[2] != "RHBA-2026:12345" {
		t.Errorf("accepted = %v", ok)
	}
	if len(bad) != 3 || bad[0] != "FOO" || bad[1] != "BAR-1" || bad[2] != "CVE-26-1" {
		t.Errorf("rejected = %v", bad)
	}
	if ok, bad := domain.ParseWatchIdentifiers(" , ; "); ok != nil || bad != nil {
		t.Errorf("blank text = %v / %v", ok, bad)
	}
	for id, want := range map[string]string{"CVE-2026-1": "", "cve-2026-0001": "cve", "RHEA-2026:100": "advisory", "USN-1-1": "", "": ""} {
		if got := domain.WatchIdentifierKind(id); got != want {
			t.Errorf("kind(%q) = %q, want %q", id, got, want)
		}
	}
}

// A Watch needs a name and one identifier; identifiers only ever grow; the resolution is a
// sorted set; reconstitution round-trips.
func TestWatch_Lifecycle(t *testing.T) {
	now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	if _, err := domain.NewWatch("w1", "  ", "alice", []string{"CVE-2026-1111"}, now); !errors.Is(err, domain.ErrWatchNameRequired) {
		t.Errorf("blank name: %v", err)
	}
	if _, err := domain.NewWatch("w1", "wave", "alice", []string{"nothing"}, now); !errors.Is(err, domain.ErrWatchEmpty) {
		t.Errorf("no identifier: %v", err)
	}
	w, err := domain.NewWatch("w1", " wave 1 ", " alice ", []string{"cve-2026-1111", "CVE-2026-1111", "RHSA-2026:0001"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if w.ID() != "w1" || w.Name() != "wave 1" || w.CreatedBy() != "alice" || !w.CreatedAt().Equal(now) || w.Notify() {
		t.Errorf("watch = %+v", w)
	}
	if ids := w.Identifiers(); len(ids) != 2 || ids[0] != "CVE-2026-1111" || ids[1] != "RHSA-2026:0001" {
		t.Errorf("identifiers = %v", ids)
	}
	if n := w.AddIdentifiers([]string{"CVE-2026-1111", "cve-2026-2222", "junk"}); n != 1 || len(w.Identifiers()) != 3 {
		t.Errorf("added = %d, identifiers = %v", n, w.Identifiers())
	}
	// A copy, not the slice.
	w.Identifiers()[0] = "X"
	if w.Identifiers()[0] != "CVE-2026-1111" {
		t.Error("Identifiers leaked the backing slice")
	}
	w.RecordResolution([]string{"CVE-2026-2222", "cve-2026-1111", "", "CVE-2026-2222"}, now.Add(time.Hour))
	if r := w.ResolvedCVEs(); len(r) != 2 || r[0] != "CVE-2026-1111" || r[1] != "CVE-2026-2222" || !w.ResolvedAt().Equal(now.Add(time.Hour)) {
		t.Errorf("resolution = %v at %v", r, w.ResolvedAt())
	}
	w.SetNotify(true)
	back := domain.ReconstituteWatch(w.ID(), w.Name(), w.CreatedBy(), w.CreatedAt(), w.Identifiers(), w.ResolvedCVEs(), w.ResolvedAt(), w.Notify())
	if back.Name() != "wave 1" || len(back.Identifiers()) != 3 || len(back.ResolvedCVEs()) != 2 || !back.Notify() || !back.ResolvedAt().Equal(w.ResolvedAt()) {
		t.Errorf("reconstituted = %+v", back)
	}
}

// The state table (D2): the human's answer first, then the machine's, then "nothing matches".
func TestWatchStateOf(t *testing.T) {
	open := domain.MatchedComponent{PURL: "pkg:rpm/a@1", Name: "a", Version: "1", ClaimClass: "carrier"}
	cleared := domain.MatchedComponent{PURL: "pkg:rpm/b@2", Name: "b", Version: "2", ClaimClass: "carrier", VerdictState: "cleared_vendor_fix"}
	withComponents := func(t *testing.T, comps ...domain.MatchedComponent) domain.Finding {
		t.Helper()
		f := newFinding(t)
		for _, c := range comps {
			if _, err := f.AbsorbComponent(c); err != nil {
				t.Fatal(err)
			}
		}
		return f
	}
	decided := func(t *testing.T, f domain.Finding, stance domain.Stance) domain.Finding {
		t.Helper()
		if err := f.RaiseProposal(proposal(t, "p1", human, stance)); err != nil {
			t.Fatal(err)
		}
		terms := domain.AcceptanceTerms{}
		if stance == domain.StanceAcceptedRisk {
			terms.Owner = "bob"
		}
		if _, err := f.AcceptProposalWith("p1", human, epoch, terms); err != nil {
			t.Fatal(err)
		}
		return f
	}
	cases := []struct {
		name     string
		f        domain.Finding
		fixKnown bool
		want     domain.WatchState
	}{
		{"no components", newFinding(t), true, domain.WatchNotAffected},
		{"open, no fix", withComponents(t, open), false, domain.WatchOpenNoFix},
		{"open, fix known", withComponents(t, open, cleared), true, domain.WatchOpenFixAvailable},
		{"all cleared", withComponents(t, cleared), false, domain.WatchFixed},
		{"not affected stands", decided(t, withComponents(t, open), domain.StanceNotAffected), true, domain.WatchNotAffected},
		{"accepted risk stands", decided(t, withComponents(t, open), domain.StanceAcceptedRisk), true, domain.WatchAccepted},
		{"mitigated stands", decided(t, withComponents(t, open), domain.StanceMitigated), false, domain.WatchAccepted},
		{"deferred stands", decided(t, withComponents(t, open), domain.StanceDeferred), false, domain.WatchAccepted},
		{"affected is still open", decided(t, withComponents(t, open), domain.StanceAffected), true, domain.WatchOpenFixAvailable},
	}
	for _, c := range cases {
		if got := domain.WatchStateOf(c.f, c.fixKnown); got != c.want {
			t.Errorf("%s: state = %s, want %s", c.name, got, c.want)
		}
	}
}
