package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type verdictsByRelease struct {
	asked string
	rows  []app.MatchVerdict
	err   error
}

func (v *verdictsByRelease) ReleaseMatchVerdicts(_ context.Context, id string) ([]app.MatchVerdict, error) {
	v.asked = id
	return v.rows, v.err
}

// EDR-REBUILD-01 D30: the read derives the fix standing from the recorded verdict; a blank id and
// an unwired lister are refused, never an empty answer; a store failure passes through.
func TestReadService_ReleaseFixVerdicts(t *testing.T) {
	ctx := context.Background()
	read := app.NewReadService(nil, nil)
	if _, err := read.ReleaseFixVerdicts(ctx, "rel-1"); !errors.Is(err, app.ErrFixVerdictsUnavailable) {
		t.Errorf("unwired: %v", err)
	}
	lister := &verdictsByRelease{rows: []app.MatchVerdict{
		{PURL: "pkg:rpm/redhat/kernel@4.18.0-1.el8", Version: "4.18.0-1.el8", Ecosystem: "rpm", State: domain.VerdictOpen, Behind: []string{"0:4.18.0-2.el8"}},
		{PURL: "pkg:rpm/redhat/bash@4.4-1.el8", Version: "4.4-1.el8", Ecosystem: "rpm", State: domain.VerdictOpen},
		{PURL: "pkg:npm/left-pad@1.0.0", Version: "1.0.0", Ecosystem: "npm", State: domain.VerdictOpen},
	}}
	read = read.WithFixVerdicts(lister)
	if _, err := read.ReleaseFixVerdicts(ctx, "  "); !errors.Is(err, app.ErrInvalidRelease) {
		t.Errorf("blank: %v", err)
	}
	got, err := read.ReleaseFixVerdicts(ctx, " rel-1 ")
	if err != nil || lister.asked != "rel-1" || len(got) != 3 {
		t.Fatalf("got %+v err %v asked %q", got, err, lister.asked)
	}
	if got[0].Fix != domain.FixKnown || got[1].Fix != domain.FixNone || got[2].Fix != domain.FixUnknown {
		t.Errorf("standings = %s %s %s", got[0].Fix, got[1].Fix, got[2].Fix)
	}
	boom := errors.New("db down")
	// KN-BEHIND-MODULE-1: a fix that lives only in another module stream is its own standing.
	lister.rows = []app.MatchVerdict{
		// base-repository install, every bound a module build
		{Version: "3.9-9.el8", Ecosystem: "rpm", State: domain.VerdictOpen, Behind: []string{"0:3.11-10.module+el8.10.0+1582+bc278001", "0:3.11-10.module+el8.9.0+1418+f0d66789"}},
		// module install, every bound a module build of another series
		{Version: "8.0.36-1.module+el8.9.0+1+a", Ecosystem: "rpm", State: domain.VerdictOpen, Behind: []string{"0:8.4.4-1.module+el8.10.0+2+b"}},
		// module install, one bound in its own series: simply behind
		{Version: "8.0.36-1.module+el8.9.0+1+a", Ecosystem: "rpm", State: domain.VerdictOpen, Behind: []string{"0:8.0.40-1.module+el8.10.0+3+c", "0:8.4.4-1.module+el8.10.0+2+b"}},
		// base install, one plain bound among module builds: simply behind
		{Version: "3.9-9.el8", Ecosystem: "rpm", State: domain.VerdictOpen, Behind: []string{"0:3.9-12.el8", "0:3.11-10.module+el8.10.0+1582+bc278001"}},
		// the rule is rpm's alone
		{Version: "1.2.3-r0", Ecosystem: "alpine", State: domain.VerdictOpen, Behind: []string{"1.2.4-r0"}},
	}
	got, err = read.ReleaseFixVerdicts(ctx, "rel-1")
	if err != nil || len(got) != 5 {
		t.Fatalf("got %+v err %v", got, err)
	}
	for i, want := range []domain.FixStanding{domain.FixOtherStream, domain.FixOtherStream, domain.FixKnown, domain.FixKnown, domain.FixKnown} {
		if got[i].Fix != want {
			t.Errorf("row %d: fix %s, want %s", i, got[i].Fix, want)
		}
	}
	lister.err = boom
	if _, err := read.ReleaseFixVerdicts(ctx, "rel-1"); !errors.Is(err, boom) {
		t.Errorf("store failure: %v", err)
	}
}
