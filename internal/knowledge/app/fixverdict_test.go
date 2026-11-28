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
	lister.err = boom
	if _, err := read.ReleaseFixVerdicts(ctx, "rel-1"); !errors.Is(err, boom) {
		t.Errorf("store failure: %v", err)
	}
}
