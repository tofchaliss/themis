package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type repoLister struct {
	repo *fakeRepo
	err  error
}

func (l repoLister) AllFaultlineIDs(context.Context) ([]domain.FaultlineID, error) {
	if l.err != nil {
		return nil, l.err
	}
	var ids []domain.FaultlineID
	for _, f := range l.repo.cards {
		ids = append(ids, f.ID())
	}
	return ids, nil
}

func rangedFacts(t *testing.T, source string, at time.Time, ranges ...string) domain.Proposal {
	t.Helper()
	c, _ := value.NewCVSS(7.5, "")
	p, err := domain.NewVulnFactsProposal(source, at, domain.VulnFacts{
		Severity: value.SeverityHigh, CVSS: c, AffectedRanges: ranges,
		Fixes: []domain.FixedVersion{{Package: "stdlib", Version: "1.4.3", Ecosystem: "go"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// KN-GO-3, the estate's shape: a card the old OSV reader fed holds `>=0` and `<1.4.3` as two
// rules; NVD's bound stands beside them. The pass folds a corrected OSV statement, the view
// pairs the interval and keeps NVD's bound, and a second pass has nothing to repair.
func TestRangeRepair_PairsTheSplitRangesAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{}, domain.NewPrecedence("nvd", "osv"), domain.NewTrustPolicy(nil))
	cve := cve(t, "CVE-2015-5739")
	t0 := time.Unix(1_600_000_000, 0)
	signal, _ := domain.NewExploitSignalProposal("epsskev", t0, domain.ExploitSignal{EPSS: 0.3})
	for _, p := range []domain.Proposal{
		rangedFacts(t, "osv", t0, ">=0", "<1.4.3"),
		rangedFacts(t, "nvd", t0, "<=1.4.2"),
		rangedFacts(t, "osv", t0.Add(time.Hour), ">=0", "<1.4.3"), // a later poll, same wrong shape
		signal, // not a range statement: ignored by the pass
		vulnFacts(t, "redhat", value.SeverityHigh), // range-less facts: ignored too
	} {
		if _, _, err := fold.FoldProposal(ctx, cve, p); err != nil {
			t.Fatal(err)
		}
	}
	pass := app.NewRangeRepair(repoLister{repo: repo}, repo, fold, fixedClock{})

	res, err := pass.Run(ctx)
	if err != nil || res.Cards != 1 || res.Repaired != 1 {
		t.Fatalf("first pass = %+v, %v; want 1 card, 1 repaired", res, err)
	}
	f, _, _ := repo.GetByCVE(ctx, "CVE-2015-5739")
	got := f.View().AffectedRanges
	if len(got) != 2 || got[0] != "<=1.4.2" || got[1] != ">=0,<1.4.3" {
		t.Fatalf("ranges after repair = %v, want [<=1.4.2 >=0,<1.4.3]", got)
	}
	// The repeated wrong poll was a restatement and was never recorded, so two originals are
	// kept and ONE corrected statement is appended: nothing edited, nothing deleted.
	if n := len(f.Proposals()); n != 5 {
		t.Fatalf("proposals = %d, want 5 (four originals kept, one corrected statement appended)", n)
	}
	// Provably out of range for the estate's build now.
	if v := (value.AffectedRange{Ecosystem: "go", Groups: got}).Applicability("go1.27.1"); v != value.RangeOutOfRange {
		t.Fatalf("go1.27.1 = %s, want out_of_range", v)
	}

	again, err := pass.Run(ctx)
	if err != nil || again.Repaired != 0 {
		t.Fatalf("second pass = %+v, %v; want nothing repaired", again, err)
	}
}

func TestRangeRepair_LeavesCorrectCardsAlone(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{}, domain.NewPrecedence("osv"), domain.NewTrustPolicy(nil))
	if _, _, err := fold.FoldProposal(ctx, cve(t, "CVE-2024-1"), rangedFacts(t, "osv", time.Unix(1_600_000_000, 0), ">=0,<2.0")); err != nil {
		t.Fatal(err)
	}
	res, err := app.NewRangeRepair(repoLister{repo: repo}, repo, fold, fixedClock{}).Run(ctx)
	if err != nil || res.Cards != 1 || res.Repaired != 0 {
		t.Fatalf("res = %+v, %v; want the correct card untouched", res, err)
	}
}

func TestRangeRepair_ReadFailuresAreFatal(t *testing.T) {
	repo := newRepo()
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{}, domain.NewPrecedence("osv"), domain.NewTrustPolicy(nil))
	if _, err := app.NewRangeRepair(repoLister{err: errors.New("db down")}, repo, fold, fixedClock{}).Run(context.Background()); err == nil {
		t.Fatal("a lister failure must abort")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := fold.FoldProposal(context.Background(), cve(t, "CVE-2024-1"), rangedFacts(t, "osv", time.Unix(1_600_000_000, 0), ">=0", "<2.0")); err != nil {
		t.Fatal(err)
	}
	if _, err := app.NewRangeRepair(repoLister{repo: repo}, repo, fold, fixedClock{}).Run(ctx); err == nil {
		t.Fatal("a cancelled context must abort")
	}
	repo.getErr = errors.New("db down")
	if _, err := app.NewRangeRepair(repoLister{repo: repo}, repo, fold, fixedClock{}).Run(context.Background()); err == nil {
		t.Fatal("a failing repository must abort the pass")
	}
	repo.getErr = nil
	if _, err := app.NewRangeRepair(repoLister{repo: repo}, unreadableCards{repo}, fold, fixedClock{}).Run(context.Background()); err == nil {
		t.Fatal("an unreadable card must abort the pass")
	}
}

// unreadableCards is the repository with GetByID failing — the read the pass depends on.
type unreadableCards struct{ *fakeRepo }

func (unreadableCards) GetByID(context.Context, domain.FaultlineID) (domain.Faultline, error) {
	return domain.Faultline{}, errors.New("db down")
}
