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

type stubCardReader struct {
	cards []app.UnattributedCard
	err   error
}

func (s stubCardReader) CardsNeedingAttribution(context.Context, int) ([]app.UnattributedCard, error) {
	return s.cards, s.err
}

type stubDiscover struct {
	byPURL map[string][]app.ProposalFor
	err    error
	calls  int
}

func (s *stubDiscover) VulnsForPackage(_ context.Context, c app.InventoryComponent) ([]app.ProposalFor, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.byPURL[c.PURL], nil
}

func attributedFor(t *testing.T, cveStr, pkg, version string) app.ProposalFor {
	t.Helper()
	c, _ := value.NewCVSS(7.5, "")
	p, err := domain.NewVulnFactsProposal("osv", time.Unix(1_700_000_000, 0), domain.VulnFacts{
		Severity: value.SeverityHigh,
		CVSS:     c,
		Fixes:    []domain.FixedVersion{{Package: pkg, Version: version}},
	})
	if err != nil {
		t.Fatalf("proposal: %v", err)
	}
	return app.ProposalFor{CVE: cve(t, cveStr), Proposal: p}
}

func card(t *testing.T, cveStr, purl, name, source string) app.UnattributedCard {
	t.Helper()
	return app.UnattributedCard{
		CVE: cveStr,
		Component: app.InventoryComponent{
			PURL: purl, Name: name, Version: "1.0", Ecosystem: "rpm", Source: source,
		},
	}
}

// The sweep exists because only OSV and Red Hat attribute a fix to a package, and OSV is queried
// during CORRELATION — which runs on UPLOAD. A card whose releases are never re-uploaded keeps its
// pre-attribution flat list forever, and content-addressing means re-uploading identical bytes
// dedups, so an operator has no workaround (KN-FIX-2).
func TestReattributeSweep_FoldsAttributedFixesForExistingCards(t *testing.T) {
	repo := newRepo()
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{},
		domain.NewPrecedence("osv"), domain.NewTrustPolicy(nil))
	disc := &stubDiscover{byPURL: map[string][]app.ProposalFor{
		"pkg:rpm/rocky/python3-ply@3.9": {attributedFor(t, "CVE-2007-4559", "python-ply", "0:3.11-10")},
	}}
	reader := stubCardReader{cards: []app.UnattributedCard{
		card(t, "CVE-2007-4559", "pkg:rpm/rocky/python3-ply@3.9", "python3-ply", "python-ply"),
	}}

	n, err := app.NewReattributeService(reader, disc, fold, 0).Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Fatalf("folded = %d, want 1", n)
	}
	f, found, _ := repo.GetByCVE(context.Background(), "CVE-2007-4559")
	if !found {
		t.Fatal("card not persisted")
	}
	if got := f.View().FixesFor("python-ply"); len(got) != 1 || got[0] != "0:3.11-10" {
		t.Errorf("FixesFor(python-ply) = %v, want the attributed fix", got)
	}
}

// A component query returns EVERY CVE affecting the package. Folding all of them would quietly
// turn a re-attribution sweep into an undeclared discovery pass — the same writes, but no longer
// the operation the operator asked for or the one this service is bounded for.
func TestReattributeSweep_FoldsOnlyTheCardItWasAskedAbout(t *testing.T) {
	repo := newRepo()
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{},
		domain.NewPrecedence("osv"), domain.NewTrustPolicy(nil))
	disc := &stubDiscover{byPURL: map[string][]app.ProposalFor{
		"pkg:rpm/rocky/python3-ply@3.9": {
			attributedFor(t, "CVE-2007-4559", "python-ply", "0:3.11-10"),
			attributedFor(t, "CVE-2099-9999", "python-ply", "0:9.9-9"), // a different CVE
		},
	}}
	reader := stubCardReader{cards: []app.UnattributedCard{
		card(t, "CVE-2007-4559", "pkg:rpm/rocky/python3-ply@3.9", "python3-ply", "python-ply"),
	}}

	if n, err := app.NewReattributeService(reader, disc, fold, 0).Sweep(context.Background()); err != nil || n != 1 {
		t.Fatalf("folded=%d err=%v, want 1", n, err)
	}
	if _, found, _ := repo.GetByCVE(context.Background(), "CVE-2099-9999"); found {
		t.Error("the sweep created a card for an unrelated CVE — that is discovery, not re-attribution")
	}
}

// Re-running must be free: folding is append-only and the aggregate drops verbatim restatements
// (KN-PROPOSAL-BLOAT-1), so a second sweep over already-attributed cards writes nothing new.
func TestReattributeSweep_IsIdempotent(t *testing.T) {
	repo := newRepo()
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{},
		domain.NewPrecedence("osv"), domain.NewTrustPolicy(nil))
	disc := &stubDiscover{byPURL: map[string][]app.ProposalFor{
		"pkg:rpm/rocky/python3-ply@3.9": {attributedFor(t, "CVE-2007-4559", "python-ply", "0:3.11-10")},
	}}
	reader := stubCardReader{cards: []app.UnattributedCard{
		card(t, "CVE-2007-4559", "pkg:rpm/rocky/python3-ply@3.9", "python3-ply", "python-ply"),
	}}
	svc := app.NewReattributeService(reader, disc, fold, 0)

	for i := range 2 {
		if _, err := svc.Sweep(context.Background()); err != nil {
			t.Fatalf("sweep %d: %v", i+1, err)
		}
	}

	f, _, _ := repo.GetByCVE(context.Background(), "CVE-2007-4559")
	if got := len(f.Proposals()); got != 1 {
		t.Errorf("proposals = %d, want 1 — a repeated sweep must not grow the audit log", got)
	}
}

// A per-card failure is skipped, not fatal: one unreachable feed must not stall the queue. Only
// the queue read aborts, because without it there is no work to do.
func TestReattributeSweep_FailureHandling(t *testing.T) {
	fold := app.NewFaultlineService(newRepo(), &seqIDs{}, fixedClock{},
		domain.NewPrecedence("osv"), domain.NewTrustPolicy(nil))
	cards := []app.UnattributedCard{card(t, "CVE-2007-4559", "p", "n", "s")}

	t.Run("a feed failure skips the card", func(t *testing.T) {
		disc := &stubDiscover{err: errors.New("feed down")}
		n, err := app.NewReattributeService(stubCardReader{cards: cards}, disc, fold, 0).Sweep(context.Background())
		if err != nil || n != 0 {
			t.Errorf("folded=%d err=%v, want a skipped card and no error", n, err)
		}
	})

	t.Run("a queue-read failure aborts", func(t *testing.T) {
		disc := &stubDiscover{}
		_, err := app.NewReattributeService(stubCardReader{err: errors.New("db down")}, disc, fold, 0).Sweep(context.Background())
		if err == nil {
			t.Error("a queue-read failure must surface — there is no work to do without it")
		}
	})
}

// A fold failure is skipped like a feed failure: one card that cannot be written must not stall
// the rest of the sweep, and it simply stays in the queue for the next run.
func TestReattributeSweep_AFoldFailureSkipsTheCard(t *testing.T) {
	repo := newRepo()
	repo.saveErr = errors.New("db down")
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{},
		domain.NewPrecedence("osv"), domain.NewTrustPolicy(nil))
	disc := &stubDiscover{byPURL: map[string][]app.ProposalFor{
		"p": {attributedFor(t, "CVE-2007-4559", "python-ply", "0:3.11-10")},
	}}
	reader := stubCardReader{cards: []app.UnattributedCard{card(t, "CVE-2007-4559", "p", "n", "s")}}

	n, err := app.NewReattributeService(reader, disc, fold, 0).Sweep(context.Background())
	if err != nil || n != 0 {
		t.Errorf("folded=%d err=%v, want a skipped card and no error", n, err)
	}
}
