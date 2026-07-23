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

type fakeRepo struct {
	cards       map[string]domain.Faultline
	saveCalls   int
	conflictFor int // return ErrConcurrent while saveCalls <= conflictFor
	getErr      error
	saveErr     error
	lastNotes   []app.OutboxNote
}

func newRepo() *fakeRepo { return &fakeRepo{cards: map[string]domain.Faultline{}} }

func (r *fakeRepo) GetByCVE(_ context.Context, cve string) (domain.Faultline, bool, error) {
	if r.getErr != nil {
		return domain.Faultline{}, false, r.getErr
	}
	f, ok := r.cards[cve]
	return f, ok, nil
}

func (r *fakeRepo) GetByID(_ context.Context, id domain.FaultlineID) (domain.Faultline, error) {
	for _, f := range r.cards {
		if f.ID() == id {
			return f, nil
		}
	}
	return domain.Faultline{}, errors.New("not found")
}

func (r *fakeRepo) Save(_ context.Context, f domain.Faultline, _ bool, _ int, notes []app.OutboxNote) error {
	r.saveCalls++
	if r.saveErr != nil {
		return r.saveErr
	}
	if r.saveCalls <= r.conflictFor {
		return app.ErrConcurrent
	}
	r.cards[f.CVE().String()] = f
	r.lastNotes = notes
	return nil
}

type seqIDs struct{ n int }

func (s *seqIDs) NewID() string { s.n++; return "fl-" + string(rune('0'+s.n)) }

type emptyIDs struct{}

func (emptyIDs) NewID() string { return "" }

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1_700_000_000, 0) }

func svc(repo app.Repository, ids app.IDGenerator) *app.FaultlineService {
	return app.NewFaultlineService(repo, ids, fixedClock{}, domain.NewPrecedence("redhat", "nvd", "osv"))
}

func cve(t *testing.T, s string) value.CVEID {
	t.Helper()
	c, err := value.NewCVEID(s)
	if err != nil {
		t.Fatalf("cve: %v", err)
	}
	return c
}

func vulnFacts(t *testing.T, source string, sev value.Severity) domain.Proposal {
	t.Helper()
	c, _ := value.NewCVSS(7.5, "")
	p, err := domain.NewVulnFactsProposal(source, time.Unix(1_700_000_000, 0), domain.VulnFacts{Severity: sev, CVSS: c})
	if err != nil {
		t.Fatalf("proposal: %v", err)
	}
	return p
}

func noteTypes(notes []app.OutboxNote) []string {
	out := make([]string, len(notes))
	for i, n := range notes {
		out[i] = n.EventType
	}
	return out
}

func TestFoldProposal_CreatesCard(t *testing.T) {
	repo := newRepo()
	id, err := svc(repo, &seqIDs{}).FoldProposal(context.Background(), cve(t, "CVE-2024-1"), vulnFacts(t, "nvd", value.SeverityHigh))
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	if id == "" {
		t.Fatal("empty faultline id")
	}
	// A new card fires Created + Enriched (view changed from empty).
	got := noteTypes(repo.lastNotes)
	if len(got) != 2 || got[0] != app.EventFaultlineCreated || got[1] != app.EventFaultlineEnriched {
		t.Errorf("notes = %v, want [created enriched]", got)
	}
}

func TestFoldProposal_EnrichAndNoOp(t *testing.T) {
	repo := newRepo()
	s := svc(repo, &seqIDs{})
	ctx := context.Background()
	c := cve(t, "CVE-2024-1")

	if _, err := s.FoldProposal(ctx, c, vulnFacts(t, "nvd", value.SeverityMedium)); err != nil {
		t.Fatal(err)
	}
	// A higher-authority proposal changes the view → Enriched only (card exists).
	if _, err := s.FoldProposal(ctx, c, vulnFacts(t, "redhat", value.SeverityCritical)); err != nil {
		t.Fatal(err)
	}
	if got := noteTypes(repo.lastNotes); len(got) != 1 || got[0] != app.EventFaultlineEnriched {
		t.Errorf("notes = %v, want [enriched]", got)
	}
	// Re-folding an identical proposal changes nothing → no events.
	if _, err := s.FoldProposal(ctx, c, vulnFacts(t, "redhat", value.SeverityCritical)); err != nil {
		t.Fatal(err)
	}
	if got := noteTypes(repo.lastNotes); len(got) != 0 {
		t.Errorf("duplicate fold notes = %v, want none", got)
	}
}

func TestFoldProposal_RetryConverges(t *testing.T) {
	repo := newRepo()
	repo.conflictFor = 2 // first two saves conflict, third wins
	id, err := svc(repo, &seqIDs{}).FoldProposal(context.Background(), cve(t, "CVE-2024-1"), vulnFacts(t, "nvd", value.SeverityHigh))
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	if id == "" || repo.saveCalls != 3 {
		t.Errorf("expected convergence after 3 saves, got id=%q saves=%d", id, repo.saveCalls)
	}
}

func TestFoldProposal_Errors(t *testing.T) {
	ctx := context.Background()
	p := vulnFacts(t, "nvd", value.SeverityHigh)

	// Zero CVE.
	if _, err := svc(newRepo(), &seqIDs{}).FoldProposal(ctx, value.CVEID{}, p); err == nil {
		t.Error("zero cve: expected error")
	}
	// Get error propagates.
	ge := newRepo()
	ge.getErr = errors.New("db down")
	if _, err := svc(ge, &seqIDs{}).FoldProposal(ctx, cve(t, "CVE-2024-1"), p); err == nil {
		t.Error("get error: expected error")
	}
	// Non-concurrent save error propagates.
	se := newRepo()
	se.saveErr = errors.New("write failed")
	if _, err := svc(se, &seqIDs{}).FoldProposal(ctx, cve(t, "CVE-2024-1"), p); err == nil {
		t.Error("save error: expected error")
	}
	// Retry exhausted → ErrConcurrent.
	ce := newRepo()
	ce.conflictFor = 99
	if _, err := svc(ce, &seqIDs{}).FoldProposal(ctx, cve(t, "CVE-2024-1"), p); !errors.Is(err, app.ErrConcurrent) {
		t.Errorf("exhausted retries err = %v, want ErrConcurrent", err)
	}
	// New-faultline construction failure (empty id from the generator).
	if _, err := svc(newRepo(), emptyIDs{}).FoldProposal(ctx, cve(t, "CVE-2024-1"), p); err == nil {
		t.Error("empty id: expected NewFaultline error")
	}
}
