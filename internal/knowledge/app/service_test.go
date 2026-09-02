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

// vulnFactsFixedFor states a fix for an EXPLICIT package — used where the version string alone
// carries no name (a bare EVR), so the test controls the attribution it is exercising.
func vulnFactsFixedFor(t *testing.T, source, pkg string, fixed ...string) domain.Proposal {
	t.Helper()
	c, _ := value.NewCVSS(7.5, "")
	fixes := make([]domain.FixedVersion, 0, len(fixed))
	for _, f := range fixed {
		fixes = append(fixes, domain.FixedVersion{Package: pkg, Version: f})
	}
	p, err := domain.NewVulnFactsProposal(source, time.Unix(1_700_000_000, 0),
		domain.VulnFacts{Severity: value.SeverityHigh, CVSS: c, Fixes: fixes})
	if err != nil {
		t.Fatalf("proposal: %v", err)
	}
	return p
}

type seqIDs struct{ n int }

func (s *seqIDs) NewID() string { s.n++; return "fl-" + string(rune('0'+s.n)) }

type emptyIDs struct{}

func (emptyIDs) NewID() string { return "" }

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1_700_000_000, 0) }

func svc(repo app.Repository, ids app.IDGenerator) *app.FaultlineService {
	return app.NewFaultlineService(repo, ids, fixedClock{}, domain.NewPrecedence("redhat", "nvd", "osv"), domain.NewTrustPolicy(nil))
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

// vulnFactsRanged builds an NVD vuln-facts Proposal carrying affected-range groups, so a
// reconciled view exposes them to the correlation range gate (A1 / D3).
func vulnFactsRanged(t *testing.T, source string, ranges ...string) domain.Proposal {
	t.Helper()
	c, _ := value.NewCVSS(7.5, "")
	p, err := domain.NewVulnFactsProposal(source, time.Unix(1_700_000_000, 0),
		domain.VulnFacts{Severity: value.SeverityHigh, CVSS: c, AffectedRanges: ranges})
	if err != nil {
		t.Fatalf("proposal: %v", err)
	}
	return p
}

// vulnFactsFixedApk mirrors the Alpine ACL (EDR-VEX-01 D7): a secdb fix bound arrives
// positively stamped `apk`, which is what qualifies it for the strict verdict selection (D9).
func vulnFactsFixedApk(t *testing.T, source, pkg string, fixed ...string) domain.Proposal {
	t.Helper()
	fixes := make([]domain.FixedVersion, 0, len(fixed))
	for _, f := range fixed {
		fixes = append(fixes, domain.FixedVersion{Package: pkg, Version: f, Ecosystem: "apk"})
	}
	p, err := domain.NewVulnFactsProposal(source, time.Unix(1_700_000_000, 0),
		domain.VulnFacts{Severity: value.SeverityUnknown, Fixes: fixes})
	if err != nil {
		t.Fatalf("proposal: %v", err)
	}
	return p
}

// vulnFactsFixed builds a vuln-facts Proposal carrying fixed versions (e.g. Red Hat main-stream
// fix NEVRAs), so a reconciled view exposes them to correlation's stream-scoped fixed gate.
// vulnFactsFixed mirrors the Red Hat ACL: a vendor fix is stated as a NEVRA, so its package is
// extracted from the string. Using UnattributedFixes here instead would make the fixed-verdict
// tests pass for the wrong reason — an unattributed fix can never fire the verdict (KN-FIX-1).
func vulnFactsFixed(t *testing.T, source string, fixed ...string) domain.Proposal {
	t.Helper()
	c, _ := value.NewCVSS(7.5, "")
	fixes := make([]domain.FixedVersion, 0, len(fixed))
	for _, f := range fixed {
		fixes = append(fixes, domain.FixedVersion{Package: value.RPMPackageName(f), Version: f})
	}
	p, err := domain.NewVulnFactsProposal(source, time.Unix(1_700_000_000, 0),
		domain.VulnFacts{Severity: value.SeverityHigh, CVSS: c, Fixes: fixes})
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
	f, _, err := svc(repo, &seqIDs{}).FoldProposal(context.Background(), cve(t, "CVE-2024-1"), vulnFacts(t, "nvd", value.SeverityHigh))
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	if f.ID() == "" {
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

	if _, _, err := s.FoldProposal(ctx, c, vulnFacts(t, "nvd", value.SeverityMedium)); err != nil {
		t.Fatal(err)
	}
	// A higher-authority proposal changes the view → Enriched only (card exists).
	if _, _, err := s.FoldProposal(ctx, c, vulnFacts(t, "redhat", value.SeverityCritical)); err != nil {
		t.Fatal(err)
	}
	if got := noteTypes(repo.lastNotes); len(got) != 1 || got[0] != app.EventFaultlineEnriched {
		t.Errorf("notes = %v, want [enriched]", got)
	}
	// Re-folding an identical proposal changes nothing → no events.
	if _, _, err := s.FoldProposal(ctx, c, vulnFacts(t, "redhat", value.SeverityCritical)); err != nil {
		t.Fatal(err)
	}
	if got := noteTypes(repo.lastNotes); len(got) != 0 {
		t.Errorf("duplicate fold notes = %v, want none", got)
	}
}

func TestFoldProposal_RetryConverges(t *testing.T) {
	repo := newRepo()
	repo.conflictFor = 2 // first two saves conflict, third wins
	f, _, err := svc(repo, &seqIDs{}).FoldProposal(context.Background(), cve(t, "CVE-2024-1"), vulnFacts(t, "nvd", value.SeverityHigh))
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	if f.ID() == "" || repo.saveCalls != 3 {
		t.Errorf("expected convergence after 3 saves, got id=%q saves=%d", f.ID(), repo.saveCalls)
	}
}

func TestFoldProposal_Errors(t *testing.T) {
	ctx := context.Background()
	p := vulnFacts(t, "nvd", value.SeverityHigh)

	// Zero CVE.
	if _, _, err := svc(newRepo(), &seqIDs{}).FoldProposal(ctx, value.CVEID{}, p); err == nil {
		t.Error("zero cve: expected error")
	}
	// Get error propagates.
	ge := newRepo()
	ge.getErr = errors.New("db down")
	if _, _, err := svc(ge, &seqIDs{}).FoldProposal(ctx, cve(t, "CVE-2024-1"), p); err == nil {
		t.Error("get error: expected error")
	}
	// Non-concurrent save error propagates.
	se := newRepo()
	se.saveErr = errors.New("write failed")
	if _, _, err := svc(se, &seqIDs{}).FoldProposal(ctx, cve(t, "CVE-2024-1"), p); err == nil {
		t.Error("save error: expected error")
	}
	// Retry exhausted → ErrConcurrent.
	ce := newRepo()
	ce.conflictFor = 99
	if _, _, err := svc(ce, &seqIDs{}).FoldProposal(ctx, cve(t, "CVE-2024-1"), p); !errors.Is(err, app.ErrConcurrent) {
		t.Errorf("exhausted retries err = %v, want ErrConcurrent", err)
	}
	// New-faultline construction failure (empty id from the generator).
	if _, _, err := svc(newRepo(), emptyIDs{}).FoldProposal(ctx, cve(t, "CVE-2024-1"), p); err == nil {
		t.Error("empty id: expected NewFaultline error")
	}
}

// SupersedeFaultline is the producer half of the withdrawal path (KN-WITHDRAW-1). Its edges
// matter because it is driven by an external feed's opinion about a CVE.
func TestSupersedeFaultline_Edges(t *testing.T) {
	ctx := context.Background()

	t.Run("zero cve is rejected", func(t *testing.T) {
		svc := app.NewFaultlineService(newRepo(), &seqIDs{}, fixedClock{},
			domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))
		if _, err := svc.SupersedeFaultline(ctx, value.CVEID{}, "nvd"); err == nil {
			t.Fatal("want an error for a zero CVE")
		}
	})

	t.Run("a read failure propagates", func(t *testing.T) {
		repo := newRepo()
		repo.getErr = errors.New("db down")
		svc := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{},
			domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))
		if _, err := svc.SupersedeFaultline(ctx, cve(t, "CVE-2024-1"), "nvd"); err == nil {
			t.Fatal("want the read error propagated")
		}
	})

	t.Run("a write failure propagates", func(t *testing.T) {
		repo := newRepo()
		svc := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{},
			domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))
		if _, _, err := svc.FoldProposal(ctx, cve(t, "CVE-2024-1"), vulnFacts(t, "nvd", value.SeverityHigh)); err != nil {
			t.Fatalf("seed: %v", err)
		}
		repo.saveErr = errors.New("db down")
		if _, err := svc.SupersedeFaultline(ctx, cve(t, "CVE-2024-1"), "nvd"); err == nil {
			t.Fatal("want the write error propagated")
		}
	})

	// A concurrent modification is retried, because superseding is additive-to-terminal and
	// converges — the same reasoning that lets FoldProposal retry.
	t.Run("a concurrency conflict retries and converges", func(t *testing.T) {
		repo := newRepo()
		svc := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{},
			domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))
		if _, _, err := svc.FoldProposal(ctx, cve(t, "CVE-2024-1"), vulnFacts(t, "nvd", value.SeverityHigh)); err != nil {
			t.Fatalf("seed: %v", err)
		}
		repo.saveCalls, repo.conflictFor = 0, 1 // first save conflicts, second succeeds
		changed, err := svc.SupersedeFaultline(ctx, cve(t, "CVE-2024-1"), "nvd")
		if err != nil || !changed {
			t.Fatalf("changed=%v err=%v, want a retried success", changed, err)
		}
	})
}

// Exhausting the retry budget surfaces as ErrConcurrent rather than a silent no-op: a card that
// could not be superseded must not look like one that was already terminal, or a withdrawn CVE
// would be quietly left alive.
// TRUST-4: the superseded event carries the class of the source that reported the withdrawal,
// classified from the injected policy table — NOT a constant.
//
// Governance used to state "a withdrawal is Observed" unconditionally. Table-driving both a
// registered Observed source and an unregistered one (which fails closed to Asserted) proves the
// class is read from provenance, so a withdrawal Themis cannot re-derive is no longer laundered
// into the class that policy auto-acceptance rests on.
func TestSupersedeFaultline_CarriesTheReportingSourcesTrustClass(t *testing.T) {
	ctx := context.Background()
	policy := domain.NewTrustPolicy(map[string]value.TrustClass{"nvd": value.TrustObserved})

	for _, tc := range []struct {
		name, source string
		want         value.TrustClass
	}{
		{"a classified public record is Observed", "nvd", value.TrustObserved},
		{"an unregistered source fails closed to Asserted", "some-vendor", value.TrustAsserted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newRepo()
			svc := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{}, domain.NewPrecedence("nvd"), policy)
			if _, _, err := svc.FoldProposal(ctx, cve(t, "CVE-2024-1"), vulnFacts(t, "nvd", value.SeverityHigh)); err != nil {
				t.Fatalf("seed: %v", err)
			}
			if _, err := svc.SupersedeFaultline(ctx, cve(t, "CVE-2024-1"), tc.source); err != nil {
				t.Fatalf("supersede: %v", err)
			}
			ev, ok := repo.lastNotes[0].Event.(domain.FaultlineSuperseded)
			if !ok {
				t.Fatalf("note 0 = %T, want FaultlineSuperseded", repo.lastNotes[0].Event)
			}
			if ev.Trust != tc.want {
				t.Errorf("Trust = %q, want %q", ev.Trust, tc.want)
			}
		})
	}
}

func TestSupersedeFaultline_ExhaustedRetriesReportConcurrent(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	svc := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{},
		domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))
	if _, _, err := svc.FoldProposal(ctx, cve(t, "CVE-2024-1"), vulnFacts(t, "nvd", value.SeverityHigh)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	repo.saveCalls, repo.conflictFor = 0, 1_000 // every save conflicts
	changed, err := svc.SupersedeFaultline(ctx, cve(t, "CVE-2024-1"), "nvd")
	if !errors.Is(err, app.ErrConcurrent) || changed {
		t.Fatalf("changed=%v err=%v, want ErrConcurrent", changed, err)
	}
}

// FoldProposal's `recorded` flag is what lets a sweep report honestly (KN-PROPOSAL-BLOAT-1).
// Observed on the VM: after the dedup landed, the exploit-signal sweep still logged "folded: 236"
// while writing ZERO rows — a stalled feed and a fully-caught-up one produced the same number.
func TestFoldProposal_ReportsWhetherTheProposalWasRecorded(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	s := svc(repo, &seqIDs{})
	c := cve(t, "CVE-2024-1")

	if _, recorded, err := s.FoldProposal(ctx, c, vulnFacts(t, "nvd", value.SeverityHigh)); err != nil || !recorded {
		t.Fatalf("first fold: recorded=%v err=%v, want recorded", recorded, err)
	}
	if _, recorded, err := s.FoldProposal(ctx, c, vulnFacts(t, "nvd", value.SeverityHigh)); err != nil || recorded {
		t.Errorf("restatement: recorded=%v err=%v, want NOT recorded", recorded, err)
	}
	// A genuinely new fact from the same source is recorded even though it may not change the
	// view — "recorded" is about the audit log, "ViewChanged" is about the event.
	if _, recorded, err := s.FoldProposal(ctx, c, vulnFacts(t, "nvd", value.SeverityCritical)); err != nil || !recorded {
		t.Errorf("changed fact: recorded=%v err=%v, want recorded", recorded, err)
	}
}
