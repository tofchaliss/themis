package app_test

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// reMatches lists one recorded occurrence of a card.
type reMatches struct {
	occ []app.MatchedOccurrence
	err error
}

func (m *reMatches) MatchesForFaultline(context.Context, string) ([]app.MatchedOccurrence, error) {
	return m.occ, m.err
}

func countNotes(notes []app.OutboxNote, typ string) int {
	n := 0
	for _, note := range notes {
		if note.EventType == typ {
			n++
		}
	}
	return n
}

// EDR-CORRELATION-01 D3/D4 — carrier attribution arriving AFTER correlation must correct the
// classes already stamped on a card's matches.
//
// Without this the class stamped at match time is the one that lasts. Measured on the VM: 370
// components all `unknown` while NVD was enriching the cards around them, because classification
// runs at correlation and a stable estate never correlates again. Step 2 would have shipped inert.
func TestFoldProposal_ReannouncesMatchesWhenCarriersFirstArrive(t *testing.T) {
	ctx := context.Background()
	matches := &reMatches{occ: []app.MatchedOccurrence{{
		ReleaseID: "rel-1",
		Component: app.InventoryComponent{
			PURL: "pkg:rpm/rocky/javapackages-filesystem@5.3.0", Name: "javapackages-filesystem",
			Version: "5.3.0", Ecosystem: "rpm", Source: "javapackages-tools",
		},
	}}}
	repo := newRepo()
	svc := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{},
		domain.NewPrecedence("nvd", "osv"), domain.NewTrustPolicy(nil)).WithMatchReader(matches)

	cve, err := value.NewCVEID("CVE-2019-10086")
	if err != nil {
		t.Fatalf("cve: %v", err)
	}
	mk := func(src string, carriers ...string) domain.Proposal {
		p, perr := domain.NewVulnFactsProposal(src, fixedClock{}.Now(), domain.VulnFacts{
			Severity: value.SeverityHigh, CarrierProducts: carriers,
			AffectedRanges: []string{"<" + src}, // makes each fold a real view change
		})
		if perr != nil {
			t.Fatalf("proposal: %v", perr)
		}
		return p
	}

	// No carriers named yet: nothing is decidable, so nothing is re-announced.
	if _, _, err := svc.FoldProposal(ctx, cve, mk("osv")); err != nil {
		t.Fatalf("fold bare: %v", err)
	}
	if got := countNotes(repo.lastNotes, app.EventComponentMatched); got != 0 {
		t.Fatalf("re-announced %d matches before any carrier was known, want 0", got)
	}

	// NVD names the carrier — the bystander's class becomes decidable.
	if _, _, err := svc.FoldProposal(ctx, cve, mk("nvd", "commons-beanutils")); err != nil {
		t.Fatalf("fold with carrier: %v", err)
	}
	notes := repo.lastNotes
	if got := countNotes(notes, app.EventComponentMatched); got != 1 {
		t.Fatalf("re-announced %d matches on the first carrier, want 1", got)
	}
	var ev domain.ComponentMatched
	for _, n := range notes {
		if n.EventType == app.EventComponentMatched {
			ev = n.Event.(domain.ComponentMatched)
		}
	}
	if len(ev.Components) != 1 || ev.Components[0].ClaimClass != domain.ClaimScope {
		t.Errorf("re-announced class = %q, want scope — javapackages-filesystem does not carry a BeanUtils flaw",
			ev.Components[0].ClaimClass)
	}

	// A LATER enrichment must not re-announce again: the trigger is the empty→non-empty
	// transition, once per card, not every enrichment.
	if _, _, err := svc.FoldProposal(ctx, cve, mk("redhat", "commons-beanutils")); err != nil {
		t.Fatalf("fold again: %v", err)
	}
	if got := countNotes(repo.lastNotes, app.EventComponentMatched); got != 0 {
		t.Errorf("re-announced again (%d), want 0 — the trigger is the transition", got)
	}
}

// No match reader wired (single-context dev) must be a silent no-op, never a nil dereference.
func TestFoldProposal_NoMatchReaderIsANoOp(t *testing.T) {
	repo := newRepo()
	svc := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{},
		domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))
	cve, _ := value.NewCVEID("CVE-2019-10086")
	p, _ := domain.NewVulnFactsProposal("nvd", fixedClock{}.Now(), domain.VulnFacts{
		Severity: value.SeverityHigh, CarrierProducts: []string{"commons-beanutils"},
	})
	if _, _, err := svc.FoldProposal(context.Background(), cve, p); err != nil {
		t.Fatalf("fold: %v", err)
	}
}

// A match-reader failure propagates rather than silently leaving classes stale.
func TestFoldProposal_MatchReaderErrorPropagates(t *testing.T) {
	repo := newRepo()
	svc := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{},
		domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil)).
		WithMatchReader(&reMatches{err: context.DeadlineExceeded})
	cve, _ := value.NewCVEID("CVE-2019-10086")
	p, _ := domain.NewVulnFactsProposal("nvd", fixedClock{}.Now(), domain.VulnFacts{
		Severity: value.SeverityHigh, CarrierProducts: []string{"commons-beanutils"},
	})
	if _, _, err := svc.FoldProposal(context.Background(), cve, p); err == nil {
		t.Error("a match-reader error must propagate")
	}
}
