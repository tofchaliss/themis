package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// stubStale hands the sweep a fixed page of stale cards.
type stubStale struct {
	cards []app.StaleCard
	err   error
	gotGn int
	gotLm int
}

func (s *stubStale) StaleClassificationCards(_ context.Context, generation, limit int) ([]app.StaleCard, error) {
	s.gotGn, s.gotLm = generation, limit
	return s.cards, s.err
}

// stubStamper records what the sweep stamped and what it emitted.
type stubStamper struct {
	err     error
	stamped []stampCall
}

type stampCall struct {
	id                domain.FaultlineID
	version, generatn int
	notes             int
	classes           []domain.ClaimClass
}

func (s *stubStamper) StampReclassified(_ context.Context, id domain.FaultlineID,
	version, generation int, notes []app.OutboxNote) error {
	if s.err != nil {
		return s.err
	}
	call := stampCall{id: id, version: version, generatn: generation, notes: len(notes)}
	for _, n := range notes {
		if ev, ok := n.Event.(domain.ComponentMatched); ok {
			for _, c := range ev.Components {
				call.classes = append(call.classes, c.ClaimClass)
			}
		}
	}
	s.stamped = append(s.stamped, call)
	return nil
}

// cardWithCarriers builds a saved card carrying the given carrier products, so the sweep has
// something real to classify against.
func cardWithCarriers(t *testing.T, repo *fakeRepo, cveID string, carriers ...string) domain.Faultline {
	t.Helper()
	svc := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{},
		domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))
	cve, err := value.NewCVEID(cveID)
	if err != nil {
		t.Fatalf("cve: %v", err)
	}
	p, err := domain.NewVulnFactsProposal("nvd", fixedClock{}.Now(), domain.VulnFacts{
		Severity: value.SeverityHigh, CarrierProducts: carriers,
	})
	if err != nil {
		t.Fatalf("proposal: %v", err)
	}
	f, _, err := svc.FoldProposal(context.Background(), cve, p)
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	return f
}

// The sweep exists for the two things no fold signals: history, and a change to the
// classification RULES (which advances no card version and folds nothing). Both carrier fixes
// in claimclass.go shipped invisible for exactly that reason — KN-VERDICT-2's failure shape.
func TestReclassifySweepReAnnouncesWithFreshClasses(t *testing.T) {
	repo := newRepo()
	card := cardWithCarriers(t, repo, "CVE-2023-31122", "spring_framework")
	matches := &reMatches{occ: []app.MatchedOccurrence{
		{ReleaseID: "rel-1", Component: app.InventoryComponent{
			PURL: "pkg:maven/org.springframework/spring-core@5.3.0", Name: "spring-core", Version: "5.3.0",
		}},
		{ReleaseID: "rel-1", Component: app.InventoryComponent{
			PURL: "pkg:maven/com.other/unrelated@1.0", Name: "unrelated", Version: "1.0",
		}},
	}}
	stale := &stubStale{cards: []app.StaleCard{{ID: card.ID(), Version: card.Version()}}}
	stamper := &stubStamper{}

	svc := app.NewReclassifyService(stale, stamper, repo, matches, fixedClock{}, 5)
	cards, occurrences, full, err := svc.Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if cards != 1 || occurrences != 2 {
		t.Fatalf("sweep = %d cards / %d occurrences, want 1/2", cards, occurrences)
	}
	if full {
		t.Error("a batch of 1 against a limit of 5 is not full")
	}
	if stale.gotGn != domain.ClassifierGeneration || stale.gotLm != 5 {
		t.Errorf("queried generation %d limit %d, want %d/5", stale.gotGn, stale.gotLm, domain.ClassifierGeneration)
	}
	if len(stamper.stamped) != 1 {
		t.Fatalf("stamped %d cards, want 1", len(stamper.stamped))
	}
	got := stamper.stamped[0]
	if got.version != card.Version() || got.generatn != domain.ClassifierGeneration {
		t.Errorf("stamped version %d generation %d, want %d/%d",
			got.version, got.generatn, card.Version(), domain.ClassifierGeneration)
	}
	// The point of the whole arc: the re-announced class is computed by the CURRENT rules, so
	// spring-core resolves to its framework's carrier through the shared-token rule while the
	// genuine bystander on the same card stays scope.
	if len(got.classes) != 2 || got.classes[0] != domain.ClaimCarrier || got.classes[1] != domain.ClaimScope {
		t.Errorf("re-announced classes = %v, want [carrier scope]", got.classes)
	}
}

// A card with no recorded occurrences is still STAMPED. It has nothing to announce, and leaving
// it unstamped would make every later sweep re-read the same rows forever — the sweep would
// never converge and a real rule-change drain could never finish.
func TestReclassifySweepStampsCardsWithNoOccurrences(t *testing.T) {
	repo := newRepo()
	card := cardWithCarriers(t, repo, "CVE-2023-31122", "http_server")
	svc := app.NewReclassifyService(
		&stubStale{cards: []app.StaleCard{{ID: card.ID(), Version: card.Version()}}},
		&stubStamper{}, repo, &reMatches{}, fixedClock{}, 5)
	cards, occurrences, _, err := svc.Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if cards != 1 || occurrences != 0 {
		t.Errorf("sweep = %d cards / %d occurrences, want 1/0 — an empty card must still stamp", cards, occurrences)
	}
}

// full == true is how the loop knows to drain again instead of waiting out the interval; it is
// what turns a rule-generation bump into consecutive sweeps rather than days of ticks.
func TestReclassifySweepReportsAFullBatch(t *testing.T) {
	repo := newRepo()
	a := cardWithCarriers(t, repo, "CVE-2023-31122", "perl")
	b := cardWithCarriers(t, repo, "CVE-2019-10086", "commons-beanutils")
	svc := app.NewReclassifyService(
		&stubStale{cards: []app.StaleCard{{ID: a.ID()}, {ID: b.ID()}}},
		&stubStamper{}, repo, &reMatches{}, fixedClock{}, 2)
	_, _, full, err := svc.Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if !full {
		t.Error("a batch that filled the limit must report full so the caller drains again")
	}
}

// Nothing stale is the steady state and must be free: no card reads, no stamps, no error.
func TestReclassifySweepNothingStale(t *testing.T) {
	stamper := &stubStamper{}
	svc := app.NewReclassifyService(&stubStale{}, stamper, newRepo(), &reMatches{}, fixedClock{}, 5)
	cards, occurrences, full, err := svc.Sweep(context.Background())
	if err != nil || cards != 0 || occurrences != 0 || full {
		t.Fatalf("sweep = %d/%d/%v/%v, want 0/0/false/nil", cards, occurrences, full, err)
	}
	if len(stamper.stamped) != 0 {
		t.Error("nothing stale must stamp nothing")
	}
}

// Every failure propagates. A sweep that swallowed an error would stamp cards it never
// re-announced, or silently stop draining — the failure mode that makes a safety net a hazard.
func TestReclassifySweepErrorsPropagate(t *testing.T) {
	boom := errors.New("boom")
	repo := newRepo()
	card := cardWithCarriers(t, repo, "CVE-2023-31122", "perl")
	one := []app.StaleCard{{ID: card.ID(), Version: card.Version()}}

	for _, tc := range []struct {
		name string
		svc  *app.ReclassifyService
	}{
		{"listing stale cards", app.NewReclassifyService(
			&stubStale{err: boom}, &stubStamper{}, repo, &reMatches{}, fixedClock{}, 5)},
		{"loading the card", app.NewReclassifyService(
			&stubStale{cards: []app.StaleCard{{ID: "ghost"}}}, &stubStamper{}, repo, &reMatches{}, fixedClock{}, 5)},
		{"reading the matches", app.NewReclassifyService(
			&stubStale{cards: one}, &stubStamper{}, repo, &reMatches{err: boom}, fixedClock{}, 5)},
		{"stamping", app.NewReclassifyService(
			&stubStale{cards: one}, &stubStamper{err: boom}, repo, &reMatches{}, fixedClock{}, 5)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := tc.svc.Sweep(context.Background()); err == nil {
				t.Errorf("a failure %s must propagate", tc.name)
			}
		})
	}
}

// A misconfigured knob must not turn the sweep into an unbounded pass, or a zero one.
func TestReclassifyBatchFallsBackToTheDefault(t *testing.T) {
	stale := &stubStale{}
	for _, batch := range []int{0, -7} {
		svc := app.NewReclassifyService(stale, &stubStamper{}, newRepo(), &reMatches{}, fixedClock{}, batch)
		if _, _, _, err := svc.Sweep(context.Background()); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		if stale.gotLm != app.DefaultReclassifyBatch {
			t.Errorf("batch %d queried limit %d, want the default %d", batch, stale.gotLm, app.DefaultReclassifyBatch)
		}
	}
}

// Generation is exposed so the composition root can log which rules it applied without
// importing the domain ring.
func TestReclassifyGenerationIsTheDomainConstant(t *testing.T) {
	svc := app.NewReclassifyService(&stubStale{}, &stubStamper{}, newRepo(), &reMatches{}, fixedClock{}, 1)
	if svc.Generation() != domain.ClassifierGeneration {
		t.Errorf("Generation() = %d, want %d", svc.Generation(), domain.ClassifierGeneration)
	}
}
