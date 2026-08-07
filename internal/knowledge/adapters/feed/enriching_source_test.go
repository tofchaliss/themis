package feed_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
	"github.com/themis-project/themis/internal/knowledge/app"
)

type fakeRawChanged struct {
	out []app.ProposalFor
	err error
}

func (f fakeRawChanged) ChangedSince(context.Context, time.Time) ([]app.ProposalFor, error) {
	return f.out, f.err
}

type fakeKnownCVEs struct {
	set    map[string]struct{}
	err    error
	called bool
}

func (f *fakeKnownCVEs) KnownCVEs(context.Context) (map[string]struct{}, error) {
	f.called = true
	return f.set, f.err
}

func newCVEID(t *testing.T, s string) value.CVEID {
	t.Helper()
	c, err := value.NewCVEID(s)
	if err != nil {
		t.Fatalf("cve %q: %v", s, err)
	}
	return c
}

func TestRelevanceFilteredSource(t *testing.T) {
	ctx := context.Background()
	a := app.ProposalFor{CVE: newCVEID(t, "CVE-2024-1")}
	b := app.ProposalFor{CVE: newCVEID(t, "CVE-2024-2")}

	// Only CVEs that already have a card pass through.
	src := feed.NewRelevanceFilteredSource("nvd",
		fakeRawChanged{out: []app.ProposalFor{a, b}},
		&fakeKnownCVEs{set: map[string]struct{}{"CVE-2024-1": {}}})
	got, err := src.ChangedSince(ctx, time.Time{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 1 || got[0].CVE.String() != "CVE-2024-1" {
		t.Fatalf("got %+v, want only CVE-2024-1", got)
	}

	// Empty known set -> nothing survives.
	src = feed.NewRelevanceFilteredSource("nvd", fakeRawChanged{out: []app.ProposalFor{a}}, &fakeKnownCVEs{set: map[string]struct{}{}})
	if got, _ := src.ChangedSince(ctx, time.Time{}); len(got) != 0 {
		t.Errorf("empty-known: got %d, want 0", len(got))
	}

	// No changes -> nothing, and the known set is not consulted.
	known := &fakeKnownCVEs{err: errors.New("must not be called")}
	src = feed.NewRelevanceFilteredSource("nvd", fakeRawChanged{out: nil}, known)
	if got, err := src.ChangedSince(ctx, time.Time{}); err != nil || len(got) != 0 {
		t.Errorf("no-changes: got (%+v,%v)", got, err)
	}
	if known.called {
		t.Error("no-changes: KnownCVEs must not be consulted when nothing changed")
	}

	// Raw error propagates.
	src = feed.NewRelevanceFilteredSource("nvd", fakeRawChanged{err: errors.New("boom")}, &fakeKnownCVEs{})
	if _, err := src.ChangedSince(ctx, time.Time{}); err == nil {
		t.Error("raw error: expected error")
	}

	// Known-set error propagates.
	src = feed.NewRelevanceFilteredSource("nvd", fakeRawChanged{out: []app.ProposalFor{a}}, &fakeKnownCVEs{err: errors.New("boom")})
	if _, err := src.ChangedSince(ctx, time.Time{}); err == nil {
		t.Error("known error: expected error")
	}
}

// The empty-feed path returns early, and must still record — "the feed returned nothing" is one
// of the two cases these counters exist to tell apart, so it is the last one that may go
// unrecorded. Asserted through the behaviour the early return governs: an empty raw feed still
// yields no proposals and no error, and the known-CVE set is never consulted.
func TestRelevanceFilteredSource_EmptyFeedShortCircuitsWithoutConsultingKnownCVEs(t *testing.T) {
	known := &fakeKnownCVEs{}
	src := feed.NewRelevanceFilteredSource("nvd", fakeRawChanged{}, known)

	out, err := src.ChangedSince(context.Background(), time.Time{})
	if err != nil || len(out) != 0 {
		t.Fatalf("out=%v err=%v, want no proposals and no error", out, err)
	}
	if known.called {
		t.Error("known-CVE set consulted for an empty feed — the early return should short-circuit")
	}
}
