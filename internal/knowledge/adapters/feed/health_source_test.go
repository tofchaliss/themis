package feed_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type fakeDiscovery struct {
	out []app.ProposalFor
	err error
}

func (f *fakeDiscovery) VulnsForPackage(context.Context, app.InventoryComponent) ([]app.ProposalFor, error) {
	return f.out, f.err
}

type recordingHealth struct {
	successes, failures []string
	tiers               []domain.Tier
	err                 error
}

func (r *recordingHealth) RecordSuccess(_ context.Context, source string, tier domain.Tier) error {
	r.successes = append(r.successes, source)
	r.tiers = append(r.tiers, tier)
	return r.err
}

func (r *recordingHealth) RecordFailure(_ context.Context, source string, tier domain.Tier) error {
	r.failures = append(r.failures, source)
	r.tiers = append(r.tiers, tier)
	return r.err
}

// OSV is queried per component on every upload and has no poll loop, so it was the one feed
// that ran constantly and reported no health at all — an outage looked like "nothing to find".
func TestHealthRecordingSource_RecordsSuccessWithTheSourcesTier(t *testing.T) {
	h := &recordingHealth{}
	src := feed.NewHealthRecordingSource("osv", &fakeDiscovery{}, h)

	if _, err := src.VulnsForPackage(context.Background(), app.InventoryComponent{Name: "urllib3"}); err != nil {
		t.Fatalf("VulnsForPackage: %v", err)
	}
	if len(h.successes) != 1 || h.successes[0] != "osv" {
		t.Fatalf("successes = %v, want one for osv", h.successes)
	}
	// The tier comes from the shared taxonomy, so GET /feeds evaluates OSV against its tier's
	// staleness rules rather than as a special case.
	if h.tiers[0] != feed.TierFor("osv") {
		t.Errorf("tier = %v, want %v", h.tiers[0], feed.TierFor("osv"))
	}
}

func TestHealthRecordingSource_RecordsFailureAndPropagatesTheError(t *testing.T) {
	h := &recordingHealth{}
	want := errors.New("osv down")
	src := feed.NewHealthRecordingSource("osv", &fakeDiscovery{err: want}, h)

	if _, err := src.VulnsForPackage(context.Background(), app.InventoryComponent{}); !errors.Is(err, want) {
		t.Fatalf("err = %v, want it propagated — health recording must not swallow a discovery failure", err)
	}
	if len(h.failures) != 1 {
		t.Fatalf("failures = %v, want one", h.failures)
	}
}

// Health is an observation ABOUT the pipeline and must never be able to fail the pipeline.
// Losing a health stamp costs a stale timestamp; failing correlation costs the enterprise its
// vulnerability discovery.
func TestHealthRecordingSource_HealthWriteFailureDoesNotFailDiscovery(t *testing.T) {
	h := &recordingHealth{err: errors.New("db down")}
	src := feed.NewHealthRecordingSource("osv", &fakeDiscovery{out: []app.ProposalFor{{}}}, h)

	got, err := src.VulnsForPackage(context.Background(), app.InventoryComponent{})
	if err != nil {
		t.Fatalf("err = %v, want nil — a health-write failure must not break correlation", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d proposals, want the discovery result passed through", len(got))
	}
}

// A caller without health wiring gets the raw source back, so the decorator is opt-in and a
// composition root that has no health service is unaffected.
func TestHealthRecordingSource_NilRecorderReturnsTheRawSource(t *testing.T) {
	raw := &fakeDiscovery{out: []app.ProposalFor{{}}}
	if got := feed.NewHealthRecordingSource("osv", raw, nil); got != app.PackageVulnSource(raw) {
		t.Fatal("want the raw source returned unwrapped when no recorder is supplied")
	}
}

// One aggregate `osv` row cannot distinguish "Alpine data flowing" from "Alpine data quietly
// absent" while rocky uploads keep the row green (GUI-4). A distro component therefore records
// a second, per-distro row — at Tier3Enrichment, whose StaleThreshold is zero, so a distro
// nobody uploads reads as an old timestamp and never as a degraded feed.
func TestHealthRecordingSource_DistroComponentAlsoRecordsPerDistroRow(t *testing.T) {
	cases := []struct {
		purl string
		want string
	}{
		{"pkg:apk/alpine/openssl@3.1.4-r5?distro=alpine-3.18.4", "osv/alpine"},
		{"pkg:rpm/rocky/openssl-libs@3.0.7?distro=rocky-8.10", "osv/rocky"},
		{"pkg:rpm/rockylinux/openssl-libs@3.0.7?distro=rockylinux-8.10", "osv/rocky"},
		{"pkg:rpm/almalinux/openssl-libs@3.0.7?distro=almalinux-9.3", "osv/alma"},
		{"pkg:rpm/redhat/openssl-libs@3.0.7?distro=redhat-8.10", "osv/rhel"},
		{"pkg:deb/debian/openssl@3.0.11?distro=debian-12", "osv/debian"},
		{"pkg:apk/wolfi/openssl@3.1.4?distro=wolfi", "osv/wolfi"},
	}
	for _, tc := range cases {
		h := &recordingHealth{}
		src := feed.NewHealthRecordingSource("osv", &fakeDiscovery{}, h)
		if _, err := src.VulnsForPackage(context.Background(), app.InventoryComponent{PURL: tc.purl}); err != nil {
			t.Fatalf("%s: %v", tc.purl, err)
		}
		if len(h.successes) != 2 || h.successes[0] != "osv" || h.successes[1] != tc.want {
			t.Fatalf("%s: successes = %v, want [osv %s]", tc.purl, h.successes, tc.want)
		}
		if h.tiers[1] != domain.Tier3Enrichment {
			t.Errorf("%s: per-distro tier = %v, want Tier3Enrichment (quiet must never mean degraded)", tc.purl, h.tiers[1])
		}
	}
}

// A failure lands on the per-distro row too — a live outage during an alpine query is an
// alpine-visible fact, not only an aggregate one.
func TestHealthRecordingSource_DistroComponentRecordsPerDistroFailure(t *testing.T) {
	h := &recordingHealth{}
	src := feed.NewHealthRecordingSource("osv", &fakeDiscovery{err: errors.New("osv down")}, h)

	_, _ = src.VulnsForPackage(context.Background(),
		app.InventoryComponent{PURL: "pkg:apk/alpine/openssl@3.1.4-r5?distro=alpine-3.18.4"})
	if len(h.failures) != 2 || h.failures[1] != "osv/alpine" {
		t.Fatalf("failures = %v, want [osv osv/alpine]", h.failures)
	}
}

// Non-distro components and distro PURLs without a distro qualifier stay on the aggregate row
// only — a language-ecosystem query says nothing about any distro's coverage.
func TestHealthRecordingSource_NonDistroRecordsAggregateRowOnly(t *testing.T) {
	for _, purl := range []string{
		"pkg:pypi/urllib3@2.0.7",
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
		"pkg:rpm/rocky/openssl-libs@3.0.7", // rpm but no distro qualifier
		"",
	} {
		h := &recordingHealth{}
		src := feed.NewHealthRecordingSource("osv", &fakeDiscovery{}, h)
		if _, err := src.VulnsForPackage(context.Background(), app.InventoryComponent{PURL: purl}); err != nil {
			t.Fatalf("%q: %v", purl, err)
		}
		if len(h.successes) != 1 || h.successes[0] != "osv" {
			t.Fatalf("%q: successes = %v, want [osv] only", purl, h.successes)
		}
	}
}
