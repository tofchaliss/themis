package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

type fakeUploadEvidence struct {
	refs     []app.SBOMRef
	inv      map[string]map[string]bool
	listErr  error
	invErrOn string
}

func (f *fakeUploadEvidence) SBOMsOfRelease(context.Context, string) ([]app.SBOMRef, error) {
	return f.refs, f.listErr
}

func (f *fakeUploadEvidence) InventoryPURLs(_ context.Context, id string) (map[string]bool, error) {
	if id == f.invErrOn {
		return nil, errors.New("evidence down")
	}
	return f.inv[id], nil
}

type fakeUploadFindings struct {
	fs  []domain.UploadFinding
	err error
}

func (f fakeUploadFindings) UploadFindings(context.Context, string) ([]domain.UploadFinding, error) {
	return f.fs, f.err
}

var upT0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func uploadFixture() (*fakeUploadEvidence, fakeUploadFindings) {
	ev := &fakeUploadEvidence{
		// Listed out of order, with a filing-time tie broken by id.
		refs: []app.SBOMRef{{ID: "sb-3", FiledAt: upT0.Add(2 * time.Hour)}, {ID: "sb-1", FiledAt: upT0}, {ID: "sb-0", FiledAt: upT0}},
		inv: map[string]map[string]bool{
			"sb-1": {"pkg:a@1": true, "pkg:b@1": true},
			"sb-3": {"pkg:a@1": true, "pkg:c@1": true},
		},
	}
	fs := fakeUploadFindings{fs: []domain.UploadFinding{
		{CVE: "CVE-A", Stage: domain.StageIdentified, CreatedAt: upT0.Add(-time.Hour), PURLs: []string{"pkg:a@1"}},
		{CVE: "CVE-B", Stage: domain.StageIdentified, CreatedAt: upT0.Add(-time.Hour), PURLs: []string{"pkg:b@1"}},
		{CVE: "CVE-C", Stage: domain.StageIdentified, CreatedAt: upT0.Add(3 * time.Hour), PURLs: []string{"pkg:c@1"}},
	}}
	return ev, fs
}

func TestUploadOutcomes_AgainstThePreviousSBOM(t *testing.T) {
	ev, fs := uploadFixture()
	got, err := app.NewUploadOutcomes(ev, fs).For(context.Background(), "rel-1", "sb-3")
	if err != nil || !got.HasBaseline || got.New != 1 || got.Unchanged != 1 || got.NoLongerPresent != 1 {
		t.Fatalf("outcome = %+v %v", got, err)
	}
	// sb-0 sorts before sb-1 on the tie, so sb-0 is the first SBOM: no baseline.
	first, err := app.NewUploadOutcomes(ev, fs).For(context.Background(), "rel-1", "sb-0")
	if err != nil || first.HasBaseline {
		t.Fatalf("first = %+v %v", first, err)
	}
}

func TestUploadOutcomes_Failures(t *testing.T) {
	ctx := context.Background()
	ev, fs := uploadFixture()
	if _, err := app.NewUploadOutcomes(ev, fs).For(ctx, "rel-1", "sb-unknown"); !errors.Is(err, app.ErrSBOMNotListed) {
		t.Fatalf("unlisted: %v", err)
	}
	ev.listErr = errors.New("down")
	if _, err := app.NewUploadOutcomes(ev, fs).For(ctx, "rel-1", "sb-3"); err == nil {
		t.Fatal("list error swallowed")
	}
	for _, on := range []string{"sb-3", "sb-1"} {
		ev, fs := uploadFixture()
		ev.invErrOn = on
		if _, err := app.NewUploadOutcomes(ev, fs).For(ctx, "rel-1", "sb-3"); err == nil {
			t.Fatalf("inventory error on %s swallowed", on)
		}
	}
	ev, _ = uploadFixture()
	if _, err := app.NewUploadOutcomes(ev, fakeUploadFindings{err: errors.New("db")}).For(ctx, "rel-1", "sb-3"); err == nil {
		t.Fatal("findings error swallowed")
	}
}

// The worker attaches the outcome to a new SBOM's evaluation, attaches none to a re-discovery,
// and publishes WITHOUT it when Evidence cannot be read — the event the loop runs on is never
// held back by a report.
func TestWorker_AttachesUploadOutcome(t *testing.T) {
	ctx := context.Background()
	ev, fs := uploadFixture()
	q, worker, _, log := evaluationWorker(t, "prod-1", "prj-1")
	worker.w.WithUploadOutcomes(app.NewUploadOutcomes(ev, fs))
	record(t, q, "rel-1", "sb-3", domain.CauseNewSBOM)
	if err := q.EnqueuePendingReleaseEvaluation(ctx, "rel-1", "sb-3", domain.CauseRediscovery); err != nil {
		t.Fatal(err)
	}
	worker.Tick(ctx)
	evs := q.publishedEvents()
	if len(evs) != 2 {
		t.Fatalf("published %d", len(evs))
	}
	for _, p := range evs {
		switch p.row.Cause {
		case domain.CauseNewSBOM:
			if p.event.UploadOutcome == nil || p.event.UploadOutcome.New != 1 {
				t.Fatalf("new sbom outcome = %+v", p.event.UploadOutcome)
			}
		default:
			if p.event.UploadOutcome != nil {
				t.Fatal("a re-discovery carried an outcome")
			}
		}
	}
	ev.listErr = errors.New("evidence down")
	if err := q.EnqueuePendingReleaseEvaluation(ctx, "rel-2", "sb-9", domain.CauseNewSBOM); err != nil {
		t.Fatal(err)
	}
	worker.Tick(ctx)
	evs = q.publishedEvents()
	if len(evs) != 3 || evs[2].event.UploadOutcome != nil || log.count() == 0 {
		t.Fatalf("degraded publish: %d events, outcome=%v, log=%d", len(evs), evs[len(evs)-1].event.UploadOutcome, log.count())
	}
}

type fakeOutcomeReader struct {
	rec   app.UploadOutcomeRecord
	found bool
	err   error
}

func (f fakeOutcomeReader) LatestUploadOutcome(context.Context, string) (app.UploadOutcomeRecord, bool, error) {
	return f.rec, f.found, f.err
}

func TestReadService_LatestUploadOutcome(t *testing.T) {
	ctx := context.Background()
	rs := app.NewReadService(newRepo(), fakeProjection{}, nil, 0)
	if _, _, err := rs.LatestUploadOutcome(ctx, "rel-1"); !errors.Is(err, app.ErrEventFeedUnavailable) {
		t.Fatalf("unwired: %v", err)
	}
	rs.WithUploadOutcomeReader(fakeOutcomeReader{rec: app.UploadOutcomeRecord{SBOMID: "sb-1"}, found: true})
	if rec, found, err := rs.LatestUploadOutcome(ctx, "rel-1"); err != nil || !found || rec.SBOMID != "sb-1" {
		t.Fatalf("wired: %+v %v %v", rec, found, err)
	}
}
