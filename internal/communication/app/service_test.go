package app_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

// fakeSerializers is a deterministic stand-in for the serializer registry (the app ring must
// not import an adapter — the real registry is exercised in serializer/http tests). It knows
// the built-in formats and renders a stable token from the artifact.
type fakeSerializers struct{}

func (fakeSerializers) Render(format string, art domain.Artifact) ([]byte, error) {
	switch format {
	case "openvex", "cyclonedx-vex", "csaf", "markdown", "json-report", "text":
		return []byte(format + "|" + string(art.Stance) + "|" + art.Title), nil
	default:
		return nil, errors.New("unknown format")
	}
}

// --- fakes ---------------------------------------------------------------------------

type fakeRepo struct {
	prior               *domain.Publication
	saved               map[domain.PublicationID]domain.Publication
	supersededPrior     *domain.Publication
	lastNotes           []app.OutboxNote
	queue               []app.QueueEntry
	saveCalls           int
	conflictFor         int
	currentErr          error
	saveErr             error
	markErr             error
	undeliveredErr      error
	undeliveredOverride []domain.Publication
	updateErr           error
	listErr             error
	queueErr            error
	lastUpdateNotes     []app.OutboxNote
	pruned              int
	pruneErr            error
}

func newRepo() *fakeRepo { return &fakeRepo{saved: map[domain.PublicationID]domain.Publication{}} }

func (r *fakeRepo) CurrentPublication(_ context.Context, _, _ string, _ domain.ArtifactType, _ string) (domain.Publication, bool, error) {
	if r.currentErr != nil {
		return domain.Publication{}, false, r.currentErr
	}
	if r.prior != nil {
		return clone(*r.prior), true, nil
	}
	return domain.Publication{}, false, nil
}

func (r *fakeRepo) GetByID(_ context.Context, id domain.PublicationID) (domain.Publication, error) {
	p, ok := r.saved[id]
	if !ok {
		return domain.Publication{}, errors.New("not found")
	}
	return p, nil
}

func (r *fakeRepo) Save(_ context.Context, pub domain.Publication, prior *domain.Publication, _ int, notes []app.OutboxNote) error {
	r.saveCalls++
	if r.saveErr != nil {
		return r.saveErr
	}
	if r.saveCalls <= r.conflictFor {
		return app.ErrConcurrent
	}
	r.saved[pub.ID()] = pub
	r.supersededPrior = prior
	r.lastNotes = notes
	return nil
}

func (r *fakeRepo) MarkPublishable(_ context.Context, entry app.QueueEntry) error {
	if r.markErr != nil {
		return r.markErr
	}
	r.queue = append(r.queue, entry)
	return nil
}

func (r *fakeRepo) UndeliveredPublications(_ context.Context, _ int) ([]domain.Publication, error) {
	if r.undeliveredErr != nil {
		return nil, r.undeliveredErr
	}
	if r.undeliveredOverride != nil {
		return r.undeliveredOverride, nil
	}
	var out []domain.Publication
	for _, p := range r.saved {
		if p.Delivery().Status != domain.DeliveryDelivered {
			out = append(out, clone(p))
		}
	}
	return out, nil
}

func (r *fakeRepo) UpdateDelivery(_ context.Context, pub domain.Publication, _ int, notes []app.OutboxNote) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	r.saved[pub.ID()] = pub
	r.lastUpdateNotes = notes
	return nil
}

func (r *fakeRepo) ListByRelease(_ context.Context, releaseID string) ([]domain.Publication, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	var out []domain.Publication
	for _, p := range r.saved {
		if p.Lineage().ReleaseID == releaseID {
			out = append(out, clone(p))
		}
	}
	return out, nil
}

func (r *fakeRepo) PublishableQueue(_ context.Context) ([]app.QueueEntry, error) {
	if r.queueErr != nil {
		return nil, r.queueErr
	}
	return r.queue, nil
}

func (r *fakeRepo) PrunePayloads(_ context.Context, _ time.Time) (int, error) {
	return r.pruned, r.pruneErr
}

// clone reconstitutes an independent Publication so the fake never aliases a stored one.
func clone(p domain.Publication) domain.Publication {
	return domain.ReconstitutePublication(p.ID(), p.Artifact(), p.Format(), p.Audience(), p.Channel(),
		p.Payload(), p.Delivery(), p.Supersedes(), p.SupersededBy(), p.Version(), p.CreatedAt())
}

type fakePositions struct {
	snap  domain.PositionSnapshot
	found bool
	err   error
}

func (f fakePositions) GetPosition(context.Context, string) (domain.PositionSnapshot, bool, error) {
	return f.snap, f.found, f.err
}

type seqIDs struct{ n int }

func (g *seqIDs) NewID() string { g.n++; return fmt.Sprintf("pub-%d", g.n) }

type emptyIDs struct{}

func (emptyIDs) NewID() string { return "" }

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

func snapshot(stance domain.Stance) domain.PositionSnapshot {
	return domain.PositionSnapshot{
		FindingID: "fnd-1", Version: 1, Stance: stance, Rationale: "vendor VEX confirms",
		Lineage: domain.Lineage{ReleaseID: "rel-1", FindingID: "fnd-1", FaultlineID: "fl-1", CVE: "CVE-2024-1"},
	}
}

func svc(repo app.Repository, pos app.PositionReader) *app.PublicationService {
	return app.NewPublicationService(repo, pos, fakeSerializers{}, &seqIDs{}, fixedClock{})
}

func noteTypes(notes []app.OutboxNote) []string {
	out := make([]string, len(notes))
	for i, n := range notes {
		out[i] = n.EventType
	}
	return out
}

// --- CreatePublication (D4/D3/D5) ----------------------------------------------------

func TestCreatePublication_First(t *testing.T) {
	repo := newRepo()
	pos := fakePositions{snap: snapshot(domain.StanceNotAffected), found: true}
	id, err := svc(repo, pos).CreatePublication(context.Background(), "fnd-1", domain.ArtifactVEX, "openvex", "tooling", "export")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	pub := repo.saved[id]
	if pub.Type() != domain.ArtifactVEX || pub.Stance() != domain.StanceNotAffected || pub.Format() != "openvex" {
		t.Errorf("publication = %+v", pub)
	}
	if pub.Delivery().Status != domain.DeliveryPending || pub.IsSuperseded() || pub.Supersedes() != "" {
		t.Errorf("delivery/supersede = %+v", pub)
	}
	if len(pub.Payload()) == 0 {
		t.Error("payload not rendered")
	}
	if got := noteTypes(repo.lastNotes); len(got) != 1 || got[0] != app.EventPublicationCreated {
		t.Errorf("notes = %v, want [publication_created]", got)
	}
}

func TestCreatePublication_SupersedesPrior(t *testing.T) {
	repo := newRepo()
	prior, _ := domain.NewPublication("pub-old", mustArt(t, domain.StanceAffected, domain.ArtifactVEX),
		"openvex", "tooling", "export", []byte("old"), "", fixedClock{}.Now())
	repo.prior = &prior

	pos := fakePositions{snap: snapshot(domain.StanceMitigated), found: true}
	id, err := svc(repo, pos).CreatePublication(context.Background(), "fnd-1", domain.ArtifactVEX, "openvex", "tooling", "export")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if repo.saved[id].Supersedes() != "pub-old" {
		t.Errorf("new publication should supersede pub-old, got %q", repo.saved[id].Supersedes())
	}
	if repo.supersededPrior == nil || repo.supersededPrior.SupersededBy() != id {
		t.Errorf("prior not superseded by %q: %+v", id, repo.supersededPrior)
	}
	want := []string{app.EventPublicationCreated, app.EventPublicationSuperseded}
	if got := noteTypes(repo.lastNotes); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("notes = %v, want %v", got, want)
	}
}

func TestCreatePublication_Errors(t *testing.T) {
	ctx := context.Background()

	// Position not found.
	if _, err := svc(newRepo(), fakePositions{found: false}).CreatePublication(ctx, "fnd-1", domain.ArtifactVEX, "openvex", "a", "c"); !errors.Is(err, app.ErrPositionNotFound) {
		t.Errorf("not-found err = %v, want ErrPositionNotFound", err)
	}
	// GetPosition error.
	if _, err := svc(newRepo(), fakePositions{err: errors.New("gov down")}).CreatePublication(ctx, "fnd-1", domain.ArtifactVEX, "openvex", "a", "c"); err == nil {
		t.Error("position error: expected error")
	}
	// Unknown artifact type → Materialize error.
	if _, err := svc(newRepo(), fakePositions{snap: snapshot(domain.StanceAffected), found: true}).CreatePublication(ctx, "fnd-1", domain.ArtifactType("bogus"), "openvex", "a", "c"); err == nil {
		t.Error("bad artifact type: expected error")
	}
	// Unknown format → serializer error.
	if _, err := svc(newRepo(), fakePositions{snap: snapshot(domain.StanceAffected), found: true}).CreatePublication(ctx, "fnd-1", domain.ArtifactVEX, "nope", "a", "c"); err == nil {
		t.Error("bad format: expected error")
	}
	// CurrentPublication error.
	ce := newRepo()
	ce.currentErr = errors.New("db down")
	if _, err := svc(ce, fakePositions{snap: snapshot(domain.StanceAffected), found: true}).CreatePublication(ctx, "fnd-1", domain.ArtifactVEX, "openvex", "a", "c"); err == nil {
		t.Error("current error: expected error")
	}
	// Non-concurrent save error.
	se := newRepo()
	se.saveErr = errors.New("write failed")
	if _, err := svc(se, fakePositions{snap: snapshot(domain.StanceAffected), found: true}).CreatePublication(ctx, "fnd-1", domain.ArtifactVEX, "openvex", "a", "c"); err == nil {
		t.Error("save error: expected error")
	}
	// Empty id from the generator → NewPublication fails.
	if _, err := app.NewPublicationService(newRepo(), fakePositions{snap: snapshot(domain.StanceAffected), found: true}, fakeSerializers{}, emptyIDs{}, fixedClock{}).CreatePublication(ctx, "fnd-1", domain.ArtifactVEX, "openvex", "a", "c"); err == nil {
		t.Error("empty id: expected error")
	}
	// Defensive: a "current" publication that is already superseded fails supersession.
	sp := newRepo()
	priorSup, _ := domain.NewPublication("pub-old", mustArt(t, domain.StanceAffected, domain.ArtifactVEX), "openvex", "tooling", "export", nil, "", fixedClock{}.Now())
	_ = priorSup.Supersede("pub-x")
	sp.prior = &priorSup
	if _, err := svc(sp, fakePositions{snap: snapshot(domain.StanceMitigated), found: true}).CreatePublication(ctx, "fnd-1", domain.ArtifactVEX, "openvex", "tooling", "export"); !errors.Is(err, domain.ErrAlreadySuperseded) {
		t.Errorf("already-superseded prior err = %v, want ErrAlreadySuperseded", err)
	}
}

func TestCreatePublication_ConcurrencyRetry(t *testing.T) {
	repo := newRepo()
	prior, _ := domain.NewPublication("pub-old", mustArt(t, domain.StanceAffected, domain.ArtifactVEX), "openvex", "tooling", "export", nil, "", fixedClock{}.Now())
	repo.prior = &prior
	repo.conflictFor = 2 // first two saves conflict, third wins

	id, err := svc(repo, fakePositions{snap: snapshot(domain.StanceMitigated), found: true}).CreatePublication(context.Background(), "fnd-1", domain.ArtifactVEX, "openvex", "tooling", "export")
	if err != nil || id == "" || repo.saveCalls != 3 {
		t.Errorf("expected convergence after 3 saves: id=%q saves=%d err=%v", id, repo.saveCalls, err)
	}

	// Exhausted retries → ErrConcurrent.
	ce := newRepo()
	ce.prior = &prior
	ce.conflictFor = 99
	if _, err := svc(ce, fakePositions{snap: snapshot(domain.StanceMitigated), found: true}).CreatePublication(context.Background(), "fnd-1", domain.ArtifactVEX, "openvex", "tooling", "export"); !errors.Is(err, app.ErrConcurrent) {
		t.Errorf("exhausted err = %v, want ErrConcurrent", err)
	}
}

// --- RecordPublishable (D4) ----------------------------------------------------------

func TestRecordPublishable(t *testing.T) {
	repo := newRepo()
	s := svc(repo, fakePositions{})

	if err := s.RecordPublishable(context.Background(), snapshot(domain.StanceAffected), false); err != nil {
		t.Fatalf("record: %v", err)
	}
	if len(repo.queue) != 1 || repo.queue[0].FindingID != "fnd-1" || repo.queue[0].Stale {
		t.Errorf("queue = %+v", repo.queue)
	}

	// A revised Position is marked stale.
	if err := s.RecordPublishable(context.Background(), snapshot(domain.StanceMitigated), true); err != nil {
		t.Fatal(err)
	}
	if !repo.queue[1].Stale || repo.queue[1].Stance != domain.StanceMitigated {
		t.Errorf("stale entry = %+v", repo.queue[1])
	}

	// Error propagates.
	me := newRepo()
	me.markErr = errors.New("db down")
	if err := svc(me, fakePositions{}).RecordPublishable(context.Background(), snapshot(domain.StanceAffected), false); err == nil {
		t.Error("mark error: expected error")
	}
}

func mustArt(t *testing.T, stance domain.Stance, typ domain.ArtifactType) domain.Artifact {
	t.Helper()
	a, err := domain.Materialize(snapshot(stance), typ)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	return a
}
