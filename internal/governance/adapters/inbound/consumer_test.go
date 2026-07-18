package inbound_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/adapters/inbound"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// --- minimal in-memory repo (drives the real FindingService) -------------------------

type memRepo struct {
	byID  map[domain.FindingID]domain.Finding
	order []domain.FindingID
}

func newMemRepo() *memRepo { return &memRepo{byID: map[domain.FindingID]domain.Finding{}} }

func (r *memRepo) seed(f domain.Finding) {
	if _, ok := r.byID[f.ID()]; !ok {
		r.order = append(r.order, f.ID())
	}
	r.byID[f.ID()] = f
}

func clone(f domain.Finding) domain.Finding {
	return domain.ReconstituteFinding(f.ID(), f.ReleaseID(), f.FaultlineID(), f.CVE(),
		f.Components(), f.Stage(), f.Proposals(), f.Positions(), f.Version())
}

func (r *memRepo) GetByKey(_ context.Context, rel, fl string) (domain.Finding, bool, error) {
	for _, id := range r.order {
		if f := r.byID[id]; f.ReleaseID() == rel && f.FaultlineID() == fl {
			return clone(f), true, nil
		}
	}
	return domain.Finding{}, false, nil
}

func (r *memRepo) GetByID(_ context.Context, id domain.FindingID) (domain.Finding, error) {
	f, ok := r.byID[id]
	if !ok {
		return domain.Finding{}, errNotFound
	}
	return clone(f), nil
}

func (r *memRepo) FindingsByFaultline(_ context.Context, fl string) ([]domain.FindingID, error) {
	var out []domain.FindingID
	for _, id := range r.order {
		if r.byID[id].FaultlineID() == fl {
			out = append(out, id)
		}
	}
	return out, nil
}

func (r *memRepo) Save(_ context.Context, f domain.Finding, _ bool, _ int, _ []app.OutboxNote) error {
	r.seed(f)
	return nil
}

var errNotFound = errNotFoundType("not found")

type errNotFoundType string

func (e errNotFoundType) Error() string { return string(e) }

type ids struct{ n int }

func (g *ids) NewID() string { g.n++; return "id-x" }

type clk struct{}

func (clk) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

func consumer(repo *memRepo) *inbound.Consumer {
	svc := app.NewFindingService(repo, &ids{}, clk{})
	return inbound.NewConsumer(app.NewCoordinator(svc))
}

// --- tests ---------------------------------------------------------------------------

func TestConsumer_ComponentMatched(t *testing.T) {
	repo := newMemRepo()
	// A payload shaped like Knowledge's ComponentMatched (PascalCase keys, no json tags).
	payload := []byte(`{"FaultlineID":"fl-1","CVE":"CVE-2024-1","ReleaseID":"rel-1",
		"Components":[{"PURL":"pkg:apk/openssl@3","Name":"openssl","Version":"3","Ecosystem":"Alpine"}]}`)
	if err := consumer(repo).Handle(context.Background(), "knowledge.component_matched", payload); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(repo.order) != 1 {
		t.Fatalf("expected a Finding, got %d", len(repo.order))
	}
	f := repo.byID[repo.order[0]]
	if f.ReleaseID() != "rel-1" || f.FaultlineID() != "fl-1" || len(f.Components()) != 1 || f.Components()[0].PURL != "pkg:apk/openssl@3" {
		t.Errorf("finding = %+v", f)
	}
}

func TestConsumer_FaultlineEnriched(t *testing.T) {
	repo := newMemRepo()
	f, _ := domain.NewFinding("fnd-1", "rel-1", "fl-1", "CVE-1")
	repo.seed(f)
	payload := []byte(`{"FaultlineID":"fl-1","CVE":"CVE-1","Severity":"high","KEV":false,"ExploitPublic":false}`)
	if err := consumer(repo).Handle(context.Background(), "knowledge.faultline_enriched", payload); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got := repo.byID["fnd-1"]
	if len(got.Proposals()) != 1 || got.Proposals()[0].Stance() != domain.StanceAffected {
		t.Errorf("proposals = %+v", got.Proposals())
	}
}

func TestConsumer_FaultlineSuperseded(t *testing.T) {
	repo := newMemRepo()
	f, _ := domain.NewFinding("fnd-1", "rel-1", "fl-1", "CVE-1")
	repo.seed(f)
	payload := []byte(`{"FaultlineID":"fl-1","CVE":"CVE-1"}`)
	if err := consumer(repo).Handle(context.Background(), "knowledge.faultline_superseded", payload); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got := repo.byID["fnd-1"]
	if len(got.Proposals()) != 1 || got.Proposals()[0].Stance() != domain.StanceNotAffected {
		t.Errorf("proposals = %+v", got.Proposals())
	}
}

func TestConsumer_UnknownTypeIgnored(t *testing.T) {
	repo := newMemRepo()
	if err := consumer(repo).Handle(context.Background(), "knowledge.something_else", []byte(`{}`)); err != nil {
		t.Errorf("unknown type should be ignored, got %v", err)
	}
	if len(repo.order) != 0 {
		t.Error("unknown event must not create a Finding")
	}
}

func TestConsumer_MalformedPayloads(t *testing.T) {
	repo := newMemRepo()
	c := consumer(repo)
	for _, evt := range []string{"knowledge.component_matched", "knowledge.faultline_enriched", "knowledge.faultline_superseded"} {
		if err := c.Handle(context.Background(), evt, []byte("{not json")); err == nil {
			t.Errorf("%s: malformed payload should error", evt)
		}
	}
}
