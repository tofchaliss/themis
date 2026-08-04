package inbound_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/adapters/inbound"
	"github.com/themis-project/themis/internal/intelligence/adapters/store"
	"github.com/themis-project/themis/internal/intelligence/domain"
	"github.com/themis-project/themis/internal/kernel/event"
)

// --- stubs -------------------------------------------------------------------------------

type stubFinding struct {
	v   domain.FindingView
	err error
}

func (s stubFinding) GetFinding(context.Context, string) (domain.FindingView, error) {
	return s.v, s.err
}

type stubFaultline struct {
	v   domain.FaultlineView
	err error
}

func (s stubFaultline) GetFaultline(context.Context, string) (domain.FaultlineView, error) {
	return s.v, s.err
}

type stubPosition struct {
	stance, rationale string
	found             bool
	err               error
}

func (s stubPosition) CurrentPosition(context.Context, string, string) (string, string, bool, error) {
	return s.stance, s.rationale, s.found, s.err
}

type stubEmbedder struct {
	vec []float32
	err error
}

func (s stubEmbedder) Embed(context.Context, string) ([]float32, error) { return s.vec, s.err }
func (s stubEmbedder) Model() string                                    { return "stub-model" }

type captureStore struct {
	recs []store.EmbeddingRecord
	err  error
}

func (c *captureStore) Upsert(_ context.Context, r store.EmbeddingRecord) error {
	if c.err != nil {
		return c.err
	}
	c.recs = append(c.recs, r)
	return nil
}

type captureIndex struct{ recs []store.EmbeddingRecord }

func (c *captureIndex) Upsert(r store.EmbeddingRecord) { c.recs = append(c.recs, r) }

// --- helpers -----------------------------------------------------------------------------

func positionEnv(typ, findingID, release, faultline, cve, stance string) event.Envelope {
	payload, _ := json.Marshal(map[string]any{
		"FindingID": findingID, "ReleaseID": release, "FaultlineID": faultline,
		"CVE": cve, "Version": 1, "Stance": stance,
	})
	return event.Envelope{ID: "env-" + findingID, Type: typ, Payload: payload}
}

func newConsumer(f stubFinding, fl stubFaultline, p stubPosition, e stubEmbedder) (*inbound.Consumer, *captureStore, *captureIndex) {
	st, idx := &captureStore{}, &captureIndex{}
	c := inbound.NewConsumer(f, fl, p, e, st, idx)
	return c, st, idx
}

// --- tests -------------------------------------------------------------------------------

func TestSubscription(t *testing.T) {
	if inbound.Subscription.Consumer != "intelligence" || inbound.Subscription.Stream != "governance" {
		t.Fatalf("subscription: %+v", inbound.Subscription)
	}
	if !inbound.Subscription.InInterest("governance.position_established") ||
		!inbound.Subscription.InInterest("governance.position_revised") {
		t.Fatalf("interest missing position events: %+v", inbound.Subscription.Interest)
	}
	if inbound.Subscription.InInterest("governance.finding_opened") {
		t.Fatal("must not be interested in lifecycle events")
	}
}

func TestPrepareHappyPathUpsertsStoreAndIndex(t *testing.T) {
	c, st, idx := newConsumer(
		stubFinding{v: domain.FindingView{Components: []string{"pkg:golang/openssl", "pkg:golang/x"}}},
		stubFaultline{v: domain.FaultlineView{Severity: "high"}},
		stubPosition{stance: "not_affected", rationale: "not reachable", found: true},
		stubEmbedder{vec: []float32{0.1, 0.2, 0.3}},
	)

	apply, err := c.Prepare(context.Background(),
		positionEnv("governance.position_established", "f1", "rel-1", "fl-1", "CVE-2026-1", "not_affected"))
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if apply == nil {
		t.Fatal("expected a non-nil apply")
	}
	if err := apply(context.Background()); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if len(st.recs) != 1 || len(idx.recs) != 1 {
		t.Fatalf("expected one store + one index upsert, got store=%d index=%d", len(st.recs), len(idx.recs))
	}
	got := st.recs[0]
	if got.FindingID != "f1" || got.ReleaseID != "rel-1" || got.FaultlineID != "fl-1" || got.CVE != "CVE-2026-1" {
		t.Errorf("identity/labels wrong: %+v", got)
	}
	if got.Stance != "not_affected" || got.Rationale != "not reachable" {
		t.Errorf("position labels wrong: %+v", got)
	}
	if got.Component != "pkg:golang/openssl" {
		t.Errorf("representative component: got %q", got.Component)
	}
	if got.Model != "stub-model" {
		t.Errorf("model stamp: got %q", got.Model)
	}
	if len(got.Vector) != 3 || got.TextHash == "" {
		t.Errorf("vector/hash: %+v", got)
	}
}

func TestPrepareEmptyTextClaimsAndSkips(t *testing.T) {
	// No components AND no severity → empty embed text → nothing to embed.
	c, st, idx := newConsumer(
		stubFinding{v: domain.FindingView{}},
		stubFaultline{v: domain.FaultlineView{}},
		stubPosition{found: true},
		stubEmbedder{vec: []float32{1}},
	)
	apply, err := c.Prepare(context.Background(),
		positionEnv("governance.position_established", "f1", "rel-1", "fl-1", "CVE-1", "affected"))
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if apply == nil {
		t.Fatal("expected a non-nil no-op apply so the envelope is still claimed")
	}
	if err := apply(context.Background()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(st.recs) != 0 || len(idx.recs) != 0 {
		t.Fatalf("expected no writes, got store=%d index=%d", len(st.recs), len(idx.recs))
	}
}

func TestPrepareRetriesOnTransientErrors(t *testing.T) {
	env := positionEnv("governance.position_revised", "f1", "rel-1", "fl-1", "CVE-1", "affected")
	good := domain.FindingView{Components: []string{"pkg:golang/openssl"}}

	cases := []struct {
		name string
		f    stubFinding
		fl   stubFaultline
		p    stubPosition
		e    stubEmbedder
	}{
		{"finding read", stubFinding{err: errors.New("gov down")}, stubFaultline{}, stubPosition{found: true}, stubEmbedder{vec: []float32{1}}},
		{"faultline read", stubFinding{v: good}, stubFaultline{err: errors.New("knowledge down")}, stubPosition{found: true}, stubEmbedder{vec: []float32{1}}},
		{"embed", stubFinding{v: good}, stubFaultline{v: domain.FaultlineView{Severity: "high"}}, stubPosition{found: true}, stubEmbedder{err: errors.New("ollama down")}},
		{"position read", stubFinding{v: good}, stubFaultline{v: domain.FaultlineView{Severity: "high"}}, stubPosition{err: errors.New("gov down")}, stubEmbedder{vec: []float32{1}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _, _ := newConsumer(tc.f, tc.fl, tc.p, tc.e)
			apply, err := c.Prepare(context.Background(), env)
			if err == nil {
				t.Fatalf("expected a retryable error for %s", tc.name)
			}
			if apply != nil {
				t.Fatalf("expected no apply on error for %s", tc.name)
			}
		})
	}
}

func TestPrepareBadPayload(t *testing.T) {
	c, _, _ := newConsumer(stubFinding{}, stubFaultline{}, stubPosition{}, stubEmbedder{})
	env := event.Envelope{ID: "e", Type: "governance.position_established", Payload: []byte("not json")}
	if _, err := c.Prepare(context.Background(), env); err == nil {
		t.Fatal("expected an error for a malformed payload")
	}
}

func TestPrepareIgnoresNonPositionType(t *testing.T) {
	c, _, _ := newConsumer(stubFinding{}, stubFaultline{}, stubPosition{}, stubEmbedder{})
	apply, err := c.Prepare(context.Background(),
		event.Envelope{ID: "e", Type: "governance.finding_opened", Payload: []byte("{}")})
	if err != nil || apply != nil {
		t.Fatalf("non-position type: got apply-nil=%v err=%v, want apply=nil err=nil", apply == nil, err)
	}
}

func TestHandleFallbackUpserts(t *testing.T) {
	c, st, idx := newConsumer(
		stubFinding{v: domain.FindingView{Components: []string{"pkg:golang/openssl"}}},
		stubFaultline{v: domain.FaultlineView{Severity: "high"}},
		stubPosition{stance: "affected", rationale: "reachable", found: true},
		stubEmbedder{vec: []float32{1, 0}},
	)
	if err := c.Handle(context.Background(),
		positionEnv("governance.position_established", "f9", "rel-9", "fl-9", "CVE-9", "affected")); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(st.recs) != 1 || len(idx.recs) != 1 {
		t.Fatalf("expected one write each, got store=%d index=%d", len(st.recs), len(idx.recs))
	}
	if st.recs[0].Rationale != "reachable" {
		t.Errorf("rationale: got %q", st.recs[0].Rationale)
	}
}

func TestHandleIgnoresNonPositionAndBadPayload(t *testing.T) {
	c, st, _ := newConsumer(stubFinding{}, stubFaultline{}, stubPosition{}, stubEmbedder{})
	if err := c.Handle(context.Background(),
		event.Envelope{ID: "e", Type: "governance.finding_opened", Payload: []byte("{}")}); err != nil {
		t.Fatalf("non-position: %v", err)
	}
	if err := c.Handle(context.Background(),
		event.Envelope{ID: "e", Type: "governance.position_established", Payload: []byte("bad")}); err == nil {
		t.Fatal("expected error for bad payload")
	}
	if len(st.recs) != 0 {
		t.Fatalf("expected no writes, got %d", len(st.recs))
	}
}

func TestHandleStoreErrorPropagates(t *testing.T) {
	c := inbound.NewConsumer(
		stubFinding{v: domain.FindingView{Components: []string{"pkg:golang/openssl"}}},
		stubFaultline{v: domain.FaultlineView{Severity: "high"}},
		stubPosition{found: true},
		stubEmbedder{vec: []float32{1}},
		&captureStore{err: errors.New("db down")},
		&captureIndex{},
	)
	if err := c.Handle(context.Background(),
		positionEnv("governance.position_established", "f1", "r", "fl", "CVE", "affected")); err == nil {
		t.Fatal("expected the store error to propagate")
	}
}
