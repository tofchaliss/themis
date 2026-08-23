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

// stubProjection stands in for Governance's FindingAssessment. The population path is just
// another consumer of the same business view the reasoning path reads.
type stubProjection struct {
	p   domain.FindingAssessment
	err error
}

func (s stubProjection) GetAssessment(context.Context, string) (domain.FindingAssessment, error) {
	return s.p, s.err
}

func (s stubProjection) GetReleasePosture(context.Context, string) (domain.ReleasePosture, error) {
	return domain.ReleasePosture{}, nil
}

func (s stubProjection) GetReleaseComparison(context.Context, string, string) (domain.ReleaseComparison, error) {
	return domain.ReleaseComparison{}, nil
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
	// cached is the stored (hash, vector) the embed-skip consults; zero value = nothing cached,
	// so every existing test embeds exactly as it did before.
	cachedHash   string
	cachedVector []float32
	cachedErr    error
	cacheReads   int
	// indexed is what IndexedForFaultline returns for the re-embed path.
	indexed        []store.IndexedFinding
	indexedErr     error
	faultlineReads int
}

func (c *captureStore) Upsert(_ context.Context, r store.EmbeddingRecord) error {
	if c.err != nil {
		return c.err
	}
	c.recs = append(c.recs, r)
	return nil
}

func (c *captureStore) IndexedForFaultline(_ context.Context, _ string) ([]store.IndexedFinding, error) {
	c.faultlineReads++
	return c.indexed, c.indexedErr
}

func (c *captureStore) CachedEmbedding(_ context.Context, _ string) (string, []float32, bool, error) {
	c.cacheReads++
	if c.cachedErr != nil {
		return "", nil, false, c.cachedErr
	}
	if c.cachedHash == "" {
		return "", nil, false, nil
	}
	return c.cachedHash, c.cachedVector, true, nil
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

func newConsumer(pr stubProjection, p stubPosition, e stubEmbedder) (*inbound.Consumer, *captureStore, *captureIndex) {
	st, idx := &captureStore{}, &captureIndex{}
	c := inbound.NewConsumer(pr, p, e, st, idx)
	return c, st, idx
}

// projOf builds a projection stub from the two halves the tests care about.
func projOf(components []string, severity string) stubProjection {
	return stubProjection{p: domain.FindingAssessment{
		Finding:   domain.FindingView{Components: components},
		Knowledge: domain.FaultlineView{Severity: severity},
	}}
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
		projOf([]string{"pkg:golang/openssl", "pkg:golang/x"}, "high"),
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
		projOf(nil, ""),
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
	good := projOf([]string{"pkg:golang/openssl"}, "high")

	cases := []struct {
		name string
		pr   stubProjection
		p    stubPosition
		e    stubEmbedder
	}{
		// One projection read replaces the two that used to fail independently.
		{"projection read", stubProjection{err: errors.New("gov down")}, stubPosition{found: true}, stubEmbedder{vec: []float32{1}}},
		{"embed", good, stubPosition{found: true}, stubEmbedder{err: errors.New("ollama down")}},
		{"position read", good, stubPosition{err: errors.New("gov down")}, stubEmbedder{vec: []float32{1}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _, _ := newConsumer(tc.pr, tc.p, tc.e)
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
	c, _, _ := newConsumer(stubProjection{}, stubPosition{}, stubEmbedder{})
	env := event.Envelope{ID: "e", Type: "governance.position_established", Payload: []byte("not json")}
	if _, err := c.Prepare(context.Background(), env); err == nil {
		t.Fatal("expected an error for a malformed payload")
	}
}

func TestPrepareIgnoresNonPositionType(t *testing.T) {
	c, _, _ := newConsumer(stubProjection{}, stubPosition{}, stubEmbedder{})
	apply, err := c.Prepare(context.Background(),
		event.Envelope{ID: "e", Type: "governance.finding_opened", Payload: []byte("{}")})
	if err != nil || apply != nil {
		t.Fatalf("non-position type: got apply-nil=%v err=%v, want apply=nil err=nil", apply == nil, err)
	}
}

func TestHandleFallbackUpserts(t *testing.T) {
	c, st, idx := newConsumer(
		projOf([]string{"pkg:golang/openssl"}, "high"),
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
	c, st, _ := newConsumer(stubProjection{}, stubPosition{}, stubEmbedder{})
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
		projOf([]string{"pkg:golang/openssl"}, "high"),
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

// --- Δ3a: skip the embed when the subject text is unchanged -------------------------------

// A Position revise usually moves only the stance or the rationale — neither of which is
// embedded, since SubjectText keys on component + severity. Re-embedding would spend an Ollama
// round-trip to reproduce the vector already stored.
func TestPrepareReusesTheCachedVectorWhenSubjectTextIsUnchanged(t *testing.T) {
	pr := projOf([]string{"pkg:golang/openssl"}, "high")
	emb := stubEmbedder{vec: []float32{9, 9, 9}} // if this is used, the assertion below fails
	st, idx := &captureStore{}, &captureIndex{}
	c := inbound.NewConsumer(pr, stubPosition{stance: "affected", rationale: "revised", found: true}, emb, st, idx)

	// Seed the cache with the hash the consumer will compute for this same subject, and a
	// distinguishable vector.
	cached := []float32{0.5, 0.25}
	st.cachedHash = inbound.SubjectTextHashFor("high", []string{"pkg:golang/openssl"})
	st.cachedVector = cached

	apply, err := c.Prepare(context.Background(),
		positionEnv("governance.position_revised", "f1", "rel-1", "fl-1", "CVE-1", "affected"))
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := apply(context.Background()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if st.cacheReads != 1 {
		t.Fatalf("cache reads = %d, want 1", st.cacheReads)
	}
	got := st.recs[0]
	if len(got.Vector) != len(cached) || got.Vector[0] != cached[0] {
		t.Fatalf("vector = %v, want the cached %v — the embedder must not have been called", got.Vector, cached)
	}
	// The row is still rewritten with the NEW labels: skipping the embed must not skip the
	// update, or a revise would leave a stale stance in the index.
	if got.Stance != "affected" || got.Rationale != "revised" {
		t.Errorf("labels = %q/%q, want the revised ones", got.Stance, got.Rationale)
	}
}

// A changed subject (here: severity moved) must re-embed. The cache is keyed by the text hash
// precisely so that a real change is never served a stale vector.
func TestPrepareReEmbedsWhenSubjectTextChanged(t *testing.T) {
	pr := projOf([]string{"pkg:golang/openssl"}, "critical")
	st, idx := &captureStore{}, &captureIndex{}
	c := inbound.NewConsumer(pr, stubPosition{stance: "affected", found: true},
		stubEmbedder{vec: []float32{7, 7}}, st, idx)

	st.cachedHash = inbound.SubjectTextHashFor("high", []string{"pkg:golang/openssl"}) // stale severity
	st.cachedVector = []float32{0.5, 0.25}

	apply, err := c.Prepare(context.Background(),
		positionEnv("governance.position_revised", "f1", "rel-1", "fl-1", "CVE-1", "affected"))
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := apply(context.Background()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := st.recs[0].Vector; len(got) != 2 || got[0] != 7 {
		t.Fatalf("vector = %v, want the freshly embedded one", got)
	}
}

// The cache is an optimization, so a lookup failure must not stall index population: it falls
// through to the embed, which is always correct — just slower. Refusing to make progress
// because a cache could not be consulted would turn a storage hiccup into a stuck consumer.
func TestPrepareEmbedsWhenTheCacheLookupFails(t *testing.T) {
	pr := projOf([]string{"pkg:golang/openssl"}, "high")
	st, idx := &captureStore{}, &captureIndex{}
	st.cachedErr = errors.New("cache read failed")
	c := inbound.NewConsumer(pr, stubPosition{stance: "affected", found: true},
		stubEmbedder{vec: []float32{7, 7}}, st, idx)

	apply, err := c.Prepare(context.Background(),
		positionEnv("governance.position_revised", "f1", "rel-1", "fl-1", "CVE-1", "affected"))
	if err != nil {
		t.Fatalf("prepare must not fail on a cache error: %v", err)
	}
	if err := apply(context.Background()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := st.recs[0].Vector; len(got) != 2 || got[0] != 7 {
		t.Fatalf("vector = %v, want the freshly embedded one", got)
	}
}

// --- Δ3a: refresh the index when a Faultline's severity moves -----------------------------

func TestFaultlineSubscriptionBindsTheKnowledgeStream(t *testing.T) {
	if inbound.FaultlineSubscription.Stream != "knowledge" {
		t.Fatalf("stream = %q, want knowledge", inbound.FaultlineSubscription.Stream)
	}
	if !inbound.FaultlineSubscription.InInterest("knowledge.faultline_enriched") {
		t.Fatalf("interest missing the enrichment fact: %+v", inbound.FaultlineSubscription.Interest)
	}
	// The bus cursor is per (consumer, stream), so sharing the Position consumer's name would
	// make the two streams fight over one cursor position.
	if inbound.FaultlineSubscription.Consumer == inbound.Subscription.Consumer {
		t.Fatal("the two subscriptions must not share a consumer name")
	}
}

// Severity is half the embedded subject text, so an enrichment that moves it must refresh every
// Finding already indexed on that card — the direction the index used to go stale in.
func TestPrepareReEmbedsEveryIndexedFindingOnAnEnrichedFaultline(t *testing.T) {
	st, idx := &captureStore{}, &captureIndex{}
	st.indexed = []store.IndexedFinding{
		{FindingID: "f1", FaultlineID: "fl-1", ReleaseID: "rel-1", CVE: "CVE-1", Stance: "affected"},
		{FindingID: "f2", FaultlineID: "fl-1", ReleaseID: "rel-2", CVE: "CVE-1", Stance: "not_affected"},
	}
	c := inbound.NewConsumer(
		projOf([]string{"pkg:golang/openssl"}, "critical"), // the NEW severity
		stubPosition{stance: "affected", rationale: "re-evaluated", found: true},
		stubEmbedder{vec: []float32{4, 2}}, st, idx)

	env := event.Envelope{ID: "e1", Type: "knowledge.faultline_enriched",
		Payload: []byte(`{"FaultlineID":"fl-1","CVE":"CVE-1"}`)}

	apply, err := c.Prepare(context.Background(), env)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := apply(context.Background()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(st.recs) != 2 || len(idx.recs) != 2 {
		t.Fatalf("store=%d index=%d, want both Findings refreshed", len(st.recs), len(idx.recs))
	}
	// The identity of each row is preserved — a re-embed updates vectors, it does not re-key.
	if st.recs[0].FindingID != "f1" || st.recs[1].FindingID != "f2" {
		t.Errorf("finding ids = %q/%q, want f1/f2", st.recs[0].FindingID, st.recs[1].FindingID)
	}
	if st.recs[1].ReleaseID != "rel-2" {
		t.Errorf("release = %q, want the stored rel-2 rather than the first row's", st.recs[1].ReleaseID)
	}
}

// A Faultline nothing is indexed under claims the envelope and does nothing: there is no vector
// to refresh, and the Position event that eventually creates one will embed then.
func TestPrepareEnrichmentForAnUnknownFaultlineIsANoOp(t *testing.T) {
	st, idx := &captureStore{}, &captureIndex{}
	c := inbound.NewConsumer(projOf([]string{"pkg:x"}, "high"),
		stubPosition{found: true}, stubEmbedder{vec: []float32{1}}, st, idx)

	apply, err := c.Prepare(context.Background(), event.Envelope{
		ID: "e", Type: "knowledge.faultline_enriched", Payload: []byte(`{"FaultlineID":"unknown"}`)})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if apply == nil {
		t.Fatal("want a no-op apply so the envelope is still claimed")
	}
	if err := apply(context.Background()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(st.recs) != 0 {
		t.Fatalf("wrote %d records for a Faultline with nothing indexed", len(st.recs))
	}
}

// An index read failure is transient: no apply, so the envelope is retried rather than claimed
// and the refresh lost.
func TestPrepareEnrichmentRetriesOnIndexReadFailure(t *testing.T) {
	st, idx := &captureStore{}, &captureIndex{}
	st.indexedErr = errors.New("db down")
	c := inbound.NewConsumer(projOf([]string{"pkg:x"}, "high"),
		stubPosition{found: true}, stubEmbedder{vec: []float32{1}}, st, idx)

	apply, err := c.Prepare(context.Background(), event.Envelope{
		ID: "e", Type: "knowledge.faultline_enriched", Payload: []byte(`{"FaultlineID":"fl-1"}`)})
	if err == nil || apply != nil {
		t.Fatalf("want a retryable error and no apply, got err=%v apply=%v", err, apply != nil)
	}
}

// Handle is the non-Preparer fallback and must cover the enrichment path too, or the Handler
// contract is total only for Position events.
func TestHandleReEmbedsOnEnrichment(t *testing.T) {
	st, idx := &captureStore{}, &captureIndex{}
	st.indexed = []store.IndexedFinding{{FindingID: "f1", FaultlineID: "fl-1", ReleaseID: "rel-1", CVE: "CVE-1", Stance: "affected"}}
	c := inbound.NewConsumer(projOf([]string{"pkg:x"}, "critical"),
		stubPosition{stance: "affected", found: true}, stubEmbedder{vec: []float32{3}}, st, idx)

	if err := c.Handle(context.Background(), event.Envelope{
		ID: "e", Type: "knowledge.faultline_enriched", Payload: []byte(`{"FaultlineID":"fl-1"}`)}); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(st.recs) != 1 || len(idx.recs) != 1 {
		t.Fatalf("store=%d index=%d, want one refresh", len(st.recs), len(idx.recs))
	}
}

func TestHandleEnrichmentBadPayload(t *testing.T) {
	c, _, _ := newConsumer(stubProjection{}, stubPosition{}, stubEmbedder{})
	err := c.Handle(context.Background(), event.Envelope{
		ID: "e", Type: "knowledge.faultline_enriched", Payload: []byte("not json")})
	if err == nil {
		t.Fatal("want an error for a malformed enrichment payload")
	}
}

func TestPrepareEnrichmentBadPayload(t *testing.T) {
	c, _, _ := newConsumer(stubProjection{}, stubPosition{}, stubEmbedder{})
	if _, err := c.Prepare(context.Background(), event.Envelope{
		ID: "e", Type: "knowledge.faultline_enriched", Payload: []byte("{")}); err == nil {
		t.Fatal("want an error for a malformed enrichment payload")
	}
}

// An event carrying no faultline id is claimed and ignored rather than retried forever.
func TestPrepareEnrichmentWithoutFaultlineIDIsANoOp(t *testing.T) {
	st, _ := &captureStore{}, &captureIndex{}
	c := inbound.NewConsumer(projOf([]string{"pkg:x"}, "high"), stubPosition{found: true},
		stubEmbedder{vec: []float32{1}}, st, &captureIndex{})

	apply, err := c.Prepare(context.Background(), event.Envelope{
		ID: "e", Type: "knowledge.faultline_enriched", Payload: []byte(`{"CVE":"CVE-1"}`)})
	if err != nil || apply == nil {
		t.Fatalf("want a no-op apply, got err=%v apply=%v", err, apply != nil)
	}
	if err := apply(context.Background()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if st.faultlineReads != 0 {
		t.Errorf("index was queried %d times for an empty faultline id", st.faultlineReads)
	}
}

// An indexed Finding whose subject text has become un-embeddable is skipped, not written as an
// empty vector — the same rule the Position path applies.
func TestPrepareEnrichmentSkipsUnembeddableFindings(t *testing.T) {
	st, idx := &captureStore{}, &captureIndex{}
	st.indexed = []store.IndexedFinding{{FindingID: "f1", FaultlineID: "fl-1"}}
	c := inbound.NewConsumer(projOf(nil, ""), stubPosition{found: true}, stubEmbedder{vec: []float32{1}}, st, idx)

	apply, err := c.Prepare(context.Background(), event.Envelope{
		ID: "e", Type: "knowledge.faultline_enriched", Payload: []byte(`{"FaultlineID":"fl-1"}`)})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := apply(context.Background()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(st.recs) != 0 {
		t.Fatalf("wrote %d records, want none", len(st.recs))
	}
}

// A read failure while rebuilding one Finding fails the whole event, so it is retried — safe
// because re-embedding is idempotent.
func TestPrepareEnrichmentPropagatesRebuildFailure(t *testing.T) {
	st, idx := &captureStore{}, &captureIndex{}
	st.indexed = []store.IndexedFinding{{FindingID: "f1", FaultlineID: "fl-1"}}
	c := inbound.NewConsumer(stubProjection{err: errors.New("gov down")},
		stubPosition{found: true}, stubEmbedder{vec: []float32{1}}, st, idx)

	if _, err := c.Prepare(context.Background(), event.Envelope{
		ID: "e", Type: "knowledge.faultline_enriched", Payload: []byte(`{"FaultlineID":"fl-1"}`)}); err == nil {
		t.Fatal("want a retryable error")
	}
}

// A write failure inside apply propagates, so the inbox transaction rolls back and the envelope
// is not claimed.
func TestApplyEnrichmentPropagatesWriteFailure(t *testing.T) {
	st, idx := &captureStore{}, &captureIndex{}
	st.indexed = []store.IndexedFinding{{FindingID: "f1", FaultlineID: "fl-1"}}
	c := inbound.NewConsumer(projOf([]string{"pkg:x"}, "high"), stubPosition{found: true},
		stubEmbedder{vec: []float32{1}}, st, idx)

	apply, err := c.Prepare(context.Background(), event.Envelope{
		ID: "e", Type: "knowledge.faultline_enriched", Payload: []byte(`{"FaultlineID":"fl-1"}`)})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	st.err = errors.New("write failed")
	if err := apply(context.Background()); err == nil {
		t.Fatal("want the write failure to propagate so the inbox tx rolls back")
	}
}
