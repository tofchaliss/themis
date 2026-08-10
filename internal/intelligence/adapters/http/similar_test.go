package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/adapters/http/gen"
	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

type fakeRetriever struct {
	out         []domain.PrecedentPosition
	err         error
	gotID       string
	gotTopK     int
	gotSameRel  bool
	callCounter int
}

func (f *fakeRetriever) RetrieveForFinding(_ context.Context, id string, topK int, sameRelease bool) ([]domain.PrecedentPosition, error) {
	f.callCounter++
	f.gotID, f.gotTopK, f.gotSameRel = id, topK, sameRelease
	return f.out, f.err
}

type tagRedactor struct{}

func (tagRedactor) Redact(s string) string { return "[scrubbed]" }

func getSimilar(t *testing.T, h *Handler, url string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, url, nil))
	return rr
}

func decodeSimilar(t *testing.T, rr *httptest.ResponseRecorder) gen.SimilarFindings {
	t.Helper()
	var got gen.SimilarFindings
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rr.Body.String())
	}
	return got
}

func twoPrecedents() []domain.PrecedentPosition {
	return []domain.PrecedentPosition{
		{ReleaseID: "R2", Stance: "not_affected", SourceCVE: "CVE-2", Component: "pkg:golang/openssl", Rationale: "unreachable", Score: 0.91},
		{ReleaseID: "R3", Stance: "affected", SourceCVE: "CVE-3", Component: "pkg:golang/openssl", Rationale: "reachable", Score: 0.77},
	}
}

func TestGetSimilarReturnsRankedPrecedent(t *testing.T) {
	ret := &fakeRetriever{out: twoPrecedents()}
	h := NewHandler(&fakeInvoker{}, nil).WithPrecedents(ret, nil)

	rr := getSimilar(t, h, "/findings/F1/similar")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	got := decodeSimilar(t, rr)
	if got.FindingId != "F1" || len(got.Precedents) != 2 {
		t.Fatalf("got %+v, want F1 with 2 precedents", got)
	}
	if got.Precedents[0].ReleaseId != "R2" || *got.Precedents[0].Score != 0.91 {
		t.Errorf("ranking not preserved: %+v", got.Precedents[0])
	}
	if *got.Precedents[0].SourceCve != "CVE-2" {
		t.Errorf("source_cve = %v, want the precedent's own CVE", got.Precedents[0].SourceCve)
	}
	if ret.gotID != "F1" {
		t.Errorf("retriever asked for %q, want F1", ret.gotID)
	}
}

// The output boundary: rationale is scrubbed on the way out, structural fields survive.
func TestGetSimilarRedactsRationaleOnly(t *testing.T) {
	ret := &fakeRetriever{out: twoPrecedents()}
	h := NewHandler(&fakeInvoker{}, nil).WithPrecedents(ret, tagRedactor{})

	got := decodeSimilar(t, getSimilar(t, h, "/findings/F1/similar"))

	for i, p := range got.Precedents {
		if p.Rationale == nil || *p.Rationale != "[scrubbed]" {
			t.Errorf("precedent %d rationale = %v, want scrubbed", i, p.Rationale)
		}
	}
	if got.Precedents[0].ReleaseId != "R2" || *got.Precedents[0].Component != "pkg:golang/openssl" {
		t.Errorf("redaction must not touch structural fields: %+v", got.Precedents[0])
	}
}

// Redaction is a projection: the slice the service returned must be unchanged, because it is
// the same data the Gateway may hold. A mutating redactor would corrupt the other consumer.
func TestGetSimilarDoesNotMutateTheRetrievedSlice(t *testing.T) {
	out := twoPrecedents()
	ret := &fakeRetriever{out: out}
	h := NewHandler(&fakeInvoker{}, nil).WithPrecedents(ret, tagRedactor{})

	getSimilar(t, h, "/findings/F1/similar")

	if out[0].Rationale != "unreachable" {
		t.Errorf("service result mutated by the response boundary: %q", out[0].Rationale)
	}
}

func TestGetSimilarPassesQuerySemantics(t *testing.T) {
	ret := &fakeRetriever{}
	h := NewHandler(&fakeInvoker{}, nil).WithPrecedents(ret, nil)

	getSimilar(t, h, "/findings/F1/similar?k=3&include_same_release=true")

	if ret.gotTopK != 3 {
		t.Errorf("k = %d, want 3", ret.gotTopK)
	}
	if !ret.gotSameRel {
		t.Error("include_same_release=true did not reach the service")
	}
}

func TestGetSimilarDefaultsQuerySemantics(t *testing.T) {
	ret := &fakeRetriever{}
	h := NewHandler(&fakeInvoker{}, nil).WithPrecedents(ret, nil)

	getSimilar(t, h, "/findings/F1/similar")

	if ret.gotTopK != 0 {
		t.Errorf("k = %d, want 0 (node default)", ret.gotTopK)
	}
	if ret.gotSameRel {
		t.Error("include_same_release must default to false — a Finding is not precedent for itself")
	}
}

// Empty must serialize as [] and not null: "we looked and found nothing" is a real answer, and
// a caller should not have to distinguish it from a missing field.
func TestGetSimilarEmptyIsAnEmptyArrayNotNull(t *testing.T) {
	ret := &fakeRetriever{out: nil}
	h := NewHandler(&fakeInvoker{}, nil).WithPrecedents(ret, nil)

	rr := getSimilar(t, h, "/findings/F1/similar")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(raw["precedents"]) != "[]" {
		t.Errorf("precedents = %s, want []", raw["precedents"])
	}
}

func TestGetSimilarUnknownFindingIs404(t *testing.T) {
	ret := &fakeRetriever{err: app.ErrNoSubject}
	h := NewHandler(&fakeInvoker{}, nil).WithPrecedents(ret, nil)

	if rr := getSimilar(t, h, "/findings/nope/similar"); rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

func TestGetSimilarAnyRetrievalErrorIs404(t *testing.T) {
	ret := &fakeRetriever{err: errors.New("some other failure")}
	h := NewHandler(&fakeInvoker{}, nil).WithPrecedents(ret, nil)

	if rr := getSimilar(t, h, "/findings/F1/similar"); rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

// A node with no retrieval plane says so, rather than returning an empty list that would read
// as "we searched and there is no precedent".
func TestGetSimilarWithoutARetrievalPlaneIs404(t *testing.T) {
	h := NewHandler(&fakeInvoker{}, nil)

	rr := getSimilar(t, h, "/findings/F1/similar")

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "retrieval") {
		t.Errorf("body should explain the node has no retrieval plane, got %s", rr.Body.String())
	}
}
