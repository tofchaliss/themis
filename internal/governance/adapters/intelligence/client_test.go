package intelligence

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientProduced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/capabilities/recommend_position/invoke" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"capability":"recommend_position@v1","stance":"affected",` +
			`"confidence":0.8,"reasoning":"KEV-listed"}`))
	}))
	defer srv.Close()

	rec, produced, _, err := NewClient(srv.URL, srv.Client()).RecommendPosition(context.Background(), "F1")
	if err != nil || !produced {
		t.Fatalf("expected produced; got %v, %v", produced, err)
	}
	if rec.Stance != "affected" || rec.Confidence != 0.8 || rec.Capability != "recommend_position@v1" {
		t.Errorf("recommendation = %+v", rec)
	}
}

func TestClientNoProposal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	_, produced, _, err := NewClient(srv.URL, srv.Client()).RecommendPosition(context.Background(), "F1")
	if err != nil || produced {
		t.Errorf("204 → no proposal, nil err; got %v, %v", produced, err)
	}
}

func TestClientErrors(t *testing.T) {
	boom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer boom.Close()
	if _, _, _, err := NewClient(boom.URL, boom.Client()).RecommendPosition(context.Background(), "F1"); err == nil {
		t.Error("500 should error")
	}

	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	defer badJSON.Close()
	if _, _, _, err := NewClient(badJSON.URL, badJSON.Client()).RecommendPosition(context.Background(), "F1"); err == nil {
		t.Error("bad JSON should error")
	}

	if _, _, _, err := NewClient("http://ex\x00ample", nil).RecommendPosition(context.Background(), "F1"); err == nil {
		t.Error("bad URL should error")
	}
	if _, _, _, err := NewClient("http://127.0.0.1:1", &http.Client{}).RecommendPosition(context.Background(), "F1"); err == nil {
		t.Error("transport error expected")
	}
}

func TestNoopAdvisor(t *testing.T) {
	_, produced, _, err := NoopAdvisor{}.RecommendPosition(context.Background(), "F1")
	if err != nil || produced {
		t.Errorf("no-op must decline; got %v, %v", produced, err)
	}
}

// The 204's two headers stay two fields. They were once concatenated into
// "<reason>: <detail>", which turned a closed enum into free text and made every
// exact-match consumer miss — a `business_invalid` safety refusal reached the operator as
// "the Gateway stated no reason" (DEF_GOV_AI_REASON_COMPOSITE_BREAKS_TAXONOMY).
func TestClientKeepsReasonAndDetailApart(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Themis-AI-Reason", "business_invalid")
		w.Header().Set("X-Themis-AI-Detail", "ungrounded citation: httpd-2.4.37-65")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	_, produced, no, err := NewClient(srv.URL, srv.Client()).RecommendPosition(context.Background(), "F1")
	if err != nil || produced {
		t.Fatalf("204 → no proposal, nil err; got %v, %v", produced, err)
	}
	if no.Reason != "business_invalid" {
		t.Errorf("Reason = %q, want the bare taxonomy word — a consumer switches on it", no.Reason)
	}
	if no.Detail != "ungrounded citation: httpd-2.4.37-65" {
		t.Errorf("Detail = %q, want the elaboration preserved beside the reason", no.Detail)
	}
}

// --- Auth-enabled Intelligence node: the invocation carries X-API-Key ------------------------

// The capability invoke is the one inter-service call of Governance's that is NOT a read, and
// Intelligence's inbound edge refuses a mutation from a read-only key. With the node's key the
// invocation authenticates; without it the Gateway answers 401 and Governance — which treats an
// unavailable Gateway as a safe no-proposal (D13) — would otherwise have no way to tell an
// operator that AI is "off" because a variable is unset.
func TestClientSendsAPIKeyOnlyWhenSet(t *testing.T) {
	const writeKey = "admin-scoped-key-abc123"
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("X-API-Key"))
		if r.Header.Get("X-API-Key") != writeKey {
			// What RequireWriteScope answers a read-only key, and RequireAPIKey an absent one.
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"capability":"recommend_position@v1","stance":"affected","confidence":0.8}`))
	}))
	defer srv.Close()

	// The key is given with surrounding whitespace, as a unit file hands it over; it is trimmed.
	padded := NewClient(srv.URL, srv.Client()).WithAPIKey("  " + writeKey + "\n")
	_, produced, _, err := padded.RecommendPosition(context.Background(), "F1")
	if err != nil || !produced {
		t.Fatalf("an authenticated invocation must produce; got %v, %v", produced, err)
	}

	// Unset: no header at all, an error (never a silent no-proposal), naming the variable AND
	// the scope this call needs — a read-scoped key is the mistake this seam invites.
	_, produced, _, err = NewClient(srv.URL, srv.Client()).RecommendPosition(context.Background(), "F1")
	if err == nil || produced {
		t.Fatalf("an unauthenticated invocation must error; got %v, %v", produced, err)
	}
	for _, want := range []string{"403", "sent no X-API-Key", "THEMIS_API_KEY", "write-capable"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to mention %q", err, want)
		}
	}
	if len(seen) != 2 || seen[1] != "" {
		t.Errorf("headers seen = %q, want the second request to carry no X-API-Key", seen)
	}

	// A refused key is a different operator problem from an absent one, and the credential is
	// never echoed.
	_, _, _, err = NewClient(srv.URL, srv.Client()).WithAPIKey("read-only-key").
		RecommendPosition(context.Background(), "F1")
	if err == nil || !strings.Contains(err.Error(), "Intelligence refused") {
		t.Errorf("err = %v, want it to distinguish a refused key from an absent one", err)
	}
	if strings.Contains(err.Error(), "read-only-key") {
		t.Errorf("err = %v leaked the credential", err)
	}
}

// A 500 carries NO credential advice: naming a variable that is already correct would send an
// operator after the wrong thing.
func TestClientCredentialHintOnlyOnAuthFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, _, _, err := NewClient(srv.URL, srv.Client()).WithAPIKey("key").
		RecommendPosition(context.Background(), "F1")
	if err == nil || strings.Contains(err.Error(), "THEMIS_API_KEY") {
		t.Errorf("err = %v, want a plain 500 with no credential advice", err)
	}
}
