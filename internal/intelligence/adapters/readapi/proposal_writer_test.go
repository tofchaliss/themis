package readapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/adapters/readapi"
)

func TestRaiseAIProposal(t *testing.T) {
	var gotBody map[string]any
	var gotKey, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.Header.Get("X-API-Key")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"proposal_id":"p-1"}`))
	}))
	defer srv.Close()

	wr := readapi.NewProposalWriter(srv.URL, "node-write-key", srv.Client())
	if err := wr.RaiseAIProposal(context.Background(), "f-1", "not_affected", "decided next door"); err != nil {
		t.Fatalf("raise: %v", err)
	}
	if gotPath != "/api/v1/findings/f-1/proposals" {
		t.Errorf("path = %q", gotPath)
	}
	if gotKey != "node-write-key" {
		t.Errorf("write key not sent: %q", gotKey)
	}
	// proposer_kind MUST be ai — that is what makes it advisory-only and never auto-acceptable.
	if gotBody["proposer_kind"] != "ai" || gotBody["stance"] != "not_affected" {
		t.Errorf("body = %+v, want proposer_kind ai + stance", gotBody)
	}
}

func TestRaiseAIProposal_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()
	wr := readapi.NewProposalWriter(srv.URL, "", nil)
	if err := wr.RaiseAIProposal(context.Background(), "f-1", "not_affected", "x"); err == nil {
		t.Error("a non-2xx must be an error the sweep skips on")
	}
}
