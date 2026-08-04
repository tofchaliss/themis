package readapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/adapters/readapi"
)

func TestCurrentPositionFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"current_position": map[string]string{"stance": "not_affected", "rationale": "unreachable"},
		})
	}))
	defer srv.Close()

	stance, rationale, found, err := readapi.NewPrecedentClient(srv.URL, srv.Client()).
		CurrentPosition(context.Background(), "rel-1", "fl-1")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if stance != "not_affected" || rationale != "unreachable" {
		t.Fatalf("got stance=%q rationale=%q", stance, rationale)
	}
}

func TestCurrentPositionNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, _, found, err := readapi.NewPrecedentClient(srv.URL, srv.Client()).
		CurrentPosition(context.Background(), "rel-1", "fl-1")
	if err != nil || found {
		t.Fatalf("expected found=false err=nil (release without a position), got found=%v err=%v", found, err)
	}
}

func TestCurrentPositionNoPositionInBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer srv.Close()

	_, _, found, err := readapi.NewPrecedentClient(srv.URL, srv.Client()).
		CurrentPosition(context.Background(), "rel-1", "fl-1")
	if err != nil || found {
		t.Fatalf("expected found=false, got found=%v err=%v", found, err)
	}
}

func TestCurrentPositionServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, _, _, err := readapi.NewPrecedentClient(srv.URL, srv.Client()).
		CurrentPosition(context.Background(), "rel-1", "fl-1"); err == nil {
		t.Fatal("expected an error on a 500 response")
	}
}
