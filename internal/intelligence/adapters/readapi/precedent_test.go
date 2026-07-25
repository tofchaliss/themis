package readapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/adapters/readapi"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

func precedentServer(t *testing.T, blastStatus int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/blast-radius"):
			if blastStatus != http.StatusOK {
				w.WriteHeader(blastStatus)
				return
			}
			_, _ = w.Write([]byte(`["R1","R2","R3"]`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/findings"):
			switch r.URL.Query().Get("release") {
			case "R2":
				_, _ = w.Write([]byte(`{"current_position":{"stance":"not_affected","rationale":"backported fix"}}`))
			case "R3":
				w.WriteHeader(http.StatusNotFound) // no finding in that release
			default:
				_, _ = w.Write([]byte(`{}`)) // R1: finding exists but no current position
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPrecedentClientComposesReads(t *testing.T) {
	srv := precedentServer(t, http.StatusOK)
	c := readapi.NewPrecedentClient(srv.URL, srv.Client())

	got, err := c.GetPrecedents(context.Background(), "FL1", "R0")
	if err != nil {
		t.Fatal(err)
	}
	want := []domain.PrecedentPosition{{ReleaseID: "R2", Stance: "not_affected", Rationale: "backported fix"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("precedents = %+v, want %+v (R1 no-position + R3 not-found are skipped)", got, want)
	}
}

func TestPrecedentClientExcludesSubjectRelease(t *testing.T) {
	srv := precedentServer(t, http.StatusOK)
	c := readapi.NewPrecedentClient(srv.URL, srv.Client())

	got, err := c.GetPrecedents(context.Background(), "FL1", "R2") // exclude the only positioned release
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("precedents = %+v, want none (subject release excluded)", got)
	}
}

func TestPrecedentClientBlastRadiusError(t *testing.T) {
	srv := precedentServer(t, http.StatusInternalServerError)
	c := readapi.NewPrecedentClient(srv.URL, srv.Client())
	if _, err := c.GetPrecedents(context.Background(), "FL1", "R0"); err == nil {
		t.Error("expected an error when blast-radius fails")
	}
}

func TestPrecedentClientDefaultHTTPClient(t *testing.T) {
	// nil http client falls back to the default; unreachable host → transport error.
	c := readapi.NewPrecedentClient("http://127.0.0.1:0", nil)
	if _, err := c.GetPrecedents(context.Background(), "FL1", "R0"); err == nil {
		t.Error("expected a transport error against an unreachable host")
	}
}
