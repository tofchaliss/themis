package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	knhttp "github.com/themis-project/themis/internal/knowledge/adapters/http"
	"github.com/themis-project/themis/internal/knowledge/adapters/store"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

type fakeRepo struct {
	card  domain.Faultline
	found bool
	err   error
}

func (r fakeRepo) GetByCVE(_ context.Context, cve string) (domain.Faultline, bool, error) {
	if r.err != nil {
		return domain.Faultline{}, false, r.err
	}
	if r.found && r.card.CVE().String() == cve {
		return r.card, true, nil
	}
	return domain.Faultline{}, false, nil
}

func (r fakeRepo) GetByID(_ context.Context, id domain.FaultlineID) (domain.Faultline, error) {
	if r.err != nil {
		return domain.Faultline{}, r.err
	}
	if r.found && r.card.ID() == id {
		return r.card, nil
	}
	return domain.Faultline{}, store.ErrNotFound
}

func (r fakeRepo) Save(context.Context, domain.Faultline, bool, int, []app.OutboxNote) error {
	return nil
}

type fakeProjection struct {
	releases []string
	err      error
}

func (f fakeProjection) AffectedReleases(context.Context, string) ([]string, error) {
	return f.releases, f.err
}

func sampleCard(t *testing.T) domain.Faultline {
	t.Helper()
	cve, _ := value.NewCVEID("CVE-2024-1")
	f, _ := domain.NewFaultline("fl-1", cve)
	c, _ := value.NewCVSS(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
	p, _ := domain.NewVulnFactsProposal("nvd", time.Unix(1_700_000_000, 0),
		domain.VulnFacts{Severity: value.SeverityHigh, CVSS: c, AffectedRanges: []string{"<3.0"}})
	f.FoldProposal(p, domain.NewPrecedence("nvd"))
	return f
}

func server(t *testing.T, repo app.Repository, proj app.ProjectionReader) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(knhttp.NewHandler(app.NewReadService(repo, proj)).Router())
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf [4096]byte
	n, _ := resp.Body.Read(buf[:])
	return resp.StatusCode, buf[:n]
}

func TestGetFaultlineById(t *testing.T) {
	srv := server(t, fakeRepo{card: sampleCard(t), found: true}, fakeProjection{})

	status, body := get(t, srv.URL+"/faultlines/fl-1")
	if status != http.StatusOK {
		t.Fatalf("status = %d: %s", status, body)
	}
	var v struct {
		Cve, Stage string
		View       struct {
			Severity string  `json:"severity"`
			CvssScore float32 `json:"cvss_score"`
		}
		Proposals []map[string]any
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	if v.Cve != "CVE-2024-1" || v.Stage != "enriched" || v.View.Severity != "high" || v.View.CvssScore != 7.5 {
		t.Errorf("view = %+v", v)
	}
	if len(v.Proposals) != 1 {
		t.Errorf("proposals = %d, want 1", len(v.Proposals))
	}

	// Unknown id → 404.
	if status, _ := get(t, srv.URL+"/faultlines/nope"); status != http.StatusNotFound {
		t.Errorf("unknown id status = %d, want 404", status)
	}
}

func TestGetFaultlineByCVE(t *testing.T) {
	srv := server(t, fakeRepo{card: sampleCard(t), found: true}, fakeProjection{})
	if status, _ := get(t, srv.URL+"/faultlines?cve=CVE-2024-1"); status != http.StatusOK {
		t.Errorf("by-cve status = %d, want 200", status)
	}
	// Unknown CVE → 404.
	srv2 := server(t, fakeRepo{found: false}, fakeProjection{})
	if status, _ := get(t, srv2.URL+"/faultlines?cve=CVE-9999-9"); status != http.StatusNotFound {
		t.Errorf("unknown cve status = %d, want 404", status)
	}
}

func TestGetFaultlineReleases(t *testing.T) {
	srv := server(t, fakeRepo{card: sampleCard(t), found: true}, fakeProjection{releases: []string{"rel-1", "rel-2"}})
	status, body := get(t, srv.URL+"/faultlines/fl-1/releases")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	var rels []string
	if err := json.Unmarshal(body, &rels); err != nil {
		t.Fatal(err)
	}
	if len(rels) != 2 {
		t.Errorf("releases = %v, want 2", rels)
	}
}

func TestReadErrors(t *testing.T) {
	boom := errors.New("db down")
	srv := server(t, fakeRepo{err: boom}, fakeProjection{err: boom})
	for _, path := range []string{"/faultlines/fl-1", "/faultlines?cve=CVE-2024-1", "/faultlines/fl-1/releases"} {
		if status, _ := get(t, srv.URL+path); status != http.StatusInternalServerError {
			t.Errorf("%s status = %d, want 500", path, status)
		}
	}
}
