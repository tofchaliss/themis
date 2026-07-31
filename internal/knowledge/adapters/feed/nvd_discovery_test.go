package feed_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
	"github.com/themis-project/themis/internal/knowledge/app"
)

// cveWithCPE builds a live NVD CVE with a CVSS metric (so translate keeps it) and a single
// vulnerable CPE match naming product, with a <2.0 upper bound.
func cveWithCPE(id, product string) string {
	return `{"id":"` + id + `","lastModified":"2026-07-20T10:00:00.000",` +
		`"metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":7.5,"baseSeverity":"HIGH","vectorString":"CVSS:3.1"}}]},` +
		`"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,` +
		`"criteria":"cpe:2.3:a:vendor:` + product + `:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]}]}`
}

// TestNVDClient_VulnsForPackage_ProductGate proves the A2 precision gate: a keyword search that
// returns two CVEs — one whose CPE product IS the component, one that only mentions it — keeps
// only the CVE whose CPE product matches. This is what makes NVD-by-keyword safe.
func TestNVDClient_VulnsForPackage_ProductGate(t *testing.T) {
	srv := nvdServer(t, cveWithCPE("CVE-2024-100", "urllib3"), cveWithCPE("CVE-2024-200", "django"))
	c := feed.NewNVDClient(srv.URL, "", srv.Client())

	got, err := c.VulnsForPackage(context.Background(), app.InventoryComponent{Name: "urllib3"})
	if err != nil {
		t.Fatalf("VulnsForPackage: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d proposals, want 1 (the non-matching CPE product must be dropped)", len(got))
	}
	if got[0].CVE.String() != "CVE-2024-100" {
		t.Errorf("kept %s, want CVE-2024-100", got[0].CVE.String())
	}

	// An empty/blank component name issues no query and returns nothing.
	if pfs, err := c.VulnsForPackage(context.Background(), app.InventoryComponent{Name: "  "}); err != nil || pfs != nil {
		t.Errorf("blank name: got %v err=%v, want nil,nil", pfs, err)
	}
}

type stubSource struct {
	pfs []app.ProposalFor
	err error
}

func (s stubSource) VulnsForPackage(context.Context, app.InventoryComponent) ([]app.ProposalFor, error) {
	return s.pfs, s.err
}

// TestMultiSource covers the best-effort fan-out: results concatenate, one source's failure
// does not block the others, and an error surfaces only when every source fails.
func TestMultiSource(t *testing.T) {
	comp := app.InventoryComponent{Name: "x"}
	one := make([]app.ProposalFor, 1)

	got, err := feed.NewMultiSource(stubSource{pfs: one}, stubSource{pfs: one}).VulnsForPackage(context.Background(), comp)
	if err != nil || len(got) != 2 {
		t.Fatalf("concat: got %d err=%v, want 2,nil", len(got), err)
	}

	got, err = feed.NewMultiSource(stubSource{err: errors.New("down")}, stubSource{pfs: one}).VulnsForPackage(context.Background(), comp)
	if err != nil || len(got) != 1 {
		t.Fatalf("best-effort: got %d err=%v, want 1,nil", len(got), err)
	}

	if _, err := feed.NewMultiSource(stubSource{err: errors.New("a")}, stubSource{err: errors.New("b")}).VulnsForPackage(context.Background(), comp); err == nil {
		t.Error("all sources failed: want error, got nil")
	}
}
