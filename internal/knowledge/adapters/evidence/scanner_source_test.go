package evidence

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
)

// docServer serves Evidence's document endpoint for one canned document.
func docServer(t *testing.T, kind, document string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"kind": kind, "document": document})
	}))
}

const goodFinding = `{"cve":"CVE-2024-1111","observed_at":"2026-08-13T00:00:00Z","scanner":"trivy",` +
	`"severity":"HIGH","cvss_score":7.5,"cvss_vector":"","affected":[">= 1.0, < 2.0"],"fixed":["2.0"],` +
	`"component":{"purl":"pkg:rpm/rocky/openssl@3.0.7","name":"openssl","version":"3.0.7","ecosystem":"rpm","source":"openssl"}}`

// A usable finding whose report names no engine — the origin falls back to bare `scanner`.
const goodFindingNoEngine = `{"cve":"CVE-2024-3333","observed_at":"2026-08-13T00:00:00Z",` +
	`"severity":"LOW","cvss_score":3.1,"cvss_vector":"","affected":[],"fixed":[],` +
	`"component":{"purl":"pkg:npm/lodash@4.17.20","name":"lodash","version":"4.17.20","ecosystem":"npm","source":""}}`

func TestScannerSource_TranslatesFindingsAndSkipsBadOnes(t *testing.T) {
	report := `{"findings":[` + goodFinding + `,` + goodFindingNoEngine + `,` +
		`{"cve":"not-a-cve","observed_at":"2026-08-13T00:00:00Z","severity":"LOW"},` + // no canonical CVE → skip
		`{"cve":"CVE-2024-2222","observed_at":"2026-08-13T00:00:00Z","severity":"LOW","cvss_score":0,"cvss_vector":""}` + // no component → skip
		`]}`
	srv := docServer(t, "scanner-report", report)
	defer srv.Close()

	src := NewScannerSource(NewClient(srv.URL, nil), feed.NewRegistry())
	props, skipped, err := src.ScannerProposals(context.Background(), "ev-1")
	if err != nil {
		t.Fatalf("ScannerProposals: %v", err)
	}
	if len(props) != 2 || skipped != 2 {
		t.Fatalf("props=%d skipped=%d, want 2 usable findings and 2 counted skips", len(props), skipped)
	}
	p := props[0]
	if p.CVE.String() != "CVE-2024-1111" || p.Component.Name != "openssl" || p.Component.Ecosystem != "rpm" {
		t.Errorf("proposal = %+v / component %+v, want the translated finding with its component", p.CVE, p.Component)
	}
	if p.Proposal.Source() != "scanner" {
		t.Errorf("source = %q, want the scanner ACL's source id", p.Proposal.Source())
	}
	// KN-SCAN-2: the engine name becomes display provenance — and ONLY that. The proposal
	// source above stays the closed-vocabulary `scanner`, or the trust table stops being
	// enumerable (TRUST-2).
	if p.Origin != "scanner/trivy" {
		t.Errorf("origin = %q, want scanner/trivy from the record's scanner field", p.Origin)
	}
	if props[1].Origin != "scanner" {
		t.Errorf("origin = %q, want bare scanner when the report names no engine", props[1].Origin)
	}
}

// A mis-routed evidence id — the document exists but is another kind — must be an error, not
// an empty success: silently ingesting zero findings from an SBOM would be the same class of
// quiet no-op this seam exists to kill.
func TestScannerSource_WrongKindIsAnError(t *testing.T) {
	srv := docServer(t, "sbom", `{"components":[]}`)
	defer srv.Close()
	if _, _, err := NewScannerSource(NewClient(srv.URL, nil), feed.NewRegistry()).
		ScannerProposals(context.Background(), "ev-1"); err == nil {
		t.Fatal("an sbom document ingested as a scanner report")
	}
}

func TestScannerSource_BadEnvelopeIsAnError(t *testing.T) {
	srv := docServer(t, "scanner-report", `not json at all`)
	defer srv.Close()
	if _, _, err := NewScannerSource(NewClient(srv.URL, nil), feed.NewRegistry()).
		ScannerProposals(context.Background(), "ev-1"); err == nil {
		t.Fatal("an unparseable envelope reported success")
	}
}

func TestScannerSource_UnreachableEvidencePropagates(t *testing.T) {
	if _, _, err := NewScannerSource(NewClient("http://127.0.0.1:1", nil), feed.NewRegistry()).
		ScannerProposals(context.Background(), "ev-1"); err == nil {
		t.Fatal("an unreachable Evidence reported success")
	}
}
