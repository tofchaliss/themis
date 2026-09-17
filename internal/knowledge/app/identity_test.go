package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"

	"github.com/themis-project/themis/internal/knowledge/app"
)

// EDR-IDENTITY-01 D1: Knowledge must be able to tell an IDENTITY from a string. It could not
// before — `value.NewPURL` was called only in Evidence — which is how `app:httpd` travelled all
// the way to a Governance rejection that halts the Knowledge→Governance stream.
func TestUsablePURL(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
		why  string
	}{
		{"pkg:rpm/rocky/httpd@2.4.57", true, "the measured good twin"},
		{"pkg:pypi/setuptools@39.2.0", true, "an ordinary language package"},
		{"  pkg:rpm/rocky/httpd@2.4.57  ", true, "surrounding whitespace is not a defect"},
		{"app:httpd", false, "THE measured bad identifier — non-empty and not an identity"},
		{"", false, "an empty PURL is not an identity (D1), and collapses to the same outcome"},
		{"httpd", false, "a bare name is a name, not an identity"},
		{"pkg:", false, "a scheme alone identifies nothing"},
	} {
		if got := app.UsablePURL(c.in); got != c.want {
			t.Errorf("UsablePURL(%q) = %v, want %v — %s", c.in, got, c.want, c.why)
		}
	}
}

// EDR-IDENTITY-01 D2: resolve onto an unambiguous twin; abstain otherwise. The measured basis is
// one SPDX document carrying the same httpd package twice — once with a proper rpm purl, once
// with no externalRefs at all, same name, same versionInfo.
func TestResolveIdentity(t *testing.T) {
	good := app.InventoryComponent{
		PURL: "pkg:rpm/rocky/httpd@2.4.57", Name: "httpd", Version: "2.4.57", Ecosystem: "rpm",
	}
	obs := app.InventoryComponent{PURL: "app:httpd", Name: "httpd", Version: "2.4.57"}

	t.Run("exactly one candidate resolves — the measured case", func(t *testing.T) {
		purl, reason := app.ResolveIdentity(obs, []app.InventoryComponent{good})
		if purl != good.PURL || reason != "" {
			t.Errorf("= %q/%q, want the twin's purl and no reason", purl, reason)
		}
	})

	t.Run("case differs on the name but not the version", func(t *testing.T) {
		upper := app.InventoryComponent{PURL: "app:HTTPD", Name: "HTTPD", Version: "2.4.57"}
		if purl, _ := app.ResolveIdentity(upper, []app.InventoryComponent{good}); purl != good.PURL {
			t.Errorf("= %q, want the twin — a distro is inconsistent about case", purl)
		}
	})

	t.Run("two DISTINCT purls abstain — no tie-break is invented", func(t *testing.T) {
		other := good
		other.PURL = "pkg:rpm/rhel/httpd@2.4.57"
		purl, reason := app.ResolveIdentity(obs, []app.InventoryComponent{good, other})
		if purl != "" || reason != app.ReasonAmbiguous {
			t.Errorf("= %q/%q, want abstain/ambiguous", purl, reason)
		}
	})

	t.Run("the SAME purl twice is not ambiguity", func(t *testing.T) {
		if purl, reason := app.ResolveIdentity(obs, []app.InventoryComponent{good, good}); purl != good.PURL {
			t.Errorf("= %q/%q, want the twin — one identity observed twice is still one", purl, reason)
		}
	})

	t.Run("zero candidates abstain — the scanner-only release (D8)", func(t *testing.T) {
		purl, reason := app.ResolveIdentity(obs, nil)
		if purl != "" || reason != app.ReasonNoCandidate {
			t.Errorf("= %q/%q, want abstain/no_candidate", purl, reason)
		}
	})

	t.Run("a different VERSION is a different build and must never resolve", func(t *testing.T) {
		older := good
		older.Version, older.PURL = "2.4.53", "pkg:rpm/rocky/httpd@2.4.53"
		purl, reason := app.ResolveIdentity(obs, []app.InventoryComponent{older})
		if purl != "" || reason != app.ReasonNoCandidate {
			t.Errorf("= %q/%q, want abstain — resolving onto another build is the one error to avoid", purl, reason)
		}
	})

	t.Run("a candidate with no usable purl cannot lend one", func(t *testing.T) {
		twinless := app.InventoryComponent{PURL: "app:httpd", Name: "httpd", Version: "2.4.57"}
		purl, reason := app.ResolveIdentity(obs, []app.InventoryComponent{twinless})
		if purl != "" || reason != app.ReasonNoCandidate {
			t.Errorf("= %q/%q, want abstain — two unidentified rows do not make an identity", purl, reason)
		}
	})

	t.Run("a name alone is never enough", func(t *testing.T) {
		for _, bad := range []app.InventoryComponent{
			{PURL: "app:httpd", Name: "httpd"},
			{PURL: "app:httpd", Version: "2.4.57"},
		} {
			// Matching on a name alone would merge every version of a package onto one
			// identity — the same shape as the empty-purl primary-key collapse.
			if purl, reason := app.ResolveIdentity(bad, []app.InventoryComponent{good}); purl != "" || reason != app.ReasonNoCandidate {
				t.Errorf("%+v = %q/%q, want abstain", bad, purl, reason)
			}
		}
	})

	t.Run("no synthesized purl appears anywhere (D3)", func(t *testing.T) {
		purl, _ := app.ResolveIdentity(obs, nil)
		if purl != "" {
			t.Errorf("abstention returned %q — a synthesized identity is the one thing D3 forbids", purl)
		}
	})
}

// factsStub resolves an evidence id to its kind and release.
type factsStub struct {
	kind, release string
	found         bool
	err           error
}

func (f factsStub) EvidenceFacts(context.Context, string) (string, string, bool, error) {
	return f.kind, f.release, f.found, f.err
}

// EDR-IDENTITY-01 D6: the unresolved population is answerable on demand, RECOMPUTED from
// immutable evidence rather than read from a stored count. That is the point — it runs through
// PlanIngest, the same code path the ingest uses, so the answer cannot drift from the behaviour
// it describes. A stored count could, and that is precisely how GOV-MIRROR-1's divergence
// happened.
func TestUnresolvedComponents(t *testing.T) {
	obs := app.ScannerProposal{
		CVE: cve(t, "CVE-2023-31122"), Proposal: vulnFacts(t, "scanner", value.SeverityHigh),
		Component: app.InventoryComponent{PURL: "app:httpd", Name: "httpd", Version: "2.4.57"},
		Origin:    "scanner/cortex",
	}
	identified := app.ScannerProposal{
		CVE: cve(t, "CVE-2024-1"), Proposal: vulnFacts(t, "scanner", value.SeverityHigh),
		Component: app.InventoryComponent{PURL: "pkg:pypi/foo@1"}, Origin: "scanner",
	}

	t.Run("reports the unresolved observation with its verbatim identifier", func(t *testing.T) {
		svc := scannerService(t, fakeScannerSource{props: []app.ScannerProposal{obs, identified}},
			newMatches(), newRepo()).
			WithEvidenceFacts(factsStub{kind: "scanner-report", release: "rel-1", found: true})

		rep, err := svc.UnresolvedComponents(context.Background(), "ev-report")
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if rep.ReleaseID != "rel-1" || rep.EvidenceID != "ev-report" {
			t.Errorf("report = %+v, want the release resolved from evidence facts", rep)
		}
		if rep.Resolved != 1 || len(rep.Unresolved) != 1 {
			t.Fatalf("resolved=%d unresolved=%d, want 1/1", rep.Resolved, len(rep.Unresolved))
		}
		u := rep.Unresolved[0]
		if u.RawPURL != "app:httpd" {
			t.Errorf("observed purl = %q, want the report's own string verbatim", u.RawPURL)
		}
		if u.Reason != app.ReasonNoCandidate {
			t.Errorf("reason = %q, want no_candidate", u.Reason)
		}
	})

	t.Run("the query writes nothing", func(t *testing.T) {
		matches := newMatches()
		svc := scannerService(t, fakeScannerSource{props: []app.ScannerProposal{obs, identified}}, matches, newRepo()).
			WithEvidenceFacts(factsStub{kind: "scanner-report", release: "rel-1", found: true})
		if _, err := svc.UnresolvedComponents(context.Background(), "ev-report"); err != nil {
			t.Fatalf("query: %v", err)
		}
		if len(matches.byPURL) != 0 {
			t.Errorf("the query recorded %v — it must read only", matches.byPURL)
		}
	})

	t.Run("a non-scanner document has no observations to resolve", func(t *testing.T) {
		svc := scannerService(t, fakeScannerSource{}, newMatches(), newRepo()).
			WithEvidenceFacts(factsStub{kind: "sbom", release: "rel-1", found: true})
		if _, err := svc.UnresolvedComponents(context.Background(), "ev-sbom"); !errors.Is(err, app.ErrNotScannerReport) {
			t.Errorf("err = %v, want ErrNotScannerReport", err)
		}
	})

	t.Run("an unknown id is distinguishable from an empty answer", func(t *testing.T) {
		svc := scannerService(t, fakeScannerSource{}, newMatches(), newRepo()).
			WithEvidenceFacts(factsStub{})
		if _, err := svc.UnresolvedComponents(context.Background(), "ev-ghost"); !errors.Is(err, app.ErrNoSuchEvidence) {
			t.Errorf("err = %v, want ErrNoSuchEvidence — 'not found' must not read as 'all clear'", err)
		}
	})

	t.Run("errors propagate rather than reading as all-clear", func(t *testing.T) {
		boom := errors.New("evidence down")
		svc := scannerService(t, fakeScannerSource{}, newMatches(), newRepo()).
			WithEvidenceFacts(factsStub{err: boom})
		if _, err := svc.UnresolvedComponents(context.Background(), "ev-1"); err == nil {
			t.Error("a facts-read failure must surface")
		}
		src := fakeScannerSource{err: boom}
		svc2 := scannerService(t, src, newMatches(), newRepo()).
			WithEvidenceFacts(factsStub{kind: "scanner-report", release: "rel-1", found: true})
		if _, err := svc2.UnresolvedComponents(context.Background(), "ev-1"); err == nil {
			t.Error("a report-read failure must surface")
		}
	})

	t.Run("unwired facts refuse honestly instead of answering none", func(t *testing.T) {
		svc := scannerService(t, fakeScannerSource{}, newMatches(), newRepo())
		if _, err := svc.UnresolvedComponents(context.Background(), "ev-1"); err == nil {
			t.Error("an unwired query must refuse, not report zero unresolved")
		}
	})
}
