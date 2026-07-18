package feed_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

func golden(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return raw
}

func TestRegistry_Sources(t *testing.T) {
	got := feed.NewRegistry().Sources()
	want := []string{"epsskev", "exploitdb", "nvd", "osv", "redhat", "vexfeed"}
	if len(got) != len(want) {
		t.Fatalf("sources = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("sources not sorted: %v", got)
		}
	}
}

func TestRegistry_GoldenFiles(t *testing.T) {
	r := feed.NewRegistry()

	// nvd → vuln-facts.
	nvd := translateOne(t, r, "nvd")
	if nvd.CVE.String() != "CVE-2024-1234" {
		t.Errorf("nvd cve = %s", nvd.CVE)
	}
	f, ok := nvd.Proposal.VulnFacts()
	if !ok || f.Severity != "high" || f.CVSS.Score() != 7.5 || len(f.AffectedRanges) != 1 || len(f.FixedVersions) != 1 {
		t.Errorf("nvd vuln-facts = %+v ok=%v", f, ok)
	}

	// osv → vuln-facts; the CVE comes from an alias of the GHSA id.
	osv := translateOne(t, r, "osv")
	if osv.CVE.String() != "CVE-2024-1234" {
		t.Errorf("osv cve (from alias) = %s", osv.CVE)
	}
	of, _ := osv.Proposal.VulnFacts()
	if of.Severity != "high" || len(of.AffectedRanges) != 2 || len(of.FixedVersions) != 1 {
		t.Errorf("osv ranges/fixes = %+v", of)
	}

	// redhat → vuln-facts; "important" folds to high.
	rh := translateOne(t, r, "redhat")
	rf, _ := rh.Proposal.VulnFacts()
	if rf.Severity != "high" {
		t.Errorf("redhat severity = %s, want high", rf.Severity)
	}

	// epsskev → exploit-signal.
	ek := translateOne(t, r, "epsskev")
	es, ok := ek.Proposal.ExploitSignal()
	if !ok || es.EPSS != 0.42 || !es.KEV {
		t.Errorf("epsskev signal = %+v ok=%v", es, ok)
	}

	// exploitdb → exploit-signal (public exploit exists).
	ed := translateOne(t, r, "exploitdb")
	eds, _ := ed.Proposal.ExploitSignal()
	if !eds.ExploitPublic {
		t.Error("exploitdb should report a public exploit")
	}

	// vexfeed → one applicability proposal per statement.
	vex, err := r.Translate("vexfeed", golden(t, "vexfeed"))
	if err != nil {
		t.Fatalf("vexfeed: %v", err)
	}
	if len(vex) != 2 {
		t.Fatalf("vexfeed produced %d proposals, want 2", len(vex))
	}
	a0, ok := vex[0].Proposal.Applicability()
	if !ok || a0.Package != "openssl" || a0.Status != "not_affected" {
		t.Errorf("vexfeed statement 0 = %+v ok=%v", a0, ok)
	}
	// Every proposal carries the feed as its source.
	for _, tr := range []feed.Translated{nvd, osv, rh, ek, ed, vex[0]} {
		if tr.Proposal.Source() == "" {
			t.Error("proposal missing source")
		}
	}
}

func TestRegistry_UnsupportedSource(t *testing.T) {
	_, err := feed.NewRegistry().Translate("bogus", []byte(`{}`))
	var ufe *feed.UnsupportedSourceError
	if !errors.As(err, &ufe) {
		t.Fatalf("err = %v, want *UnsupportedSourceError", err)
	}
	if ufe.Requested != "bogus" || len(ufe.Supported) == 0 {
		t.Errorf("unsupported error = %+v", ufe)
	}
}

func TestACLs_HelpfulRejections(t *testing.T) {
	r := feed.NewRegistry()
	cases := []struct {
		name, source, raw string
	}{
		{"nvd bad json", "nvd", `{`},
		{"nvd no cve", "nvd", `{"id":"not-a-cve","observed_at":"2024-05-01T00:00:00Z"}`},
		{"nvd bad time", "nvd", `{"id":"CVE-2024-1","observed_at":"nope"}`},
		{"nvd bad cvss", "nvd", `{"id":"CVE-2024-1","observed_at":"2024-05-01T00:00:00Z","base_score":99}`},
		{"osv bad json", "osv", `{`},
		{"osv no cve", "osv", `{"id":"GHSA-x","aliases":["also-not-cve"],"modified":"2024-05-01T00:00:00Z"}`},
		{"osv bad time", "osv", `{"id":"CVE-2024-1","modified":""}`},
		{"osv bad cvss", "osv", `{"id":"CVE-2024-1","modified":"2024-05-01T00:00:00Z","database_specific":{"cvss_score":42}}`},
		{"redhat bad json", "redhat", `{`},
		{"redhat no cve", "redhat", `{"cve":"x","observed_at":"2024-05-01T00:00:00Z"}`},
		{"redhat bad time", "redhat", `{"cve":"CVE-2024-1","observed_at":"nope"}`},
		{"redhat bad cvss", "redhat", `{"cve":"CVE-2024-1","observed_at":"2024-05-01T00:00:00Z","cvss3":{"cvss3_base_score":42}}`},
		{"epsskev bad json", "epsskev", `{`},
		{"epsskev no cve", "epsskev", `{"cve":"x","observed_at":"2024-05-01T00:00:00Z"}`},
		{"epsskev bad time", "epsskev", `{"cve":"CVE-2024-1","observed_at":"nope"}`},
		{"epsskev epss range", "epsskev", `{"cve":"CVE-2024-1","observed_at":"2024-05-01T00:00:00Z","epss":1.5}`},
		{"exploitdb bad json", "exploitdb", `{`},
		{"exploitdb no cve", "exploitdb", `{"cve":"x","observed_at":"2024-05-01T00:00:00Z"}`},
		{"exploitdb bad time", "exploitdb", `{"cve":"CVE-2024-1","observed_at":"nope"}`},
		{"vexfeed bad json", "vexfeed", `{`},
		{"vexfeed no cve", "vexfeed", `{"vulnerability":"x","observed_at":"2024-05-01T00:00:00Z"}`},
		{"vexfeed bad time", "vexfeed", `{"vulnerability":"CVE-2024-1","observed_at":"nope"}`},
		{"vexfeed no statements", "vexfeed", `{"vulnerability":"CVE-2024-1","observed_at":"2024-05-01T00:00:00Z","statements":[]}`},
		{"vexfeed bad statement", "vexfeed", `{"vulnerability":"CVE-2024-1","observed_at":"2024-05-01T00:00:00Z","statements":[{"product":"","status":""}]}`},
	}
	for _, c := range cases {
		if _, err := r.Translate(c.source, []byte(c.raw)); err == nil {
			t.Errorf("%s: expected a rejection, got nil", c.name)
		}
	}
}

func translateOne(t *testing.T, r *feed.Registry, source string) feed.Translated {
	t.Helper()
	out, err := r.Translate(source, golden(t, source))
	if err != nil {
		t.Fatalf("%s: %v", source, err)
	}
	if len(out) != 1 {
		t.Fatalf("%s produced %d proposals, want 1", source, len(out))
	}
	if out[0].Proposal.Kind() == domain.ProposalKind("") {
		t.Fatalf("%s produced an empty proposal kind", source)
	}
	return out[0]
}
