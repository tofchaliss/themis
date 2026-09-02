package feed_test

import (
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
)

// The rocky ACL translates one RXSA fix statement: a source package, its fixing rpm version,
// and the CVEs that version addresses — one rpm-stamped fix-bound Proposal per canonical CVE.
func TestRockyACL_Translate(t *testing.T) {
	r := feed.NewRegistry()
	out, err := r.Translate("rocky", []byte(`{
		"package": "kernel", "fix_version": "0:5.14.0-687.36.1.el9_8.cloud.1.0",
		"cves": ["CVE-2026-23415", "RXSA-2026:51035", "CVE-2026-43450"],
		"observed_at": "2026-08-27T00:00:00Z"
	}`))
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("translated = %d, want 2 (the RXSA id can never match a card)", len(out))
	}
	for _, tr := range out {
		facts, ok := tr.Proposal.VulnFacts()
		if !ok || len(facts.Fixes) != 1 {
			t.Fatalf("%s: fixes = %+v, want one bound", tr.CVE, facts.Fixes)
		}
		f := facts.Fixes[0]
		if f.Package != "kernel" || f.Version != "0:5.14.0-687.36.1.el9_8.cloud.1.0" || f.Ecosystem != "rpm" {
			t.Errorf("%s: fix = %+v, want the rpm-stamped kernel bound", tr.CVE, f)
		}
	}
}

func TestRockyACL_Rejections(t *testing.T) {
	r := feed.NewRegistry()
	for name, raw := range map[string]string{
		"invalid json":     `{`,
		"no observed_at":   `{"package":"kernel","fix_version":"0:5.14.0-687.el9","cves":["CVE-2026-1"]}`,
		"no package":       `{"fix_version":"0:5.14.0-687.el9","cves":["CVE-2026-1"],"observed_at":"2026-08-27T00:00:00Z"}`,
		"no fix version":   `{"package":"kernel","cves":["CVE-2026-1"],"observed_at":"2026-08-27T00:00:00Z"}`,
		"no canonical CVE": `{"package":"kernel","fix_version":"0:5.14.0-687.el9","cves":["RXSA-2026:1"],"observed_at":"2026-08-27T00:00:00Z"}`,
	} {
		if _, err := r.Translate("rocky", []byte(raw)); err == nil {
			t.Errorf("%s: expected a rejection", name)
		} else if strings.Contains(err.Error(), "panic") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
