package feed_test

import (
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
)

// The alpine ACL translates one secdb fix statement: a package, its fixing apk version, and the
// ids that version addresses — one fix-bound Proposal per canonical CVE among them.
func TestAlpineACL_Translate(t *testing.T) {
	r := feed.NewRegistry()
	out, err := r.Translate("alpine", []byte(`{
		"package": "openssl", "fix_version": "3.1.4-r5",
		"cves": ["CVE-2024-1", "XSA-999", "CVE-2024-2"],
		"observed_at": "2026-08-12T00:00:00Z"
	}`))
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("translated = %d, want 2 (the XSA id can never match a card)", len(out))
	}
	for _, tr := range out {
		facts, ok := tr.Proposal.VulnFacts()
		if !ok || len(facts.Fixes) != 1 || facts.Fixes[0].Package != "openssl" || facts.Fixes[0].Version != "3.1.4-r5" {
			t.Errorf("%s: fixes = %+v, want the openssl 3.1.4-r5 bound", tr.CVE, facts.Fixes)
		}
	}
}

func TestAlpineACL_Rejections(t *testing.T) {
	r := feed.NewRegistry()
	for name, raw := range map[string]string{
		"invalid json":         `{`,
		"no observed_at":       `{"package":"openssl","fix_version":"3.1.4-r5","cves":["CVE-2024-1"]}`,
		"no package":           `{"fix_version":"3.1.4-r5","cves":["CVE-2024-1"],"observed_at":"2026-08-12T00:00:00Z"}`,
		"unfixed marker \"0\"": `{"package":"openssl","fix_version":"0","cves":["CVE-2024-1"],"observed_at":"2026-08-12T00:00:00Z"}`,
		"no canonical CVE":     `{"package":"openssl","fix_version":"3.1.4-r5","cves":["XSA-999"],"observed_at":"2026-08-12T00:00:00Z"}`,
	} {
		if _, err := r.Translate("alpine", []byte(raw)); err == nil {
			t.Errorf("%s: expected a rejection", name)
		} else if strings.Contains(err.Error(), "panic") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
