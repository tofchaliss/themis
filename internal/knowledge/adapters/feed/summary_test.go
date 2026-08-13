package feed

import (
	"strings"
	"testing"
)

// The summary must survive translation from each feed's own shape — it was delivered on
// every record for two months and parsed by nothing, which is why no screen could say what
// a CVE was about.

func TestOSVTranslateCarriesSummary(t *testing.T) {
	raw := []byte(`{"id":"CVE-2026-1000","modified":"2026-08-01T00:00:00Z",
		"summary":"A heap overflow in libfoo's parser.",
		"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`)
	out, err := osvACL{}.Translate(raw)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	f, _ := out[0].Proposal.VulnFacts()
	if f.Summary != "A heap overflow in libfoo's parser." {
		t.Fatalf("summary = %q", f.Summary)
	}
}

func TestOSVSummaryFallsBackToFirstParagraphOfDetails(t *testing.T) {
	raw := []byte(`{"id":"CVE-2026-1000","modified":"2026-08-01T00:00:00Z",
		"details":"First paragraph explains the flaw.\n\nSecond paragraph is remediation prose that should not ride along.",
		"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`)
	out, err := osvACL{}.Translate(raw)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	f, _ := out[0].Proposal.VulnFacts()
	if f.Summary != "First paragraph explains the flaw." {
		t.Fatalf("summary = %q, want the first paragraph only", f.Summary)
	}
}

func TestOSVSummaryEmptyWhenFeedHasNone(t *testing.T) {
	raw := []byte(`{"id":"CVE-2026-1000","modified":"2026-08-01T00:00:00Z",
		"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`)
	out, err := osvACL{}.Translate(raw)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if f, _ := out[0].Proposal.VulnFacts(); f.Summary != "" {
		t.Fatalf("summary = %q, want empty", f.Summary)
	}
}

func TestOSVSummaryIsBounded(t *testing.T) {
	long := strings.Repeat("wordy ", 200)
	raw := []byte(`{"id":"CVE-2026-1000","modified":"2026-08-01T00:00:00Z",
		"summary":"` + long + `",
		"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`)
	out, err := osvACL{}.Translate(raw)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	f, _ := out[0].Proposal.VulnFacts()
	if len([]rune(f.Summary)) > 480 {
		t.Fatalf("summary not bounded: %d runes", len([]rune(f.Summary)))
	}
}

func TestNVDTranslateCarriesSummary(t *testing.T) {
	raw := []byte(`{"id":"CVE-2026-2000","observed_at":"2026-08-01T00:00:00Z",
		"summary":"urllib.parse mishandles URLs beginning with blank characters.",
		"base_score":7.5,"vector_string":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","base_severity":"HIGH"}`)
	out, err := nvdACL{}.Translate(raw)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	f, _ := out[0].Proposal.VulnFacts()
	if !strings.HasPrefix(f.Summary, "urllib.parse mishandles") {
		t.Fatalf("summary = %q", f.Summary)
	}
}

func TestNVDEnglishDescriptionSelection(t *testing.T) {
	pick := func(langs ...[2]string) string {
		var cve nvdLiveCVE
		for _, l := range langs {
			cve.Descriptions = append(cve.Descriptions, struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{Lang: l[0], Value: l[1]})
		}
		return nvdEnglishDescription(cve)
	}
	if got := pick([2]string{"es", "hola"}, [2]string{"en", "hello"}); got != "hello" {
		t.Fatalf("en preferred: %q", got)
	}
	if got := pick([2]string{"es", "hola"}); got != "hola" {
		t.Fatalf("fallback to first: %q", got)
	}
	if got := pick(); got != "" {
		t.Fatalf("no descriptions: %q", got)
	}
}
