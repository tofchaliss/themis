package domain

import (
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
)

func cvss(t *testing.T, score float64) value.CVSS {
	t.Helper()
	c, err := value.NewCVSS(score, "")
	if err != nil {
		t.Fatalf("NewCVSS(%v): %v", score, err)
	}
	return c
}

func TestPriorityAndScore(t *testing.T) {
	z := value.CVSS{} // zero CVSS (no score supplied)
	cases := []struct {
		name     string
		v        EnterpriseView
		priority string
		score    int
	}{
		// --- Priority Layer-1 rules (first match) ---
		{"crit: c>=9 & KEV", EnterpriseView{Severity: value.SeverityCritical, CVSS: cvss(t, 9.8), KEV: true}, PriorityCritical, 100},
		{"high+: c>=9 & exploit", EnterpriseView{CVSS: cvss(t, 9.8), ExploitPublic: true}, PriorityHighPlus, 90},                         // sev derived from CVSS 9.8 -> critical base 90
		{"high: KEV & c<9", EnterpriseView{Severity: value.SeverityHigh, CVSS: cvss(t, 7.5), KEV: true}, PriorityHigh, 85},               // 70 + 15
		{"elevated: EPSS>=.5 & c>=7", EnterpriseView{Severity: value.SeverityHigh, CVSS: cvss(t, 7.5), EPSS: 0.6}, PriorityElevated, 83}, // 70 + 70*.6*.3 = 82.6
		{"high: c>=9 plain", EnterpriseView{Severity: value.SeverityHigh, CVSS: cvss(t, 9.1)}, PriorityHigh, 70},
		{"informational: low c", EnterpriseView{Severity: value.SeverityMedium, CVSS: cvss(t, 5.0)}, PriorityInformational, 40},

		// --- effectiveCVSS severity proxies (no CVSS) + effectiveSeverity return-set branch ---
		{"proxy high -> elevated", EnterpriseView{Severity: value.SeverityHigh, CVSS: z, EPSS: 0.6}, PriorityElevated, 83}, // c=7 proxy; 70 + 12.6
		{"proxy medium -> info", EnterpriseView{Severity: value.SeverityMedium, CVSS: z}, PriorityInformational, 40},
		{"proxy low -> info", EnterpriseView{Severity: value.SeverityLow, CVSS: z}, PriorityInformational, 10},
		{"proxy critical -> high", EnterpriseView{Severity: value.SeverityCritical, CVSS: z, EPSS: 0.2}, PriorityHigh, 95}, // c=9 proxy, no KEV -> rule5; 90 + 5.4

		// --- effectiveSeverity: derive from CVSS when headline none/unknown ---
		{"none sev + CVSS derives", EnterpriseView{Severity: value.SeverityNone, CVSS: cvss(t, 9.0)}, PriorityHigh, 90}, // derived critical base 90
		{"unknown sev no CVSS -> 0", EnterpriseView{Severity: value.SeverityUnknown, CVSS: z}, PriorityInformational, 0},

		// --- Score edges ---
		{"KEV bump + clamp", EnterpriseView{Severity: value.SeverityHigh, CVSS: cvss(t, 7.5), EPSS: 0.9, KEV: true}, PriorityHigh, 100},           // 70 + 18.9 + 15 = 103.9 -> 100
		{"unknown sev + KEV floor", EnterpriseView{Severity: value.SeverityUnknown, CVSS: z, KEV: true}, PriorityHigh, 65},                        // base 50 + 15
		{"unknown sev + exploit floor", EnterpriseView{Severity: value.SeverityUnknown, CVSS: z, ExploitPublic: true}, PriorityInformational, 25}, // base 25
		{"low baseline", EnterpriseView{Severity: value.SeverityLow, CVSS: cvss(t, 2.0)}, PriorityInformational, 10},
	}
	for _, c := range cases {
		if got := c.v.Priority(); got != c.priority {
			t.Errorf("%s: Priority() = %q, want %q", c.name, got, c.priority)
		}
		if got := c.v.Score(); got != c.score {
			t.Errorf("%s: Score() = %d, want %d", c.name, got, c.score)
		}
	}
}
