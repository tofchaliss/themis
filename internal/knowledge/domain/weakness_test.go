package domain_test

import (
	"fmt"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

// EDR-PSIRT-01 choice 6: every source spelling reads to one sorted, distinct set of CWE ids, and
// the NVD placeholders, which name no weakness, are dropped.
func TestNormalizeCWEs(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"CWE-787"}, "[CWE-787]"},
		{[]string{"cwe-79", "CWE-79"}, "[CWE-79]"},
		{[]string{"CWE-120->CWE-787", "(CWE-119|CWE-20)"}, "[CWE-20 CWE-119 CWE-120 CWE-787]"},
		{[]string{"NVD-CWE-noinfo", "NVD-CWE-Other"}, "[]"},
		{[]string{"CWE-0", "CWE-x", ""}, "[]"},
		{nil, "[]"},
	}
	for _, c := range cases {
		if got := fmt.Sprint(domain.NormalizeCWEs(c.in...)); got != c.want {
			t.Errorf("NormalizeCWEs(%q) = %s, want %s", c.in, got, c.want)
		}
	}
	if domain.NormalizeCWEs("NVD-CWE-noinfo") != nil {
		t.Error("no id must be nil, so the wire omits it")
	}
}

// The label is the first table row any CWE maps to, so the worse type wins; an unmapped CWE is
// "Other"; no CWE is no label.
func TestIssueType(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"CWE-78"}, "Code execution"},
		{[]string{"CWE-400", "CWE-787"}, "Memory safety"},
		{[]string{"CWE-787", "CWE-94"}, "Code execution"},
		{[]string{"cwe-79"}, "Cross-site scripting"},
		{[]string{" CWE-400 "}, "Denial of service"},
		{[]string{"CWE-20"}, "Input validation"},
		{[]string{"CWE-99999"}, domain.IssueTypeOther},
		{[]string{"not-a-cwe"}, domain.IssueTypeOther},
		{nil, ""},
	}
	for _, c := range cases {
		if got := domain.IssueType(c.in); got != c.want {
			t.Errorf("IssueType(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if domain.IssueTypeTableVersion == "" {
		t.Error("the table must carry a version")
	}
}
