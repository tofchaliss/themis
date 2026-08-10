package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

func TestSubjectText(t *testing.T) {
	cases := []struct {
		name       string
		severity   string
		components []string
		want       string
	}{
		{"components and severity", "high", []string{"pkg:golang/openssl", "pkg:golang/x"}, "pkg:golang/openssl pkg:golang/x high"},
		{"components only", "", []string{"pkg:npm/lodash"}, "pkg:npm/lodash"},
		{"severity only", "critical", nil, "critical"},
		{"empty", "", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.SubjectText(tc.severity, tc.components); got != tc.want {
				t.Fatalf("SubjectText(%q, %v) = %q, want %q", tc.severity, tc.components, got, tc.want)
			}
		})
	}
}

// The composition must be identical for the same inputs — population and query rely on it.
func TestSubjectTextIsStable(t *testing.T) {
	a := domain.SubjectText("high", []string{"pkg:golang/openssl"})
	b := domain.SubjectText("high", []string{"pkg:golang/openssl"})
	if a != b {
		t.Fatalf("not stable: %q != %q", a, b)
	}
}
