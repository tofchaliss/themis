package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestNormalizeCVEID(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"CVE-2024-0001", "CVE-2024-0001"},
		{"cve-2024-0001", "CVE-2024-0001"},
		{"ALPINE-CVE-2024-0001", "CVE-2024-0001"},
		{"alpine-cve-2024-0001", "CVE-2024-0001"},
		{"GHSA-xxxx-yyyy-zzzz", "GHSA-xxxx-yyyy-zzzz"},
		{"ALPINE-NOT-CVE", "ALPINE-NOT-CVE"},
		{"", ""},
		{"  CVE-2023-12345  ", "CVE-2023-12345"},
	}
	for _, tc := range tests {
		if got := domain.NormalizeCVEID(tc.in); got != tc.want {
			t.Errorf("NormalizeCVEID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"high", "high"},
		{"CRITICAL", "CRITICAL"}, // case preserved; read queries LOWER() it
		{"", "unknown"},
		{"   ", "unknown"},
		{"  medium  ", "medium"},
		{"unknown", "unknown"},
	}
	for _, tc := range tests {
		if got := domain.NormalizeSeverity(tc.in); got != tc.want {
			t.Errorf("NormalizeSeverity(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
