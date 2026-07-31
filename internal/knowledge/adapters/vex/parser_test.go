package vex_test

import (
	"testing"

	"github.com/themis-project/themis/internal/knowledge/adapters/vex"
)

func TestParseOpenVEX(t *testing.T) {
	raw := []byte(`{"statements":[
		{"vulnerability":{"name":"CVE-2024-1"},"products":[{"@id":"pkg:pypi/urllib3@1.0"},{"@id":"pkg:pypi/other"}],"status":"not_affected","justification":"vulnerable_code_not_present"},
		{"vulnerability":"CVE-2024-2","products":[{"@id":"pkg:deb/openssl"}],"status":"affected"},
		{"vulnerability":{"name":"CVE-2024-3"},"products":[{"@id":"pkg:x"}],"status":""},
		{"vulnerability":{"name":""},"products":[{"@id":"pkg:y"}],"status":"fixed"},
		{"vulnerability":{"name":"CVE-2024-4"},"products":[{"@id":""}],"status":"fixed"},
		{"products":[{"@id":"pkg:z"}],"status":"fixed"}
	]}`)
	stmts, err := vex.ParseOpenVEX(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Statement 1 → two (two products, object vuln); statement 2 → one (bare-string vuln); the
	// rest are skipped (empty status / empty name / empty product / no vulnerability).
	if len(stmts) != 3 {
		t.Fatalf("got %d statements, want 3: %+v", len(stmts), stmts)
	}
	if stmts[0].CVE != "CVE-2024-1" || stmts[0].Package != "pkg:pypi/urllib3@1.0" ||
		stmts[0].Status != "not_affected" || stmts[0].Justification != "vulnerable_code_not_present" {
		t.Errorf("stmt[0] = %+v", stmts[0])
	}
	if stmts[1].Package != "pkg:pypi/other" {
		t.Errorf("stmt[1] = %+v (second product of statement 1)", stmts[1])
	}
	if stmts[2].CVE != "CVE-2024-2" || stmts[2].Package != "pkg:deb/openssl" {
		t.Errorf("stmt[2] = %+v (bare-string vulnerability)", stmts[2])
	}
}

func TestParseOpenVEX_InvalidJSON(t *testing.T) {
	if _, err := vex.ParseOpenVEX([]byte(`{not json`)); err == nil {
		t.Error("invalid OpenVEX json must error")
	}
}
