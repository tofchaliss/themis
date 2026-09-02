package serializer

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/domain"
)

func rollupFixture(t *testing.T) domain.RollupArtifact {
	t.Helper()
	art, err := domain.MaterializeRollup(
		domain.RollupProductRef{Product: "MRF", Project: "cdmrf-oamp", Version: "20.1.0.0-118", ReleaseID: "rel-1"},
		time.Date(2026, 9, 2, 16, 0, 0, 0, time.UTC),
		[]domain.RollupEntry{
			{FindingID: "f1", CVE: "CVE-2020-1747", HasPosition: true,
				Stance: domain.StanceNotAffected, PositionVersion: 2, Rationale: "not reachable"},
			{FindingID: "f2", CVE: "CVE-2025-47273",
				OpenComponents: []string{"pkg:pypi/setuptools@70.3.0"},
				Annotations:    []string{"setuptools@39.2.0 cleared: vendor fix present"}},
		}, 3)
	if err != nil {
		t.Fatal(err)
	}
	return art
}

// The D13 document in OpenVEX form: one statement per finding, product identified by the
// Registry-derived purl, open components as subcomponents, clearances as bracketed notes
// (never the status), the vintage inline, and a not_affected statement carrying the
// spec-required justification.
func TestOpenVEXRollup(t *testing.T) {
	art := rollupFixture(t)
	raw, err := Default().RenderRollup("openvex", art)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	stmts := doc["statements"].([]any)
	if len(stmts) != 2 {
		t.Fatalf("statements = %d, want 2", len(stmts))
	}
	body := string(raw)
	for _, want := range []string{
		`"pkg:generic/MRF/cdmrf-oamp@20.1.0.0-118"`, // the product line a consumer can match (D13.4)
		`"not_affected"`, `"vulnerable_code_not_in_execute_path"`, // the decided statement + justification
		`"under_investigation"`,                        // the honest undecided status (D13.1)
		`[note: setuptools@39.2.0 cleared`,             // the clearance as annotation, bracketed
		`"pkg:pypi/setuptools@70.3.0"`,                 // the OPEN copy as subcomponent
		`"timestamp": "2026-09-02T16:00:00Z"`,          // the vintage inline (D13.2)
		`"release_ref": "rel-1"`, `"findings_covered": 2`, `"withdrawn_cves_excluded": 3`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("document missing %s\n%s", want, body)
		}
	}
	// Deterministic bytes: same artifact, same output.
	raw2, _ := Default().RenderRollup("openvex", art)
	if string(raw) != string(raw2) {
		t.Error("rollup render must be deterministic")
	}
}

// D13.5: an unsupported rollup format is a CLEAR error, never a half-document — and an
// unknown format stays the registry's ordinary unknown-format error.
func TestRollupFormatErrors(t *testing.T) {
	art := rollupFixture(t)
	if _, err := Default().RenderRollup("csaf", art); !errors.Is(err, ErrRollupUnsupported) {
		t.Errorf("csaf rollup err = %v, want ErrRollupUnsupported (COMM-VEX-1b)", err)
	}
	if _, err := Default().RenderRollup("nope", art); !errors.Is(err, ErrUnknownFormat) {
		t.Errorf("unknown format err = %v, want ErrUnknownFormat", err)
	}
}
