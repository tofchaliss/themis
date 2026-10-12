package http

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/themis-project/themis/internal/evidence/adapters/http/gen"
	"github.com/themis-project/themis/internal/evidence/domain"
)

// TestStatusForReason_IsD11sTableAndNothingElse walks the closed taxonomy against the
// table directly, so a reason added without a status fails HERE — at the mapping —
// and not later as a surprising 422 on the wire.
func TestStatusForReason_IsD11sTableAndNothingElse(t *testing.T) {
	for _, reason := range domain.AllRejectReasons() {
		if _, ok := httpStatusFor[reason]; !ok {
			t.Errorf("reason %q has no status; D11's table and the enum must grow together", reason)
		}
	}
	if len(httpStatusFor) != len(domain.AllRejectReasons()) {
		t.Errorf("the table maps %d reasons and the taxonomy has %d", len(httpStatusFor), len(domain.AllRejectReasons()))
	}
}

// TestRejectReasonEnumMatchesTheOpenAPISpec is the spec-versus-Go contract, and it is
// a SET comparison in both directions so it fails when EITHER side grows alone: the
// wire enum and `domain.RejectReason` are the same closed taxonomy, and a value only
// one of them knows is a refusal a consumer cannot switch on (#116).
//
// The spec is read as the file rather than through the generated constants because
// the generated constants cannot be enumerated — only probed — so a value added to
// the spec alone would leave every probe green.
func TestRejectReasonEnumMatchesTheOpenAPISpec(t *testing.T) {
	// internal/evidence/adapters/http -> the repository root.
	path := filepath.Join("..", "..", "..", "..", "api", "evidence.openapi.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var spec struct {
		Components struct {
			Schemas struct {
				RejectReason struct {
					Enum []string `yaml:"enum"`
				} `yaml:"RejectReason"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	inSpec := spec.Components.Schemas.RejectReason.Enum
	if len(inSpec) == 0 {
		t.Fatalf("%s states no RejectReason enum", path)
	}

	spoken := make(map[domain.RejectReason]bool, len(inSpec))
	for _, v := range inSpec {
		spoken[domain.RejectReason(v)] = true
		if !gen.RejectReason(v).Valid() {
			t.Errorf("spec value %q is not in the generated enum — run `make generate-api-evidence`", v)
		}
		if !domain.RejectReason(v).Valid() {
			t.Errorf("spec value %q is not a domain reason; the spec and the Go enum must grow in the same change", v)
		}
	}
	for _, reason := range domain.AllRejectReasons() {
		if !spoken[reason] {
			t.Errorf("reason %q is in the Go enum but not in the API spec; the spec and the Go enum must grow in the same change", reason)
		}
	}
	if len(inSpec) != len(domain.AllRejectReasons()) {
		t.Errorf("the spec states %d reasons and the taxonomy has %d", len(inSpec), len(domain.AllRejectReasons()))
	}
}

// TestStatusForReason_AnUnmappedReasonIs422 — unreachable through the domain, which
// refuses a reason outside the closed taxonomy, and asserted because the alternative
// to a stated fallback is a zero status code. 422 rather than 500: the document was
// understood and declined, and an unmapped reason is a contract gap on our side.
func TestStatusForReason_AnUnmappedReasonIs422(t *testing.T) {
	if got := statusForReason(domain.RejectReason("invented")); got != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422", got)
	}
}
