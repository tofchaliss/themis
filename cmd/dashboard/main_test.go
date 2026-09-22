package main

import (
	"bytes"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The Phase-1 boot refusal (EDR-GUI-01, D3 grill amendment): THEMIS_AUTH_REQUIRED=1
// with no authenticated edge wired must refuse to boot — a guard that only runs in
// production is a guard nobody has seen work.
func TestGuardAuth(t *testing.T) {
	if err := guardAuth(config{authRequired: true}); !errors.Is(err, errAuthRequired) {
		t.Errorf("authRequired=true: err = %v, want the boot refusal", err)
	}
	if err := guardAuth(config{authRequired: false}); err != nil {
		t.Errorf("authRequired=false: err = %v, want boot to proceed", err)
	}
}

// The embedded assets must actually resolve — a broken go:embed path fails here, not
// on the first page load of a deployment.
func TestAssetHandlerEmbeds(t *testing.T) {
	if _, err := assetHandler(""); err != nil {
		t.Fatalf("embedded assets: %v", err)
	}
	if _, err := assetHandler(t.TempDir()); err != nil {
		t.Fatalf("override dir: %v", err)
	}
}

// Every no-answer reason the servers can state must have an entry in the page's taxonomy.
//
// The page once knew six of the fifteen and rendered the rest as "the Gateway stated no
// reason" — an assertion, and a false one, because the server had stated a precise reason in
// every case (DEF_GUI_AI_REASON_MAP_INCOMPLETE). AI-204-1 grew the vocabulary on one side of
// the wire and nothing re-derived the consumer on the other, which is CONVENTIONS R5's shape
// applied to an enum. This test is that re-derivation, made automatic: it reads the reason
// constants out of the two servers' source and fails when one has no home on the page.
func TestAIReasonTaxonomyIsCoveredByTheDashboard(t *testing.T) {
	js, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	// The map's own block, so a reason merely MENTIONED in a comment elsewhere does not pass.
	const marker = "const AI_REASONS = {"
	start := bytes.Index(js, []byte(marker))
	if start < 0 {
		t.Fatalf("app.js no longer defines %s — this guard needs re-pointing", marker)
	}
	end := bytes.Index(js[start:], []byte("\n};"))
	if end < 0 {
		t.Fatal("AI_REASONS block is unterminated")
	}
	block := string(js[start : start+end])

	// Reason* constants, read from the source rather than copied — a copy would go stale in
	// exactly the way this test exists to prevent.
	reasonConst := regexp.MustCompile(`Reason[A-Za-z]*\s+=\s+"([a-z_]+)"`)
	for _, src := range []string{
		"../../internal/intelligence/app/gateway.go",
		"../../internal/governance/app/service.go",
	} {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read %s: %v", src, err)
		}
		found := reasonConst.FindAllStringSubmatch(string(b), -1)
		if len(found) == 0 {
			t.Fatalf("%s: no Reason* constants matched — this guard needs re-pointing", src)
		}
		for _, m := range found {
			if !strings.Contains(block, "\n  "+m[1]+": [") {
				t.Errorf("reason %q (%s) has no entry in AI_REASONS — it would render as an "+
					"unrecognised reason instead of an explanation", m[1], src)
			}
		}
	}
}
