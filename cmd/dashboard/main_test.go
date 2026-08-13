package main

import (
	"errors"
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
