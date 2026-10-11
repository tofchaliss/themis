package report

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// updateGoldens regenerates `testdata/**/*.golden.json` FROM THE ORACLES — the
// maintained Python script and the browser translator — never from this package's
// own output. A golden produced by the code under test proves nothing; a golden
// produced by the implementation being replaced is the acceptance oracle (D4).
//
//	go test ./internal/evidence/adapters/report/ -run TestUpdateGoldens -update-goldens
var updateGoldens = flag.Bool("update-goldens", false,
	"regenerate testdata goldens by running the Cortex script and the browser Trivy translator")

func TestUpdateGoldens(t *testing.T) {
	if !*updateGoldens {
		t.Skip("pass -update-goldens to regenerate the oracle outputs")
	}
	for _, fx := range cortexFixtures {
		oracle, ok := runCortexScript(t, fx.file, fx.effective)
		if !ok {
			t.Fatalf("cannot regenerate %s: the Cortex oracle is unavailable", fx.file)
		}
		writeGolden(t, "cortex", fx.file+".golden.json", oracle)
	}
	for _, fx := range trivyFixtures {
		oracle, ok := runTrivyTranslator(t, fx.file)
		if !ok {
			t.Fatalf("cannot regenerate %s: node is unavailable", fx.file)
		}
		writeGolden(t, "trivy", goldenName(fx.file), oracle)
	}
}

func writeGolden(t *testing.T, dir, name string, content []byte) {
	t.Helper()
	path := filepath.Join("testdata", dir, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	t.Logf("wrote %s (%d bytes)", path, len(content))
}
