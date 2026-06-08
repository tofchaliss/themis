package trust

import (
	"bytes"
	"testing"

	"pgregory.net/rapid"

	"github.com/themis-project/themis/internal/testutil/gen"
)

func TestChecksumDeterminismProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		data := rapid.SliceOfN(rapid.Byte(), 0, 512).Draw(t, "data")
		a := checksumSHA256(data)
		b := checksumSHA256(append([]byte(nil), data...))
		if a != b {
			t.Fatalf("checksum not deterministic: %q vs %q", a, b)
		}
		if len(a) != 64 {
			t.Fatalf("checksum length = %d want 64", len(a))
		}
	})
}

func TestCompareChecksumProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		data := rapid.SliceOfN(rapid.Byte(), 0, 512).Draw(t, "data")
		sum := checksumSHA256(data)

		if err := compareChecksum(sum, ""); err != nil {
			t.Fatalf("empty expected should pass: %v", err)
		}
		if err := compareChecksum(sum, sum); err != nil {
			t.Fatalf("identical checksum should match: %v", err)
		}
		// Case-insensitive comparison.
		if err := compareChecksum(sum, gen.RandomCase(t, sum)); err != nil {
			t.Fatalf("case-mixed checksum should match: %v", err)
		}

		other := rapid.SliceOfN(rapid.Byte(), 0, 512).Draw(t, "other")
		if !bytes.Equal(data, other) {
			if err := compareChecksum(sum, checksumSHA256(other)); err == nil {
				t.Fatalf("different data should mismatch")
			}
		}
	})
}

// dedupKey models the Phase 1 dedup tuples: SBOM (image_digest, checksum) and
// VEX (sbom_checksum, checksum). Both reduce to a stable content hash paired with
// a scope identifier.
type dedupKey struct {
	scope    string
	checksum string
}

func TestDedupKeyStabilityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		scope := rapid.StringN(0, 32, -1).Draw(t, "scope")
		raw := rapid.SliceOfN(rapid.Byte(), 0, 512).Draw(t, "raw")

		key := func(scope string, b []byte) dedupKey {
			return dedupKey{scope: scope, checksum: checksumSHA256(b)}
		}

		// Byte-identical re-ingest under the same scope is idempotent.
		if key(scope, raw) != key(scope, append([]byte(nil), raw...)) {
			t.Fatalf("dedup key not stable for identical input")
		}

		other := rapid.SliceOfN(rapid.Byte(), 0, 512).Draw(t, "other")
		if !bytes.Equal(raw, other) && key(scope, raw) == key(scope, other) {
			t.Fatalf("distinct payloads collided under same scope")
		}

		otherScope := scope + "x"
		if key(scope, raw) == key(otherScope, raw) {
			t.Fatalf("same payload under distinct scope must differ")
		}
	})
}
