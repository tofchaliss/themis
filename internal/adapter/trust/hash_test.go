package trust

import (
	"testing"
)

func TestChecksumSHA256(t *testing.T) {
	got := checksumSHA256([]byte("hello"))
	if got != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("checksum = %q", got)
	}
}

func TestCompareChecksum(t *testing.T) {
	computed := checksumSHA256([]byte("payload"))
	if err := compareChecksum(computed, ""); err != nil {
		t.Fatal(err)
	}
	if err := compareChecksum(computed, computed); err != nil {
		t.Fatal(err)
	}
	if err := compareChecksum(computed, "deadbeef"); err == nil {
		t.Fatal("expected mismatch error")
	}
}
