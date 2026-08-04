package store

import (
	"math"
	"testing"
)

func TestEncodeDecodeRoundTripIsExact(t *testing.T) {
	in := []float32{0, 1, -1, 0.5, -0.25, 3.1415927, math.MaxFloat32, math.SmallestNonzeroFloat32}
	out, err := decodeVector(encodeVector(in))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("length: got %d want %d", len(out), len(in))
	}
	for i := range in {
		if out[i] != in[i] {
			t.Errorf("element %d: got %v want %v", i, out[i], in[i])
		}
	}
}

func TestEncodeDecodeEmpty(t *testing.T) {
	out, err := decodeVector(encodeVector(nil))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty, got %d elements", len(out))
	}
}

func TestDecodeRejectsCorruptLength(t *testing.T) {
	if _, err := decodeVector([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for a byte length that is not a multiple of 4")
	}
}
