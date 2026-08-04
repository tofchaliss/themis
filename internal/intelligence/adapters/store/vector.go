package store

import (
	"encoding/binary"
	"errors"
	"math"
)

// encodeVector serializes a float32 slice little-endian into the BYTEA column (dim*4 bytes).
// The round-trip is exact — float32 bits are preserved, so a persisted vector is identical to
// the one embedded.
func encodeVector(v []float32) []byte {
	b := make([]byte, len(v)*4)
	for i, f := range v {
		binary.LittleEndian.PutUint32(b[i*4:], math.Float32bits(f))
	}
	return b
}

// decodeVector is encodeVector's inverse. It rejects a payload whose length is not a whole
// number of float32s — a corrupt or truncated column, surfaced as an error rather than a
// silently mangled vector.
func decodeVector(b []byte) ([]float32, error) {
	if len(b)%4 != 0 {
		return nil, errors.New("corrupt embedding vector: byte length not a multiple of 4")
	}
	v := make([]float32, len(b)/4)
	for i := range v {
		v[i] = math.Float32frombits(binary.LittleEndian.Uint32(b[i*4:]))
	}
	return v, nil
}
