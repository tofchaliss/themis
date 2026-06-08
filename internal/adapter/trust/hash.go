package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func checksumSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func compareChecksum(computed, expected string) error {
	if expected == "" {
		return nil
	}
	if !strings.EqualFold(computed, expected) {
		return fmt.Errorf("checksum mismatch")
	}
	return nil
}
