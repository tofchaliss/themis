// Package id provides the shared identity and time primitives for Themis contexts:
// opaque aggregate identifiers and an injectable clock. These are base primitives
// admitted to the kernel (EDR-KERNEL-01 D3) — universal, stable, owned by no context.
// Unlike internal/kernel/value (standard-library only), this package may depend on
// google/uuid.
package id

import (
	"time"

	"github.com/google/uuid"
)

// New returns a new random, opaque identifier (a UUID v4 string). Aggregates use it
// for their own stable identity (DOM-0027); the value is opaque — callers must not
// parse meaning from it.
func New() string { return uuid.NewString() }

// Clock supplies the current time. Injecting it keeps time-dependent logic testable.
type Clock interface {
	Now() time.Time
}

// SystemClock is the real-time Clock.
type SystemClock struct{}

// Now returns the current time in UTC.
func (SystemClock) Now() time.Time { return time.Now().UTC() }
