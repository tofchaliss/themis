package trust

import (
	"context"
	"fmt"
	"sync"

	"github.com/themis-project/themis/internal/domain"
)

// MemoryRepository is an in-memory TrustRepository for unit tests.
type MemoryRepository struct {
	mu sync.RWMutex

	sboms         map[string]string
	vex           map[string]string
	images        map[string]struct{}
	sbomChecksums map[string]struct{}
}

// NewMemoryRepository creates an empty in-memory trust repository.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		sboms:         make(map[string]string),
		vex:           make(map[string]string),
		images:        make(map[string]struct{}),
		sbomChecksums: make(map[string]struct{}),
	}
}

func sbomKey(imageDigest, checksum string) string {
	return imageDigest + "|" + checksum
}

func vexKey(sbomChecksum, checksum string) string {
	return sbomChecksum + "|" + checksum
}

// SeedImage registers an image digest for integrity chain tests.
func (r *MemoryRepository) SeedImage(digest string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.images[digest] = struct{}{}
}

// SeedSBOM registers an SBOM dedup record and checksum for VEX chain tests.
func (r *MemoryRepository) SeedSBOM(documentID, imageDigest, checksum string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sboms[sbomKey(imageDigest, checksum)] = documentID
	r.images[imageDigest] = struct{}{}
	r.sbomChecksums[checksum] = struct{}{}
}

// SeedVEX registers a VEX dedup record.
func (r *MemoryRepository) SeedVEX(documentID, sbomChecksum, checksum string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.vex[vexKey(sbomChecksum, checksum)] = documentID
}

func (r *MemoryRepository) FindSBOMByDedupKey(_ context.Context, imageDigest, checksumSHA256 string) (string, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.sboms[sbomKey(imageDigest, checksumSHA256)]
	return id, ok, nil
}

func (r *MemoryRepository) FindVEXByDedupKey(_ context.Context, sbomChecksum, checksumSHA256 string) (string, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.vex[vexKey(sbomChecksum, checksumSHA256)]
	return id, ok, nil
}

func (r *MemoryRepository) ImageDigestExists(_ context.Context, digest string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.images[digest]
	return ok, nil
}

func (r *MemoryRepository) SBOMChecksumExists(_ context.Context, checksum string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.sbomChecksums[checksum]
	return ok, nil
}

// MemoryAuditRecorder stores audit entries in memory for unit tests.
type MemoryAuditRecorder struct {
	mu      sync.Mutex
	Entries []domain.AuditEntry
}

// NewMemoryAuditRecorder creates an empty audit recorder.
func NewMemoryAuditRecorder() *MemoryAuditRecorder {
	return &MemoryAuditRecorder{}
}

func (a *MemoryAuditRecorder) Record(_ context.Context, entry domain.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Entries = append(a.Entries, entry)
	return nil
}

func (a *MemoryAuditRecorder) Count(action string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	count := 0
	for _, entry := range a.Entries {
		if entry.Action == action {
			count++
		}
	}
	return count
}

// ErrRepository is returned by failing test repositories.
var ErrRepository = fmt.Errorf("repository failure")

type failingRepository struct{}

func (failingRepository) FindSBOMByDedupKey(context.Context, string, string) (string, bool, error) {
	return "", false, ErrRepository
}
func (failingRepository) FindVEXByDedupKey(context.Context, string, string) (string, bool, error) {
	return "", false, ErrRepository
}
func (failingRepository) ImageDigestExists(context.Context, string) (bool, error) {
	return false, ErrRepository
}
func (failingRepository) SBOMChecksumExists(context.Context, string) (bool, error) {
	return false, ErrRepository
}
