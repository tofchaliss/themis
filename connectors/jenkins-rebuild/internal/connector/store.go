package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// The stored states of a request (D37).
const (
	StateReceived   = "received"
	StateSubmitting = "submitting"
	StateSubmitted  = "submitted"
	StateRefused    = "refused"
	StateUncertain  = "uncertain"
)

// Record is what the connector keeps per request, under the event id (the intent id).
type Record struct {
	IntentID string `json:"intent_id"`
	State    string `json:"state"`
	// Job and Params are what will be, or was, passed to the build system. Empty for a
	// request that was refused by a check.
	Job    string            `json:"job,omitempty"`
	Params map[string]string `json:"params,omitempty"`
	// The claim of D39: who holds it, how many claims there were, and when it ends.
	ClaimOwner   string    `json:"claim_owner,omitempty"`
	ClaimCounter int       `json:"claim_counter"`
	ClaimUntil   time.Time `json:"claim_until,omitzero"`
	// BuildRef is the identity the build system gave the build (D38 item 5). Reason says why,
	// for refused and uncertain.
	BuildRef string `json:"build_ref,omitempty"`
	Reason   string `json:"reason,omitempty"`
	// Reported is true once Themis answered the status call with success (D37 item 4).
	Reported   bool      `json:"reported"`
	ReceivedAt time.Time `json:"received_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// ended says whether the record is in an end state.
func (r Record) ended() bool {
	return r.State == StateSubmitted || r.State == StateRefused || r.State == StateUncertain
}

// Store is the connector's durable store. Every instance of one connector must use the same
// store (D39 item 2). Each method is one atomic step.
type Store interface {
	// Put stores a new record. When the intent id is already stored, the stored record is
	// returned and nothing changes (D12 item 2).
	Put(rec Record) (stored Record, created bool, err error)
	// Claim is the one conditional write received -> submitting (D39 item 2).
	Claim(intentID, owner string, now time.Time, ttl time.Duration) (Record, bool, error)
	// TakeOver takes a submitting record whose claim ended before notBefore. It allows the
	// question of D37 item 3 only, never a direct call (D39 item 4).
	TakeOver(intentID, owner string, now, notBefore time.Time, ttl time.Duration) (Record, bool, error)
	// Outcome moves submitting to an end state. It names the claim counter, so a worker that
	// lost its claim cannot write (D39 item 3).
	Outcome(intentID string, counter int, state, buildRef, reason string, now time.Time) (bool, error)
	// Release moves submitting back to received, under the same counter rule.
	Release(intentID string, counter int, now time.Time) (bool, error)
	// MarkReported notes that Themis confirmed the report of this end state.
	MarkReported(intentID, state string, now time.Time) error
	// Get reads one record.
	Get(intentID string) (Record, bool, error)
	// List returns every record, oldest first.
	List() ([]Record, error)
	// Prune removes records that ended, were reported, and were last changed before the given
	// time. An event that old is refused by its time (D18 item 5), so its id is not needed any
	// more to recognise a repeat.
	Prune(before time.Time) (removed int, err error)
}

// FileStore keeps one JSON file per request in a directory. A lock file makes each step
// atomic across the processes that share the directory, and a file is replaced by rename, so a
// crash leaves the old or the new record and never half of one.
//
// Limit, stated: the lock is a POSIX file lock. Several instances may share the directory on
// one host, or on a file system whose locks work across hosts. Where that is not given, run
// one instance, or implement Store on a database.
type FileStore struct {
	dir string
}

// OpenFileStore opens (and creates) the store directory.
func OpenFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FileStore{dir: dir}, nil
}

func (s *FileStore) path(intentID string) string {
	sum := sha256.Sum256([]byte(intentID))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:])+".json")
}

// locked runs fn while holding the directory lock.
func (s *FileStore) locked(fn func() error) error {
	f, err := os.OpenFile(filepath.Join(s.dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	return fn()
}

func (s *FileStore) read(intentID string) (Record, bool, error) {
	raw, err := os.ReadFile(s.path(intentID))
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	var rec Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return Record{}, false, err
	}
	return rec, true, nil
}

// write replaces the record's file: temporary file, sync, rename.
func (s *FileStore) write(rec Record) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, "tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path(rec.IntentID))
}

// change reads a record, lets fn change it, and writes it when fn says so.
func (s *FileStore) change(intentID string, fn func(*Record) bool) (Record, bool, error) {
	var (
		out     Record
		changed bool
	)
	err := s.locked(func() error {
		rec, found, err := s.read(intentID)
		if err != nil || !found {
			return err
		}
		if !fn(&rec) {
			out = rec
			return nil
		}
		out, changed = rec, true
		return s.write(rec)
	})
	return out, changed && err == nil, err
}

// Put implements Store.
func (s *FileStore) Put(rec Record) (Record, bool, error) {
	var (
		out     Record
		created bool
	)
	err := s.locked(func() error {
		stored, found, err := s.read(rec.IntentID)
		if err != nil {
			return err
		}
		if found {
			out = stored
			return nil
		}
		out, created = rec, true
		return s.write(rec)
	})
	return out, created && err == nil, err
}

// Claim implements Store.
func (s *FileStore) Claim(intentID, owner string, now time.Time, ttl time.Duration) (Record, bool, error) {
	return s.change(intentID, func(r *Record) bool {
		if r.State != StateReceived {
			return false
		}
		r.State, r.ClaimOwner, r.ClaimUntil, r.UpdatedAt = StateSubmitting, owner, now.Add(ttl), now
		r.ClaimCounter++
		return true
	})
}

// TakeOver implements Store.
func (s *FileStore) TakeOver(intentID, owner string, now, notBefore time.Time, ttl time.Duration) (Record, bool, error) {
	return s.change(intentID, func(r *Record) bool {
		if r.State != StateSubmitting || !r.ClaimUntil.Before(notBefore) {
			return false
		}
		r.ClaimOwner, r.ClaimUntil, r.UpdatedAt = owner, now.Add(ttl), now
		r.ClaimCounter++
		return true
	})
}

// Outcome implements Store.
func (s *FileStore) Outcome(intentID string, counter int, state, buildRef, reason string, now time.Time) (bool, error) {
	_, ok, err := s.change(intentID, func(r *Record) bool {
		if r.State != StateSubmitting || r.ClaimCounter != counter {
			return false
		}
		r.State, r.BuildRef, r.Reason, r.UpdatedAt = state, buildRef, reason, now
		r.ClaimOwner, r.ClaimUntil = "", time.Time{}
		return true
	})
	return ok, err
}

// Release implements Store.
func (s *FileStore) Release(intentID string, counter int, now time.Time) (bool, error) {
	_, ok, err := s.change(intentID, func(r *Record) bool {
		if r.State != StateSubmitting || r.ClaimCounter != counter {
			return false
		}
		r.State, r.ClaimOwner, r.ClaimUntil, r.UpdatedAt = StateReceived, "", time.Time{}, now
		return true
	})
	return ok, err
}

// MarkReported implements Store.
func (s *FileStore) MarkReported(intentID, state string, now time.Time) error {
	_, _, err := s.change(intentID, func(r *Record) bool {
		if r.State != state || r.Reported {
			return false
		}
		r.Reported, r.UpdatedAt = true, now
		return true
	})
	return err
}

// List implements Store.
func (s *FileStore) List() ([]Record, error) {
	var out []Record
	err := s.locked(func() error {
		entries, err := os.ReadDir(s.dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
			if err != nil {
				return err
			}
			var rec Record
			if err := json.Unmarshal(raw, &rec); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ReceivedAt.Equal(out[j].ReceivedAt) {
			return out[i].ReceivedAt.Before(out[j].ReceivedAt)
		}
		return out[i].IntentID < out[j].IntentID
	})
	return out, err
}

// Get implements Store.
func (s *FileStore) Get(intentID string) (Record, bool, error) {
	var (
		rec   Record
		found bool
	)
	err := s.locked(func() error {
		var err error
		rec, found, err = s.read(intentID)
		return err
	})
	return rec, found, err
}

// Prune implements Store.
func (s *FileStore) Prune(before time.Time) (int, error) {
	recs, err := s.List()
	if err != nil {
		return 0, err
	}
	removed := 0
	err = s.locked(func() error {
		for _, rec := range recs {
			if !rec.ended() || !rec.Reported || !rec.UpdatedAt.Before(before) {
				continue
			}
			// Read again under the lock: the record may have changed since the list.
			cur, found, err := s.read(rec.IntentID)
			if err != nil {
				return err
			}
			if !found || !cur.ended() || !cur.Reported || !cur.UpdatedAt.Before(before) {
				continue
			}
			if err := os.Remove(s.path(rec.IntentID)); err != nil {
				return err
			}
			removed++
		}
		return nil
	})
	return removed, err
}
