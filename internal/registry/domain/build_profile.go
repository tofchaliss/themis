package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The build profile (EDR-REBUILD-01 D10, D16; step R2a): a JSON block that tells a build
// system how to build the image of a Release, stored per Project, with an optional one per
// Release that replaces the Project's AS A WHOLE (a merged profile is one nobody wrote).
//
// Themis does not read inside it. It checks only what keeps it safe to show and to send: it
// must be a JSON object, it is bounded in size and depth, and no key may be named like a
// secret. Profiles are recorded, never edited: every change is a new record with an actor and
// its own revision number, a removal is a record too, and the current value of a level is its
// latest record.

// Bounds of one profile (D10 item 4).
const (
	MaxBuildProfileBytes = 16 * 1024
	MaxBuildProfileDepth = 5
)

// ErrInvalidBuildProfile is returned for a profile that is not a JSON object, is too large or
// too deep, carries a key named like a secret, or for a record without an actor.
var ErrInvalidBuildProfile = errors.New("registry: invalid build profile")

// BuildProfileLevel is where a profile is stored: a Project or a Release.
type BuildProfileLevel = TagEntity

// secretKeyMarks are the names a key may not carry (D10 item 3). The check is a guard against
// a mistake, not proof that a profile holds no secret: a value is never inspected.
var secretKeyMarks = []string{"password", "token", "secret", "apikey", "credential"}

// secretLikeKey reports whether key is named like a secret: any case, with `_` and `-` ignored
// so that api_key, api-key and apiKey read alike.
func secretLikeKey(key string) bool {
	k := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(key))
	for _, mark := range secretKeyMarks {
		if strings.Contains(k, mark) {
			return true
		}
	}
	return false
}

// checkBuildProfileValue walks one decoded JSON value. depth is the nesting level of v, the
// top object being 1.
func checkBuildProfileValue(v any, depth int) error {
	var children []any
	switch t := v.(type) {
	case map[string]any:
		for key, child := range t {
			if secretLikeKey(key) {
				return fmt.Errorf("%w: the key %q is named like a secret; credentials stay on the build side", ErrInvalidBuildProfile, key)
			}
			children = append(children, child)
		}
	case []any:
		children = t
	default:
		return nil
	}
	if depth > MaxBuildProfileDepth {
		return fmt.Errorf("%w: nested deeper than %d levels", ErrInvalidBuildProfile, MaxBuildProfileDepth)
	}
	for _, child := range children {
		if err := checkBuildProfileValue(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// NormalizeBuildProfile checks a profile and returns it in compact form, which is what is
// stored, served, sent and hashed. Key order is kept as written.
func NormalizeBuildProfile(raw []byte) ([]byte, error) {
	if len(raw) > MaxBuildProfileBytes {
		return nil, fmt.Errorf("%w: %d bytes, at most %d", ErrInvalidBuildProfile, len(raw), MaxBuildProfileBytes)
	}
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil || top == nil {
		return nil, fmt.Errorf("%w: it must be a JSON object", ErrInvalidBuildProfile)
	}
	if err := checkBuildProfileValue(top, 1); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	_ = json.Compact(&out, raw) // raw was just decoded, so it compacts
	return out.Bytes(), nil
}

// BuildProfileRecord is one recorded change of one level's profile. Immutable.
type BuildProfileRecord struct {
	Level    BuildProfileLevel
	EntityID string
	// Revision counts the changes of this entity's profile from 1. The store assigns it.
	Revision int
	// Profile is the compact JSON object; nil on a removal.
	Profile []byte
	// Removed marks the record that took the profile away. The level then states none.
	Removed bool
	Actor   string
	// Via is the name of the API key that made the change, when auth is on.
	Via string
	At  time.Time
}

// SHA256 is the hex digest of the stored bytes (D16), "" for a removal.
func (r BuildProfileRecord) SHA256() string {
	if r.Removed {
		return ""
	}
	sum := sha256.Sum256(r.Profile)
	return hex.EncodeToString(sum[:])
}

func newBuildProfileRecord(level BuildProfileLevel, id, actor, via string, at time.Time) (BuildProfileRecord, error) {
	switch {
	case level != TagProject && level != TagRelease:
		return BuildProfileRecord{}, fmt.Errorf("%w: a profile belongs to a project or a release, not %q", ErrInvalidBuildProfile, level)
	case strings.TrimSpace(id) == "":
		return BuildProfileRecord{}, fmt.Errorf("%w: empty entity id", ErrInvalidBuildProfile)
	case strings.TrimSpace(actor) == "":
		return BuildProfileRecord{}, fmt.Errorf("%w: an actor is required", ErrInvalidBuildProfile)
	}
	return BuildProfileRecord{
		Level: level, EntityID: id, Actor: strings.TrimSpace(actor), Via: strings.TrimSpace(via), At: at.UTC(),
	}, nil
}

// NewBuildProfileRecord validates and builds the record of a new profile value.
func NewBuildProfileRecord(level BuildProfileLevel, id string, raw []byte, actor, via string, at time.Time) (BuildProfileRecord, error) {
	rec, err := newBuildProfileRecord(level, id, actor, via, at)
	if err != nil {
		return BuildProfileRecord{}, err
	}
	if rec.Profile, err = NormalizeBuildProfile(raw); err != nil {
		return BuildProfileRecord{}, err
	}
	return rec, nil
}

// NewBuildProfileRemoval builds the record that takes a level's profile away.
func NewBuildProfileRemoval(level BuildProfileLevel, id, actor, via string, at time.Time) (BuildProfileRecord, error) {
	rec, err := newBuildProfileRecord(level, id, actor, via, at)
	if err != nil {
		return BuildProfileRecord{}, err
	}
	rec.Removed = true
	return rec, nil
}

// ResolveBuildProfile picks the profile that applies to a Release: its own when it has one,
// else its Project's. A nil or removed record states none. found is false when neither does.
func ResolveBuildProfile(release, project *BuildProfileRecord) (rec BuildProfileRecord, found bool) {
	for _, r := range []*BuildProfileRecord{release, project} {
		if r != nil && !r.Removed {
			return *r, true
		}
	}
	return BuildProfileRecord{}, false
}
