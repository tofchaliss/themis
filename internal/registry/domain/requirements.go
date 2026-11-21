package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Security requirements (EDR-SCORING-01 4.4, S3): the CVSS Confidentiality, Integrity and
// Availability Requirements (CR, IR, AR) a Product, Project or Release sets for its components.
// Each metric resolves on its own: Release, then Project, then Product, then X (not defined).
// X at a level means "this level states nothing", so the metric falls through to the next one.
// A component exception (above Release) needs the GUI permissions of S6 and is not built here.
// Requirements are recorded, never edited: every change is a new record with a reason and an
// actor, and the current value of a level is its latest record.

// Requirement is one CVSS requirement value.
type Requirement string

// The four values of the CVSS 3.x specification.
const (
	RequirementHigh       Requirement = "H"
	RequirementMedium     Requirement = "M"
	RequirementLow        Requirement = "L"
	RequirementNotDefined Requirement = "X"
)

// ErrInvalidRequirement is returned for a value outside H / M / L / X, or a record without a
// reason or an actor.
var ErrInvalidRequirement = errors.New("registry: invalid security requirement")

// ParseRequirement reads one value; empty reads X.
func ParseRequirement(s string) (Requirement, error) {
	switch v := Requirement(strings.ToUpper(strings.TrimSpace(s))); v {
	case "":
		return RequirementNotDefined, nil
	case RequirementHigh, RequirementMedium, RequirementLow, RequirementNotDefined:
		return v, nil
	default:
		return "", fmt.Errorf("%w: %q (one of H, M, L, X)", ErrInvalidRequirement, s)
	}
}

// Requirements are the three values one level states.
type Requirements struct {
	CR, IR, AR Requirement
}

// RequirementLevel is where a requirement is set. It reuses the tag entity kinds.
type RequirementLevel = TagEntity

// LevelDefault is the level a metric reports when no level states it (it then reads X).
const LevelDefault RequirementLevel = "default"

// RequirementRecord is one recorded change at one level. Immutable.
type RequirementRecord struct {
	Level        RequirementLevel
	EntityID     string
	Requirements Requirements
	Reason       string
	Actor        string
	// Via is the name of the API key that made the change, when auth is on.
	Via string
	At  time.Time
}

// NewRequirementRecord validates and builds a record. The reason and the actor are required:
// a change of requirements changes scores, and it is never silent (R-E5).
func NewRequirementRecord(level RequirementLevel, id string, cr, ir, ar, reason, actor, via string, at time.Time) (RequirementRecord, error) {
	switch level {
	case TagProduct, TagProject, TagRelease:
	default:
		return RequirementRecord{}, fmt.Errorf("%w: unknown level %q", ErrInvalidRequirement, level)
	}
	var reqs Requirements
	for _, f := range []struct {
		dst *Requirement
		raw string
	}{{&reqs.CR, cr}, {&reqs.IR, ir}, {&reqs.AR, ar}} {
		v, err := ParseRequirement(f.raw)
		if err != nil {
			return RequirementRecord{}, err
		}
		*f.dst = v
	}
	switch {
	case strings.TrimSpace(id) == "":
		return RequirementRecord{}, fmt.Errorf("%w: empty entity id", ErrInvalidRequirement)
	case strings.TrimSpace(reason) == "":
		return RequirementRecord{}, fmt.Errorf("%w: a reason is required", ErrInvalidRequirement)
	case strings.TrimSpace(actor) == "":
		return RequirementRecord{}, fmt.Errorf("%w: an actor is required", ErrInvalidRequirement)
	}
	return RequirementRecord{
		Level: level, EntityID: id, Requirements: reqs, Reason: strings.TrimSpace(reason),
		Actor: strings.TrimSpace(actor), Via: strings.TrimSpace(via), At: at.UTC(),
	}, nil
}

// ResolvedRequirement is one metric's value and the level it came from.
type ResolvedRequirement struct {
	Value Requirement
	Level RequirementLevel
}

// ResolvedRequirements are the three metrics, each resolved on its own.
type ResolvedRequirements struct {
	CR, IR, AR ResolvedRequirement
}

// ResolveRequirements resolves CR, IR and AR for a Release from the current record of each
// level (nil when a level has none): Release, then Project, then Product, then X.
func ResolveRequirements(release, project, product *RequirementRecord) ResolvedRequirements {
	levels := []*RequirementRecord{release, project, product}
	pick := func(get func(Requirements) Requirement) ResolvedRequirement {
		for _, l := range levels {
			if l == nil {
				continue
			}
			if v := get(l.Requirements); v != RequirementNotDefined && v != "" {
				return ResolvedRequirement{Value: v, Level: l.Level}
			}
		}
		return ResolvedRequirement{Value: RequirementNotDefined, Level: LevelDefault}
	}
	return ResolvedRequirements{
		CR: pick(func(r Requirements) Requirement { return r.CR }),
		IR: pick(func(r Requirements) Requirement { return r.IR }),
		AR: pick(func(r Requirements) Requirement { return r.AR }),
	}
}
