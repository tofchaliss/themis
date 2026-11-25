package domain

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
)

// Owner-set severity (EDR-SCORING-01 section 7.1, OS1-OS2). A named person decides the severity
// that counts for one Finding. They give a reason and either a level or a changed CVSS vector;
// Themis computes the score either way. The original score is never changed: the owner-set
// score sits beside it and is what priority and the remediation deadline read while it stands.

// SeverityLevel is one of the five CVSS severity levels.
type SeverityLevel string

// The levels, with the CVSS score bands they stand for.
const (
	SeverityNone     SeverityLevel = "none"     // 0.0
	SeverityLow      SeverityLevel = "low"      // 0.1 - 3.9
	SeverityMedium   SeverityLevel = "medium"   // 4.0 - 6.9
	SeverityHigh     SeverityLevel = "high"     // 7.0 - 8.9
	SeverityCritical SeverityLevel = "critical" // 9.0 - 10.0
)

// The two ways an owner-set severity is given (OS1).
const (
	OwnerSeverityByLevel  = "level"
	OwnerSeverityByVector = "vector"
)

var (
	// ErrOwnerSeverityLevel is returned for a level outside the five CVSS levels.
	ErrOwnerSeverityLevel = errors.New("governance: severity level must be none, low, medium, high or critical")
	// ErrOwnerSeverityVector is returned for a vector the calculator cannot score.
	ErrOwnerSeverityVector = errors.New("governance: owner-set severity needs a valid CVSS 3.0 or 3.1 vector")
	// ErrOwnerSeverityReason is returned when no reason is given: the reason is the record.
	ErrOwnerSeverityReason = errors.New("governance: owner-set severity needs a reason")
	// ErrOwnerSeverityActor is returned when the actor is not a named person.
	ErrOwnerSeverityActor = errors.New("governance: only a named person sets a severity")
	// ErrOwnerSeverityInput is returned when both or neither of level and vector are given.
	ErrOwnerSeverityInput = errors.New("governance: give a severity level or a CVSS vector, not both")
)

// ParseSeverityLevel reads a level, in any letter case.
func ParseSeverityLevel(s string) (SeverityLevel, error) {
	switch l := SeverityLevel(strings.ToLower(strings.TrimSpace(s))); l {
	case SeverityNone, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return l, nil
	}
	return "", ErrOwnerSeverityLevel
}

// Band returns the lowest and highest score of the level.
func (l SeverityLevel) Band() (low, high float64) {
	switch l {
	case SeverityLow:
		return 0.1, 3.9
	case SeverityMedium:
		return 4.0, 6.9
	case SeverityHigh:
		return 7.0, 8.9
	case SeverityCritical:
		return 9.0, 10.0
	}
	return 0, 0
}

// ScoreForLevel is the level rule of OS1: the original score moved into the picked band by the
// shortest way. A score above the band becomes the top of the band, a score below it becomes
// the bottom, a score already inside stays. With no original score there is nothing to move, so
// the result is the bottom of the band.
func ScoreForLevel(level SeverityLevel, original *float64) float64 {
	low, high := level.Band()
	if original == nil || *original < low {
		return low
	}
	if *original > high {
		return high
	}
	return *original
}

// OwnerSeverity is one owner-set severity on one Finding.
type OwnerSeverity struct {
	// Kind is how it was given: OwnerSeverityByLevel or OwnerSeverityByVector.
	Kind string
	// Level is the picked level, or the band of the computed score for a vector.
	Level SeverityLevel
	// Vector is the changed vector, normalized; empty for a level, which is never shown with a
	// vector it was not computed from.
	Vector string
	// Score is what Themis computed (0.0 - 10.0, one decimal).
	Score float64
	// OriginalScore is the original score when this was set; nil when there was none.
	OriginalScore *float64
	Reason        string
	Actor         Actor
	SetAt         time.Time
	// PickedFrom is the Finding whose form this was set on, when it reached this Finding through
	// the pick list (OS3) or with a copied decision (OS5); empty on that Finding itself.
	PickedFrom FindingID
	// OriginalVector is the vector Themis had selected for the original when this was set.
	OriginalVector string
	// Kept is the last time a person looked at a changed original and kept this severity (OS6);
	// nil when nobody has.
	Kept *SeverityKept
}

// SeverityKept records that a named person kept an owner-set severity after the original
// changed: who, when, and the original they saw.
type SeverityKept struct {
	At     time.Time
	By     string
	Score  *float64
	Vector string
}

// Baseline is the original this severity was last judged against: what the person saw when
// they set it, or when they last kept it.
func (o OwnerSeverity) Baseline() (score *float64, vector string) {
	if o.Kept != nil {
		return o.Kept.Score, o.Kept.Vector
	}
	return o.OriginalScore, o.OriginalVector
}

// ReviewReason says what changed in the original since the baseline (OS6), in words a person
// reads; empty when nothing changed. A change never alters the owner-set severity: it only
// asks a person to look again.
func (o OwnerSeverity) ReviewReason(score *float64, vector string) string {
	was, wasVector := o.Baseline()
	switch {
	case was == nil && score != nil:
		return fmt.Sprintf("there was no original score, now it is %.1f", *score)
	case was != nil && score == nil:
		return fmt.Sprintf("the original score was %.1f, now there is none", *was)
	case was != nil && *was != *score:
		return fmt.Sprintf("the original score changed from %.1f to %.1f", *was, *score)
	case wasVector != vector:
		return "the original CVSS vector changed"
	}
	return ""
}

// ComputeOwnerScore computes what an owner-set severity would be from exactly one of a level or
// a vector, without recording anything (the preview and the save share it). The result carries
// the kind, the level, the normalized vector and the score.
func ComputeOwnerScore(level, vector string, original *float64) (OwnerSeverity, error) {
	level, vector = strings.TrimSpace(level), strings.TrimSpace(vector)
	if (level == "") == (vector == "") {
		return OwnerSeverity{}, ErrOwnerSeverityInput
	}
	var out OwnerSeverity
	if original != nil {
		o := *original
		out.OriginalScore = &o
	}
	if level != "" {
		l, err := ParseSeverityLevel(level)
		if err != nil {
			return OwnerSeverity{}, err
		}
		out.Kind, out.Level, out.Score = OwnerSeverityByLevel, l, ScoreForLevel(l, original)
		return out, nil
	}
	v, err := value.ParseCVSS3(vector)
	if err != nil {
		return OwnerSeverity{}, fmt.Errorf("%w: %v", ErrOwnerSeverityVector, err)
	}
	out.Kind, out.Vector, out.Score = OwnerSeverityByVector, v.String(), v.Scores().Environmental
	out.Level = SeverityLevel(ScoreBand(out.Score))
	return out, nil
}

// NewOwnerSeverity builds an owner-set severity: the computed score with the reason, the person
// and the time. The reason is required and the actor must be a named person.
func NewOwnerSeverity(level, vector string, original *float64, reason string, actor Actor, now time.Time) (OwnerSeverity, error) {
	out, err := ComputeOwnerScore(level, vector, original)
	if err != nil {
		return OwnerSeverity{}, err
	}
	if reason = strings.TrimSpace(reason); reason == "" {
		return OwnerSeverity{}, ErrOwnerSeverityReason
	}
	if actor.Kind != ActorHuman || strings.TrimSpace(actor.ID) == "" {
		return OwnerSeverity{}, ErrOwnerSeverityActor
	}
	if now.IsZero() {
		return OwnerSeverity{}, errZeroTime
	}
	out.Reason, out.Actor, out.SetAt = reason, actor, now.UTC()
	return out, nil
}

// BaseScore is the owner-set score on the 0-100 scale priority and the deadline read. The
// severity floors of that scale (90 / 70 / 40) are the CVSS bands times ten, so the level the
// owner sees is the bucket the deadline uses.
func (o OwnerSeverity) BaseScore() int { return int(math.Round(o.Score * 10)) }

// SLABucket is the deadline bucket of the owner-set score; empty for None (no deadline).
func (o OwnerSeverity) SLABucket() string { return SLABucketOf(o.BaseScore()) }

// For returns the same severity as it is recorded on another Finding, picked from this one's
// form (OS3) or reached by a copied decision (OS5): same level or vector, same reason and person. A level is computed again from
// that Finding's own original score; a vector's score does not depend on it.
func (o OwnerSeverity) For(source FindingID, original *float64) OwnerSeverity {
	out := o
	out.PickedFrom, out.OriginalScore, out.OriginalVector, out.Kept = source, nil, "", nil
	if original != nil {
		v := *original
		out.OriginalScore = &v
	}
	if o.Kind == OwnerSeverityByLevel {
		out.Score = ScoreForLevel(o.Level, original)
	}
	return out
}
