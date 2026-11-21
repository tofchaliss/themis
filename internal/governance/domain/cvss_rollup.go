package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// Finding roll-up of the per-component CVSS assessments (EDR-SCORING-01 6, S4, shadow).

// Roll-up states, checked in this order (EDR 6).
const (
	RollupNoComponents      = "no_components"
	RollupNoCarrier         = "no_carrier"
	RollupNoOpenOccurrences = "no_open_occurrences"
	RollupUnavailable       = "unavailable"
	RollupScored            = "scored"
)

// Coverage values (EDR 6).
const (
	CoverageComplete      = "complete"
	CoveragePartial       = "partial"
	CoverageNone          = "none"
	CoverageNotApplicable = "not_applicable"
)

// Ratio is one coverage indicator: numerator, denominator and its value.
type Ratio struct {
	Numerator   int    `json:"numerator"`
	Denominator int    `json:"denominator"`
	Value       string `json:"value"`
}

func ratio(num, den int) Ratio {
	r := Ratio{Numerator: num, Denominator: den}
	switch {
	case den == 0:
		r.Value = CoverageNotApplicable
	case num == den:
		r.Value = CoverageComplete
	case num == 0:
		r.Value = CoverageNone
	default:
		r.Value = CoveragePartial
	}
	return r
}

// Unassessed names one eligible open component with no usable assessment.
type Unassessed struct {
	PURL   string `json:"purl"`
	Reason string `json:"reason"`
}

// FindingScore is the Finding-level roll-up.
type FindingScore struct {
	State string `json:"state"`
	// Score is the highest Environmental score among contributors; nil unless State is scored.
	Score *float64 `json:"score,omitempty"`
	Band  string   `json:"band,omitempty"`
	// Status is final or provisional when scored (D5), else empty.
	Status       string       `json:"score_status,omitempty"`
	Contributors []string     `json:"contributors"`
	AtMaximum    []string     `json:"at_maximum"`
	Coverage     Ratio        `json:"scoring_coverage"`
	Finality     Ratio        `json:"assessment_finality"`
	Unassessed   []Unassessed `json:"unassessed"`
}

// RollUp computes the Finding roll-up from its current components' assessments. The caller
// passes only currently matched components (retired matches excluded).
func RollUp(components []ComponentScore) FindingScore {
	out := FindingScore{Contributors: []string{}, AtMaximum: []string{}, Unassessed: []Unassessed{}}
	eligible, eligibleOpen, scored, final := 0, 0, 0, 0
	var best float64
	for _, c := range components {
		if !c.Eligible {
			continue
		}
		eligible++
		if !c.Open {
			continue
		}
		eligibleOpen++
		if c.Status == ScoreUnavailable || c.Scores == nil {
			out.Unassessed = append(out.Unassessed, Unassessed{PURL: c.PURL, Reason: c.UnscoredReason})
			continue
		}
		scored++
		if c.Status == ScoreFinal {
			final++
		}
		out.Contributors = append(out.Contributors, c.PURL)
		if c.Scores.Environmental > best {
			best = c.Scores.Environmental
		}
	}
	out.Coverage = ratio(scored, eligibleOpen)
	out.Finality = ratio(final, scored)
	switch {
	case len(components) == 0:
		out.State = RollupNoComponents
	case eligible == 0:
		out.State = RollupNoCarrier
	case eligibleOpen == 0:
		out.State = RollupNoOpenOccurrences
	case scored == 0:
		out.State = RollupUnavailable
	default:
		out.State = RollupScored
		out.Score, out.Band, out.Status = &best, ScoreBand(best), ScoreFinal
		for _, c := range components {
			if c.Eligible && c.Open && c.Scores != nil && c.Status != ScoreUnavailable && c.Scores.Environmental == best {
				out.AtMaximum = append(out.AtMaximum, c.PURL)
				if c.Status == ScoreProvisional {
					out.Status = ScoreProvisional
				}
			}
		}
	}
	sort.Strings(out.Contributors)
	sort.Strings(out.AtMaximum)
	sort.Slice(out.Unassessed, func(i, j int) bool { return out.Unassessed[i].PURL < out.Unassessed[j].PURL })
	return out
}

// ContentFingerprint is the SHA-256 of a value's JSON form. A new assessment or roll-up revision
// is written only when its fingerprint differs from the current one, so a re-delivered event or
// an equivalent recalculation creates nothing (EDR 8.3 item 2).
func ContentFingerprint(v any) string {
	b, _ := json.Marshal(v) // the snapshot types hold only JSON-safe fields
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
