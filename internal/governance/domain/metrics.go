package domain

import (
	"sort"
	"time"
)

// Remediation metrics (EDR-REMEDIATION-01 D6, D8 Q4). Pure arithmetic over facts Governance
// already records; the read side groups the Findings by Product and hands each group here.
//
// Two remediation measures are kept apart on purpose, labelled so they cannot be confused:
//   - time to remediation: creation → the first evaluated SBOM in which the Finding was no longer
//     present, counted ONLY when a person decided or resolved it afterwards (Q4: absence alone is
//     not a fix);
//   - time to resolution: creation → a person resolving it, whatever the SBOMs say.

// Age bands of open Findings, in days since creation.
const (
	AgeBand0to7   = "0-7"
	AgeBand8to30  = "8-30"
	AgeBand31to90 = "31-90"
	AgeBandOver90 = "over-90"
)

// AgeBands in display order.
var AgeBands = []string{AgeBand0to7, AgeBand8to30, AgeBand31to90, AgeBandOver90}

// MetricsFinding is one Finding as the metrics read it.
type MetricsFinding struct {
	CreatedAt time.Time
	// Open: not resolved or archived.
	Open bool
	// Bucket is the Finding's severity bucket ("" = unknown).
	Bucket string
	// FirstHumanAt is the first Position a person established; zero when none.
	FirstHumanAt time.Time
	// AbsentSince is when an evaluated SBOM first no longer carried it; zero when present.
	AbsentSince time.Time
	// HumanAfterAbsentAt is the first person's decision at or after AbsentSince; zero when none.
	HumanAfterAbsentAt time.Time
	// ResolvedAt is when it reached resolved/archived; zero when open or unknown.
	ResolvedAt time.Time
	// SLA is the clock's state for an open Finding ("" when not computed).
	SLA SLAState
}

// Mean is an average in days over N samples; Days is 0 when N is 0.
type Mean struct {
	Days float64 `json:"mean_days"`
	N    int     `json:"count"`
}

// RemediationMetrics is one scope's figures (a Product, or the estate).
type RemediationMetrics struct {
	Scope string `json:"scope"`
	Open  int    `json:"open"`
	// OpenByAge is band → severity bucket → count ("unknown" for no bucket).
	OpenByAge map[string]map[string]int `json:"open_by_age"`
	// SLA: open Findings whose clock is running or paused (applicable), how many are within
	// it (within, due_soon, paused) and how many are breached now.
	SLAApplicable int     `json:"sla_applicable"`
	WithinSLA     int     `json:"within_sla"`
	BreachedNow   int     `json:"breached_now"`
	WithinShare   float64 `json:"within_sla_share"`
	// TimeToDecision: creation → first human Position.
	TimeToDecision Mean `json:"time_to_decision"`
	// TimeToRemediation: creation → no longer present, then decided by a person (Q4).
	TimeToRemediation Mean `json:"time_to_remediation"`
	// TimeToResolution: creation → a person resolved it (reported beside, never merged).
	TimeToResolution Mean `json:"time_to_resolution"`
}

func days(d time.Duration) float64 { return d.Hours() / 24 }

func ageBand(age time.Duration) string {
	switch d := days(age); {
	case d <= 7:
		return AgeBand0to7
	case d <= 30:
		return AgeBand8to30
	case d <= 90:
		return AgeBand31to90
	default:
		return AgeBandOver90
	}
}

type meanAcc struct {
	sum float64
	n   int
}

func (m *meanAcc) add(from, to time.Time) {
	if from.IsZero() || to.IsZero() || to.Before(from) {
		return
	}
	m.sum += days(to.Sub(from))
	m.n++
}

func (m meanAcc) mean() Mean {
	if m.n == 0 {
		return Mean{}
	}
	return Mean{Days: m.sum / float64(m.n), N: m.n}
}

// ComputeRemediationMetrics reads one scope's Findings at now.
func ComputeRemediationMetrics(scope string, fs []MetricsFinding, now time.Time) RemediationMetrics {
	out := RemediationMetrics{Scope: scope, OpenByAge: map[string]map[string]int{}}
	for _, b := range AgeBands {
		out.OpenByAge[b] = map[string]int{}
	}
	var decision, remediation, resolution meanAcc
	for _, f := range fs {
		decision.add(f.CreatedAt, f.FirstHumanAt)
		if !f.AbsentSince.IsZero() && !f.HumanAfterAbsentAt.IsZero() {
			remediation.add(f.CreatedAt, f.AbsentSince)
		}
		resolution.add(f.CreatedAt, f.ResolvedAt)
		if !f.Open {
			continue
		}
		out.Open++
		bucket := f.Bucket
		if bucket == "" {
			bucket = "unknown"
		}
		out.OpenByAge[ageBand(now.Sub(f.CreatedAt))][bucket]++
		switch f.SLA {
		case SLAWithin, SLADueSoon, SLAPaused:
			out.SLAApplicable++
			out.WithinSLA++
		case SLABreached:
			out.SLAApplicable++
			out.BreachedNow++
		}
	}
	if out.SLAApplicable > 0 {
		out.WithinShare = float64(out.WithinSLA) / float64(out.SLAApplicable)
	}
	out.TimeToDecision, out.TimeToRemediation, out.TimeToResolution = decision.mean(), remediation.mean(), resolution.mean()
	return out
}

// SortMetrics orders scopes by name, the estate ("") first.
func SortMetrics(ms []RemediationMetrics) {
	sort.SliceStable(ms, func(i, j int) bool { return ms[i].Scope < ms[j].Scope })
}
