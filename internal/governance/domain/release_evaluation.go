package domain

// The release-evaluation vocabulary (EDR-DELIVERY-01 M2-2 / M2-3 / N-M2b): why a correlation
// ran, how a Release's Findings bucket into four severities, and the completed fact Governance
// states about a Release once it has been evaluated.
//
// The causes are RE-DECLARED here rather than imported from Knowledge — contexts collaborate
// via events and read APIs only, so the wire vocabulary is restated on each side (the same rule
// the inbound Knowledge facts in app follow).

const (
	// CauseNewSBOM — correlation ran because an SBOM was uploaded for the release.
	CauseNewSBOM = "new_sbom"
	// CauseRediscovery — correlation re-ran from Knowledge's re-discovery sweep (KN-RECOR-1).
	// A real posture change, but nothing was built, so the rebuild loop must ignore it (M2-3).
	CauseRediscovery = "rediscovery"
)

// ValidDiscoveryCause reports whether cause is one of the two values the contract admits.
//
// A third value is REFUSED rather than carried through: `cause` is a closed enum on
// governance.release_evaluated.v1, and a consumer switching on it would be left without a case.
// Refusing at the edge keeps the enum closed where it is cheapest to keep closed.
func ValidDiscoveryCause(cause string) bool {
	return cause == CauseNewSBOM || cause == CauseRediscovery
}

// The four severity-bucket floors over `base_score` (EDR-DELIVERY-01 M1b-5, reaffirmed by
// M2-2). They are FLOORS, not ranges: a score belongs to the highest bucket whose floor it
// reaches. The ladder inverts the one Knowledge built the score from, so the event and the Jira
// body cannot disagree about what "High" means.
const (
	SeverityCriticalFloor = 90
	SeverityHighFloor     = 70
	SeverityMediumFloor   = 40
)

// SeverityCounts is how many of a Release's Findings fall in each severity bucket.
//
// The counts need NOT sum to the Release's Finding count, and a consumer must not assume they
// do: a `base_score` of 0 is `Unknown` and is counted in no bucket — least of all `low`, since
// the absence of severity evidence is not evidence of mildness (M2-2).
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// CountSeverityBuckets buckets every given base score by the M1b-5 ladder.
//
// EVERY Finding of the Release is counted, including the ones a Position has suppressed
// (M1b-4): the event states what the Release CONTAINS, and a suppression is a decision about a
// Finding, not evidence that the flaw left the inventory. A subscriber that wants the
// undecided half reads the posture.
//
// Zero counts are a legitimate answer and the caller publishes them (M2-2) — a Release with
// nothing open is evaluated-and-clean, which silence could never say.
func CountSeverityBuckets(scores []int) SeverityCounts {
	var c SeverityCounts
	for _, score := range scores {
		switch {
		case score >= SeverityCriticalFloor:
			c.Critical++
		case score >= SeverityHighFloor:
			c.High++
		case score >= SeverityMediumFloor:
			c.Medium++
		case score > 0:
			c.Low++
		}
	}
	return c
}

// ReleaseEvaluated announces that Governance has evaluated one Release against one SBOM — the
// per-Release signal RC-1 asked for, published once per `knowledge.release_correlation_completed`
// (EDR-DELIVERY-01 M2-1 / M2-2).
//
// Unlike every other Governance event this one is about a RELEASE rather than a Finding, and it
// is the only one that names the product and the project: Knowledge holds no Registry seam, so
// M2a-1 left those two ids off its completion event and they are resolved here, where Governance
// already reads Registry and already owns the counts.
//
// The field names are snake_case and the counts are integers (M2-2) — the kernel envelope's body
// convention, and the one shape a JSON consumer never has to guess at. All four ids are carried
// verbatim as TEXT, never parsed.
type ReleaseEvaluated struct {
	ProductID      string         `json:"product_id"`
	ProjectID      string         `json:"project_id"`
	ReleaseID      string         `json:"release_id"`
	SBOMID         string         `json:"sbom_id"`
	SeverityCounts SeverityCounts `json:"severity_counts"`
	// Cause is copied VERBATIM from the Knowledge event that triggered the evaluation. Governance
	// never re-derives it: the producer knows why correlation ran, and a consumer inferring it
	// from "did the SBOM id change" would be guessing — a wrong guess silently spends the rebuild
	// loop's attempt budget (M2-3).
	Cause string `json:"cause"`
}

// NewReleaseEvaluated builds the per-Release evaluation fact.
func NewReleaseEvaluated(productID, projectID, releaseID, sbomID, cause string, counts SeverityCounts) ReleaseEvaluated {
	return ReleaseEvaluated{
		ProductID: productID, ProjectID: projectID, ReleaseID: releaseID, SBOMID: sbomID,
		SeverityCounts: counts, Cause: cause,
	}
}
