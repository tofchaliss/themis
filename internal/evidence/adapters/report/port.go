package report

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/evidence/app"
	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// Port adapts this ACL onto the application's ReportRegistry port — the seam the
// intake use case identifies and converts a submitted body through (EDR-INTAKE-01
// D4/D5). The app must not import this package: a vendor shape never reaches the
// inner rings, and neither does the package that understands one.
//
// It is stateless, so the zero value is usable.
type Port struct{}

var _ app.ReportRegistry = Port{}

// Detect names the body (D5a's closed, ordered table) and reports the kind and
// dialect as the ACL's own strings, which the intake echoes to the client as
// `detected_kind` / `detected_format`.
func (Port) Detect(contentType string, body []byte) (string, string, error) {
	kind, dialect, err := Detect(contentType, body)
	if err != nil {
		return "", "", asReject(err, domain.ReasonUnrecognisedFormat)
	}
	return string(kind), string(dialect), nil
}

// Convert produces the curated document plus the provenance of the conversion.
//
// The source digest is computed HERE, over the submitted bytes, because for a
// converted submission those are not the bytes that get filed (D2) — and it is the
// digest that makes the provenance verifiable at all. A pass-through still carries
// one: the source is then also the document, and recording it costs nothing.
func (Port) Convert(dialect string, body []byte, suppliedObservedAt time.Time) ([]byte, app.ReportStats, string, string, error) {
	conv, ok := ConverterFor(Dialect(dialect))
	if !ok {
		// The dialect came from Detect, so a miss here is a defect in this package
		// rather than a fault in the document — refused by name all the same,
		// because converting with a converter nobody chose is how an unreadable
		// document lands.
		return nil, app.ReportStats{}, "", "", domain.Reject(domain.ReasonUnrecognisedFormat,
			fmt.Sprintf("no converter is registered for dialect %q", dialect))
	}
	sourceDigest := value.NewContentFingerprint(body).String()
	curated, stats, err := conv.Convert(body, suppliedObservedAt)
	if err != nil {
		return nil, app.ReportStats{}, "", "", asReject(err, domain.ReasonConversionFailed)
	}
	return curated, app.ReportStats(stats), conv.Version(), sourceDigest, nil
}

// reasonFor maps this ACL's sentinels onto the domain's closed refusal taxonomy
// (D11). Walked in order, so it is a table and not map iteration.
var reasonFor = []struct {
	sentinel error
	reason   domain.RejectReason
}{
	{ErrUnrecognisedFormat, domain.ReasonUnrecognisedFormat},
	{ErrEmptyReport, domain.ReasonEmptyReport},
	{ErrMalformedBody, domain.ReasonMalformedBody},
	{ErrSourceInvalid, domain.ReasonSourceInvalid},
	{ErrObservedAtUnderivable, domain.ReasonObservedAtUnderivable},
}

// asReject translates an ACL error into a reason-carrying refusal, and strips the
// sentinel's own text out of the detail while doing it.
//
// The strip is the point, not tidiness. These sentinels are named after their reason
// (`errors.New("unrecognised_format")`) and wrapped as "<reason>: <elaboration>", so
// handing the whole string over as `detail` would ship the reason inside its own
// elaboration — the flattening that turned a closed enum into free text and made
// every consumer's table lookup miss (fixed 2026-09-22). The pair stays two fields
// from here all the way to the wire.
//
// An error matching no sentinel carries no reason of its own: it is an
// infrastructure fault, and the most honest thing available is the step it failed
// in, which is what the fallback names.
func asReject(err error, fallback domain.RejectReason) error {
	for _, m := range reasonFor {
		if errors.Is(err, m.sentinel) {
			return domain.Reject(m.reason, strings.TrimPrefix(err.Error(), string(m.reason)+": "))
		}
	}
	return domain.Reject(fallback, err.Error())
}
