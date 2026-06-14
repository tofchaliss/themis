package vexfeed_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/adapter/vexfeed"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

func TestEnrichmentAssertionReaderNilStore(t *testing.T) {
	var r vexfeed.EnrichmentAssertionReader
	out, err := r.ListVendorAssertionsForCVE(context.Background(), "CVE-1")
	if err != nil || out != nil {
		t.Fatalf("ListVendorAssertionsForCVE() = %v, %v", out, err)
	}
}

func TestStaticFeedSourceError(t *testing.T) {
	src := vexfeed.StaticFeedSource{FeedName: "bad", Err: errors.New("fail")}
	if _, err := src.Fetch(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestVendorMatchResultFields(t *testing.T) {
	_ = enrichment.VendorMatchResult{Matched: true, MatchType: domain.VEXMatchTypeExact}
}

func TestParseCSAFLegacyShape(t *testing.T) {
	raw := []byte(`{
		"document":{"tracking":{"id":"RHSA-LEGACY"}},
		"vulnerabilities":[{"cve":"CVE-LEG","product_status":[{"category":"known_not_affected","branches":[{"product":{"product_id":"pkg:rpm/redhat/bash@1.0"}}]}]}]
	}`)
	_, err := vexfeed.ParseCSAF(raw, "RHSA-LEGACY")
	if err != nil {
		t.Fatalf("ParseCSAF() error = %v", err)
	}
}
