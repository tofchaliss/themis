package vexfeed

import (
	"context"
	"fmt"

	"github.com/themis-project/themis/internal/domain"
)

// StaticFeedSource returns fixed assertions (tests and stub deployments).
type StaticFeedSource struct {
	FeedName   string
	Assertions []domain.VendorVEXAssertion
	Err        error
}

func (s StaticFeedSource) Name() string { return s.FeedName }

func (s StaticFeedSource) Fetch(context.Context) ([]domain.VendorVEXAssertion, error) {
	if s.Err != nil {
		return nil, s.Err
	}
	return s.Assertions, nil
}

// URLFeedSource fetches and parses a single feed URL.
type URLFeedSource struct {
	Name_   string
	URL     string
	Kind    string // csaf, osv
	Fetcher *HTTPFetcher
}

func (s URLFeedSource) Name() string { return s.Name_ }

func (s URLFeedSource) Fetch(ctx context.Context) ([]domain.VendorVEXAssertion, error) {
	if s.Fetcher == nil || s.URL == "" {
		return nil, fmt.Errorf("feed %s not configured", s.Name_)
	}
	body, err := s.Fetcher.Fetch(ctx, s.URL)
	if err != nil {
		return nil, err
	}
	switch s.Kind {
	case "csaf":
		return ParseCSAF(body, s.Name_)
	default:
		return ParseOSVFeed(body, s.Name_)
	}
}
