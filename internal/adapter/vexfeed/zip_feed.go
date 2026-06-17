package vexfeed

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

// ZipOSVFeedSource downloads a zip archive of OSV JSON files and parses each entry.
type ZipOSVFeedSource struct {
	Name_   string
	URL     string
	Fetcher *HTTPFetcher
}

func (s ZipOSVFeedSource) Name() string { return s.Name_ }

func (s ZipOSVFeedSource) Fetch(ctx context.Context) ([]domain.VendorVEXAssertion, error) {
	if s.Fetcher == nil || s.URL == "" {
		return nil, fmt.Errorf("feed %s not configured", s.Name_)
	}
	body, err := s.Fetcher.Fetch(ctx, s.URL)
	if err != nil {
		return nil, err
	}
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("parse zip feed %s: %w", s.Name_, err)
	}
	var out []domain.VendorVEXAssertion
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(file.Name), ".json") {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			continue
		}
		assertions, err := ParseOSVFeed(raw, s.Name_)
		if err != nil {
			continue
		}
		out = append(out, assertions...)
	}
	return out, nil
}
