package vexfeed

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

var csafAdvisoryLinkRE = regexp.MustCompile(`href="([^"]+\.json)"`)

// CSAFDirectoryFeedSource crawls a Red Hat CSAF advisory index and parses each linked document.
type CSAFDirectoryFeedSource struct {
	Name_   string
	URL     string
	Fetcher *HTTPFetcher
}

func (s CSAFDirectoryFeedSource) Name() string { return s.Name_ }

func (s CSAFDirectoryFeedSource) Fetch(ctx context.Context) ([]domain.VendorVEXAssertion, error) {
	if s.Fetcher == nil || s.URL == "" {
		return nil, fmt.Errorf("feed %s not configured", s.Name_)
	}
	indexBody, err := s.Fetcher.Fetch(ctx, s.URL)
	if err != nil {
		return nil, err
	}
	links := extractCSAFLinks(string(indexBody), s.URL)
	var out []domain.VendorVEXAssertion
	seen := map[string]struct{}{}
	for _, link := range links {
		if _, ok := seen[link]; ok {
			continue
		}
		seen[link] = struct{}{}
		body, err := s.Fetcher.Fetch(ctx, link)
		if err != nil {
			continue
		}
		assertions, err := ParseCSAF(body, s.Name_)
		if err != nil {
			continue
		}
		out = append(out, assertions...)
	}
	return out, nil
}

func extractCSAFLinks(html, baseURL string) []string {
	matches := csafAdvisoryLinkRE.FindAllStringSubmatch(html, -1)
	base := strings.TrimRight(baseURL, "/")
	var links []string
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		href := match[1]
		if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
			links = append(links, href)
			continue
		}
		if strings.HasPrefix(href, "/") {
			if idx := strings.Index(base, "://"); idx >= 0 {
				if end := strings.Index(base[idx+3:], "/"); end >= 0 {
					origin := base[:idx+3+end]
					links = append(links, origin+href)
				}
			}
			continue
		}
		links = append(links, base+"/"+strings.TrimPrefix(href, "./"))
	}
	return links
}
