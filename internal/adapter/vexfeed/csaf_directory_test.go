package vexfeed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSAFDirectoryFeedSourceName(t *testing.T) {
	src := CSAFDirectoryFeedSource{Name_: "rhel"}
	if src.Name() != "rhel" {
		t.Fatalf("Name() = %q", src.Name())
	}
}

func TestZipOSVFeedSourceName(t *testing.T) {
	src := ZipOSVFeedSource{Name_: "alpine"}
	if src.Name() != "alpine" {
		t.Fatalf("Name() = %q", src.Name())
	}
}

func TestExtractCSAFLinksVariants(t *testing.T) {
	links := extractCSAFLinks(
		`<a href="https://example.com/RHSA-1.json">x</a><a href="/advisories/RHSA-2.json">y</a><a href="local.json">z</a>`,
		"https://security.example.com/index/",
	)
	if len(links) != 3 {
		t.Fatalf("links = %#v", links)
	}
	if links[0] != "https://example.com/RHSA-1.json" {
		t.Fatalf("absolute link = %q", links[0])
	}
	if links[1] != "https://security.example.com/advisories/RHSA-2.json" {
		t.Fatalf("root-relative link = %q", links[1])
	}
	if links[2] != "https://security.example.com/index/local.json" {
		t.Fatalf("relative link = %q", links[2])
	}
}

func TestCSAFDirectoryFeedSourceNotConfigured(t *testing.T) {
	src := CSAFDirectoryFeedSource{Name_: "rhel"}
	if _, err := src.Fetch(context.Background()); err == nil {
		t.Fatal("expected configuration error")
	}
}

func TestCSAFDirectoryFeedSourceSkipsBrokenAdvisories(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index/":
			_, _ = w.Write([]byte(`<html><a href="good.json">x</a><a href="bad.json">y</a></html>`))
		case "/index/good.json":
			_, _ = w.Write([]byte(`{"document":{"tracking":{"id":"GOOD","version":"1"}},"product_tree":{"branches":[{"category":"product_name","name":"Red Hat Enterprise Linux","branches":[{"category":"product_version","name":"8","branches":[{"category":"architecture","name":"x86_64","product":{"product_id":"prod","name":"pkg"}}]}]}]},"vulnerabilities":[{"cve":"CVE-2024-8888","product_status":{"fixed":["prod"]}}]}`))
		default:
			http.Error(w, "missing", http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	src := CSAFDirectoryFeedSource{
		Name_: "rhel", URL: srv.URL + "/index/",
		Fetcher: &HTTPFetcher{HTTPClient: srv.Client()},
	}
	out, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected assertions from good advisory")
	}
}
