package vexfeed_test

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/adapter/vexfeed"
)

func TestZipOSVFeedSource(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	entry, err := zw.Create("ALPINE-CVE-2024-0001.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = entry.Write([]byte(`{"id":"ALPINE-CVE-2024-0001","aliases":["CVE-2024-0001"],"affected":[{"package":{"ecosystem":"Alpine","name":"busybox"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0","fixed":"1.0-r1"}]}]}]}`))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(srv.Close)

	src := vexfeed.ZipOSVFeedSource{
		Name_: "alpine", URL: srv.URL,
		Fetcher: &vexfeed.HTTPFetcher{HTTPClient: srv.Client()},
	}
	out, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if len(out) == 0 || out[0].CVEID != "CVE-2024-0001" {
		t.Fatalf("out = %#v", out)
	}
}

func TestCSAFDirectoryFeedSource(t *testing.T) {
	advisory := `{"document":{"tracking":{"id":"RHSA-TEST","version":"1"}},"product_tree":{"branches":[{"category":"product_name","name":"Red Hat Enterprise Linux","branches":[{"category":"product_version","name":"8","branches":[{"category":"architecture","name":"x86_64","product":{"product_id":"prod","name":"pkg"}}]}]}]},"vulnerabilities":[{"cve":"CVE-2024-9999","product_status":{"fixed":["prod"]}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index/" {
			_, _ = w.Write([]byte(`<html><a href="RHSA-TEST.json">x</a></html>`))
			return
		}
		_, _ = w.Write([]byte(advisory))
	}))
	t.Cleanup(srv.Close)

	src := vexfeed.CSAFDirectoryFeedSource{
		Name_: "rhel", URL: srv.URL + "/index/",
		Fetcher: &vexfeed.HTTPFetcher{HTTPClient: srv.Client()},
	}
	out, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("expected assertions, got %#v", out)
	}
}

func TestParseOSVFeedAlpineIDNormalization(t *testing.T) {
	raw := []byte(`{"id":"ALPINE-CVE-2024-7777","affected":[{"package":{"ecosystem":"Alpine","name":"zlib"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`)
	out, err := vexfeed.ParseOSVFeed(raw, "alpine")
	if err != nil {
		t.Fatalf("ParseOSVFeed() error = %v", err)
	}
	if len(out) != 1 || out[0].CVEID != "CVE-2024-7777" {
		t.Fatalf("out = %#v", out)
	}
}
