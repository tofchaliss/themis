package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func nextFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":              {Data: []byte("classic")},
		"next/index.html":         {Data: []byte("<!doctype html>next")},
		"next/theme-init.js":      {Data: []byte("theme")},
		"next/assets/app-1.js":    {Data: []byte("plain-js")},
		"next/assets/app-1.js.br": {Data: []byte("brotli-js")},
		"next/assets/app-1.js.gz": {Data: []byte("gzip-js")},
		"next/assets/small-2.js":  {Data: []byte("small")},
	}
}

func serve(t *testing.T, h http.Handler, method, target, accept string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if accept != "" {
		req.Header.Set("Accept-Encoding", accept)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func newNext(fsys fs.FS) http.Handler {
	classic := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("classic-handler")) })
	return withNext(classic, fsys)
}

func TestNextRedirectsBarePath(t *testing.T) {
	rec := serve(t, newNext(nextFS()), http.MethodGet, "/next", "")
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/next/" {
		t.Fatalf("got %d %q, want 301 to /next/", rec.Code, rec.Header().Get("Location"))
	}
}

func TestNextIndexIsRevalidatedAndCarriesCSP(t *testing.T) {
	rec := serve(t, newNext(nextFS()), http.MethodGet, "/next/", "br, gzip")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "next") {
		t.Fatalf("index: %d %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != cacheRevalidate {
		t.Errorf("Cache-Control = %q, want %q", got, cacheRevalidate)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != nextCSP {
		t.Errorf("CSP = %q", got)
	}
	if rec.Header().Get("Content-Encoding") != "" {
		t.Error("index.html must not be sent pre-compressed (it has no compressed copy)")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("nosniff missing")
	}
}

func TestNextAssetsAreImmutableAndPreCompressed(t *testing.T) {
	cases := []struct {
		accept, wantEnc, wantBody string
	}{
		{"gzip, deflate, br", "br", "brotli-js"},
		{"gzip", "gzip", "gzip-js"},
		{"br;q=0, gzip", "gzip", "gzip-js"},
		{"br;q=0, gzip;q=0.0", "", "plain-js"},
		{"", "", "plain-js"},
	}
	for _, c := range cases {
		rec := serve(t, newNext(nextFS()), http.MethodGet, "/next/assets/app-1.js", c.accept)
		if rec.Code != http.StatusOK {
			t.Fatalf("%q: status %d", c.accept, rec.Code)
		}
		if got := rec.Header().Get("Content-Encoding"); got != c.wantEnc {
			t.Errorf("%q: Content-Encoding = %q, want %q", c.accept, got, c.wantEnc)
		}
		if rec.Body.String() != c.wantBody {
			t.Errorf("%q: body = %q, want %q", c.accept, rec.Body.String(), c.wantBody)
		}
		if got := rec.Header().Get("Cache-Control"); got != cacheImmutable {
			t.Errorf("%q: Cache-Control = %q", c.accept, got)
		}
		if c.wantEnc != "" {
			if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/javascript") {
				t.Errorf("%q: Content-Type = %q", c.accept, rec.Header().Get("Content-Type"))
			}
			if rec.Header().Get("Vary") != "Accept-Encoding" {
				t.Errorf("%q: Vary missing", c.accept)
			}
		}
	}
}

func TestNextAssetWithoutCompressedCopyFallsBack(t *testing.T) {
	rec := serve(t, newNext(nextFS()), http.MethodGet, "/next/assets/small-2.js", "br")
	if rec.Body.String() != "small" || rec.Header().Get("Content-Encoding") != "" {
		t.Fatalf("got %q enc %q", rec.Body.String(), rec.Header().Get("Content-Encoding"))
	}
}

func TestNextHeadSendsNoBody(t *testing.T) {
	rec := serve(t, newNext(nextFS()), http.MethodHead, "/next/assets/app-1.js", "br")
	if rec.Body.Len() != 0 || rec.Header().Get("Content-Encoding") != "br" {
		t.Fatalf("HEAD: body %d bytes, enc %q", rec.Body.Len(), rec.Header().Get("Content-Encoding"))
	}
}

func TestNextThemeInitIsRevalidated(t *testing.T) {
	rec := serve(t, newNext(nextFS()), http.MethodGet, "/next/theme-init.js", "")
	if rec.Header().Get("Cache-Control") != cacheRevalidate || rec.Body.String() != "theme" {
		t.Fatalf("theme-init: %q %q", rec.Header().Get("Cache-Control"), rec.Body.String())
	}
}

func TestClassicPathsAreUntouched(t *testing.T) {
	rec := serve(t, newNext(nextFS()), http.MethodGet, "/", "br")
	if rec.Body.String() != "classic-handler" {
		t.Fatalf("classic: %q", rec.Body.String())
	}
	if rec.Header().Get("Content-Security-Policy") != "" {
		t.Error("the classic GUI must not get the new GUI's CSP: its inline styles would break")
	}
}

func TestNextPathTraversalStaysInside(t *testing.T) {
	rec := serve(t, newNext(nextFS()), http.MethodGet, "/next/../index.html", "")
	if strings.Contains(rec.Body.String(), "classic") && rec.Header().Get("Content-Security-Policy") != "" {
		t.Fatal("a /next/ request served a file outside next/")
	}
}

// The committed build output (EDR-GUI-02 D3) must be inside the binary: a build that
// forgot it would serve the classic GUI's 404 at /next/.
func TestEmbeddedNextBuildIsPresent(t *testing.T) {
	h, err := assetHandler("")
	if err != nil {
		t.Fatal(err)
	}
	rec := serve(t, h, http.MethodGet, "/next/", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `<div id="root">`) {
		t.Fatalf("embedded /next/: %d", rec.Code)
	}
	if rec.Header().Get("Content-Security-Policy") != nextCSP {
		t.Fatal("embedded /next/ served without the CSP")
	}
}

func TestPickEncoding(t *testing.T) {
	cases := map[string]string{
		"":                  "",
		"identity":          "",
		"gzip":              "gzip",
		"GZIP;q=0.5, br":    "br",
		"br; q=0":           "",
		"br;q=bad":          "br",
		"deflate, gzip;q=1": "gzip",
	}
	for in, want := range cases {
		if got, _ := pickEncoding(in); got != want {
			t.Errorf("pickEncoding(%q) = %q, want %q", in, got, want)
		}
	}
}

// THEMIS_DASHBOARD_ASSETS (the edit-and-refresh override, D8) serves /next/ from the same
// directory, with the same rules.
func TestOverrideDirServesNext(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "next"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "next", "index.html"), []byte("override-next"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := assetHandler(dir)
	if err != nil {
		t.Fatal(err)
	}
	rec := serve(t, h, http.MethodGet, "/next/", "")
	if rec.Body.String() != "override-next" || rec.Header().Get("Content-Security-Policy") != nextCSP {
		t.Fatalf("override /next/: %q", rec.Body.String())
	}
}
