package main

import (
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
)

// The new GUI (EDR-GUI-02) is served at /next/ beside the classic one during the move-over
// (D11). Everything it needs that a plain file server does not do lives here:
//
//   - D8 cache rules: the content-hashed files under /next/assets/ never change, so they are
//     cached for a year; index.html and theme-init.js are revalidated on every load, so a new
//     release is picked up at once.
//   - D8 pre-compressed files: the build writes .br and .gz beside each large file, and the
//     smallest one the browser accepts is sent, with no compression work per request.
//   - D9 Content-Security-Policy, on the new GUI only. The classic GUI builds HTML with
//     inline style attributes and would break under it; it is removed with that GUI (G7).
const (
	nextPrefix = "/next/"

	// nextCSP — EDR-GUI-02 D9. React sets styles through the DOM (allowed); the Vite build
	// emits no inline script, and the pre-paint theme line is a file (theme-init.js).
	nextCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
		"font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; " +
		"form-action 'self'; frame-ancestors 'none'"

	cacheImmutable  = "public, max-age=31536000, immutable"
	cacheRevalidate = "no-cache"
)

// withNext routes /next and /next/* to the new GUI's files in fsys (rooted like the static
// directory, so the files live under "next/"); every other path goes to classic unchanged.
func withNext(classic http.Handler, fsys fs.FS) http.Handler {
	files := http.FileServer(http.FS(fsys))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/next":
			http.Redirect(w, r, nextPrefix, http.StatusMovedPermanently)
		case strings.HasPrefix(r.URL.Path, nextPrefix):
			serveNext(w, r, fsys, files)
		default:
			classic.ServeHTTP(w, r)
		}
	})
}

func serveNext(w http.ResponseWriter, r *http.Request, fsys fs.FS, files http.Handler) {
	h := w.Header()
	h.Set("Content-Security-Policy", nextCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")

	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/") // "next/assets/x.js", or "next" for /next/
	if strings.HasPrefix(name, "next/assets/") {
		h.Set("Cache-Control", cacheImmutable)
	} else {
		h.Set("Cache-Control", cacheRevalidate)
	}

	if enc, ext := pickEncoding(r.Header.Get("Accept-Encoding")); enc != "" && strings.HasPrefix(name, "next/assets/") {
		if body, err := fs.ReadFile(fsys, name+ext); err == nil {
			h.Add("Vary", "Accept-Encoding")
			if ct := mime.TypeByExtension(path.Ext(name)); ct != "" {
				h.Set("Content-Type", ct)
			}
			h.Set("Content-Encoding", enc)
			if r.Method != http.MethodHead {
				_, _ = w.Write(body)
			}
			return
		}
	}
	files.ServeHTTP(w, r)
}

// pickEncoding chooses brotli over gzip when the browser accepts it. A q of 0 refuses.
func pickEncoding(accept string) (encoding, ext string) {
	var br, gz bool
	for _, part := range strings.Split(accept, ",") {
		fields := strings.Split(part, ";")
		name := strings.ToLower(strings.TrimSpace(fields[0]))
		if refusedByQ(fields[1:]) {
			continue
		}
		switch name {
		case "br":
			br = true
		case "gzip":
			gz = true
		}
	}
	switch {
	case br:
		return "br", ".br"
	case gz:
		return "gzip", ".gz"
	}
	return "", ""
}

func refusedByQ(params []string) bool {
	for _, p := range params {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok || strings.TrimSpace(k) != "q" {
			continue
		}
		if q, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && q == 0 {
			return true
		}
	}
	return false
}
