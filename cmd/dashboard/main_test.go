package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/crypto/bcrypt"

	"github.com/themis-project/themis/internal/dashboard/session"
	"github.com/themis-project/themis/internal/dashboard/userstore"
	"github.com/themis-project/themis/internal/platform/auth"
	"github.com/themis-project/themis/internal/platform/observability"
)

// The Phase-1 boot refusal (EDR-GUI-01, D3 grill amendment): THEMIS_AUTH_REQUIRED=1
// with no authenticated edge wired must refuse to boot — a guard that only runs in
// production is a guard nobody has seen work.
func TestGuardAuth(t *testing.T) {
	if err := guardAuth(config{authRequired: true}); !errors.Is(err, errAuthRequired) {
		t.Errorf("authRequired=true: err = %v, want the boot refusal", err)
	}
	if err := guardAuth(config{authRequired: false}); err != nil {
		t.Errorf("authRequired=false: err = %v, want boot to proceed", err)
	}
}

// The embedded assets must actually resolve — a broken go:embed path fails here, not
// on the first page load of a deployment.
func TestAssetHandlerEmbeds(t *testing.T) {
	if _, err := assetHandler(""); err != nil {
		t.Fatalf("embedded assets: %v", err)
	}
	if _, err := assetHandler(t.TempDir()); err != nil {
		t.Fatalf("override dir: %v", err)
	}
}

// Every no-answer reason the servers can state must have an entry in the page's taxonomy.
//
// The page once knew six of the fifteen and rendered the rest as "the Gateway stated no
// reason" — an assertion, and a false one, because the server had stated a precise reason in
// every case (DEF_GUI_AI_REASON_MAP_INCOMPLETE). AI-204-1 grew the vocabulary on one side of
// the wire and nothing re-derived the consumer on the other, which is CONVENTIONS R5's shape
// applied to an enum. This test is that re-derivation, made automatic: it reads the reason
// constants out of the two servers' source and fails when one has no home on the page.
func TestAIReasonTaxonomyIsCoveredByTheDashboard(t *testing.T) {
	js, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	// The map's own block, so a reason merely MENTIONED in a comment elsewhere does not pass.
	const marker = "const AI_REASONS = {"
	start := bytes.Index(js, []byte(marker))
	if start < 0 {
		t.Fatalf("app.js no longer defines %s — this guard needs re-pointing", marker)
	}
	end := bytes.Index(js[start:], []byte("\n};"))
	if end < 0 {
		t.Fatal("AI_REASONS block is unterminated")
	}
	block := string(js[start : start+end])

	// Reason* constants, read from the source rather than copied — a copy would go stale in
	// exactly the way this test exists to prevent.
	reasonConst := regexp.MustCompile(`Reason[A-Za-z]*\s+=\s+"([a-z_]+)"`)
	for _, src := range []string{
		"../../internal/intelligence/app/gateway.go",
		"../../internal/governance/app/service.go",
	} {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read %s: %v", src, err)
		}
		found := reasonConst.FindAllStringSubmatch(string(b), -1)
		if len(found) == 0 {
			t.Fatalf("%s: no Reason* constants matched — this guard needs re-pointing", src)
		}
		for _, m := range found {
			if !strings.Contains(block, "\n  "+m[1]+": [") {
				t.Errorf("reason %q (%s) has no entry in AI_REASONS — it would render as an "+
					"unrecognised reason instead of an explanation", m[1], src)
			}
		}
	}
}

// The Admin tab's wiring, read out of the embedded assets. The SPA has no compiler (which is
// why `make js-check` exists), so the one thing a Go test CAN prove is that the pieces the
// server's routes depend on are still present and still spelled the same: a renamed route or
// a deleted rail link would otherwise ship as a tab that silently is not there.
func TestAdminTabIsWiredIntoTheSPA(t *testing.T) {
	js, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	html, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}

	for _, want := range []string{
		`function viewAdmin(`,                  // the view itself
		`#/admin`,                              // the route the rail link and the notice point at
		`IS_ADMIN = j.scopes.includes("admin"`, // the tab is admin-only…
		`let IS_ADMIN = false`,                 // …and nobody is admin until an answer says so
		`rail.hidden = !(IS_ADMIN || authOff)`, // auth-off keeps the tab reachable (requirement 6)
		`auth_enabled`,                         // the auth-disabled branch renders from this
	} {
		if !bytes.Contains(js, []byte(want)) {
			t.Errorf("app.js no longer contains %s — the Admin tab's wiring moved and this guard needs re-pointing", want)
		}
	}
	// Both routes the server mounts must be the ones the page actually calls.
	for _, route := range []string{adminStatusRoute, adminPasswordRoute} {
		if !bytes.Contains(js, []byte(route)) {
			t.Errorf("app.js does not call %s", route)
		}
	}
	for _, want := range []string{`id="rail-admin"`, `id="default-pw-notice"`} {
		if !bytes.Contains(html, []byte(want)) {
			t.Errorf("index.html no longer contains %s", want)
		}
	}
	// The shipped default password must not be baked into anything a browser downloads: the
	// page says a default is in use, never what it is.
	if bytes.Contains(js, []byte(userstore.DefaultAdminPassword)) || bytes.Contains(html, []byte(userstore.DefaultAdminPassword)) {
		t.Error("the default password is embedded in an asset served to the browser")
	}
}

/* ---------- the dashboard's own login table (EDR-GUI-01 D3 amendment 2026-10-12) ---------- */

// The `auth` database is migrated by authadmin too, so the dashboard needs its OWN
// golang-migrate bookkeeping table — otherwise whichever ran second reads the other's
// version, concludes it is up to date, and silently skips its own CREATE TABLE (the defect
// Registry hit in the `evidence` database).
func TestMigrationDSN_CarriesTheDashboardsOwnMigrationsTable(t *testing.T) {
	got, err := migrationDSN("postgres://u:p@localhost:5432/auth?sslmode=disable")
	if err != nil {
		t.Fatalf("migrationDSN: %v", err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("result is not a valid URL: %v", err)
	}
	if u.Query().Get("x-migrations-table") != userstore.MigrationsTable {
		t.Errorf("x-migrations-table = %q, want %q", u.Query().Get("x-migrations-table"), userstore.MigrationsTable)
	}
	if u.Query().Get("sslmode") != "disable" {
		t.Errorf("sslmode = %q, want it preserved", u.Query().Get("sslmode"))
	}
}

// The trap: putting x-migrations-table on the POOL DSN makes the migration succeed and then
// kills every runtime connection, because pgx forwards the unknown parameter to Postgres as a
// startup option. The caller's string must come back untouched.
func TestMigrationDSN_DoesNotMutateThePoolDSN(t *testing.T) {
	const pool = "postgres://u:p@localhost:5432/auth?sslmode=disable"
	if _, err := migrationDSN(pool); err != nil {
		t.Fatalf("migrationDSN: %v", err)
	}
	if strings.Contains(pool, "x-migrations-table") {
		t.Fatal("the pool DSN was mutated — pgx must never see the migrations-table parameter")
	}
}

func TestMigrationDSN_AddsAQueryStringWhenThereIsNone(t *testing.T) {
	got, err := migrationDSN("postgres://u:p@localhost:5432/auth")
	if err != nil {
		t.Fatalf("migrationDSN: %v", err)
	}
	if !strings.Contains(got, "x-migrations-table="+userstore.MigrationsTable) {
		t.Errorf("got %q, want the parameter appended", got)
	}
}

func TestMigrationDSN_RejectsAnUnparseableDSN(t *testing.T) {
	if _, err := migrationDSN("postgres://u:p@%%/auth"); err == nil {
		t.Error("want an error for an unparseable DSN, so a bad config fails at startup rather than mid-migration")
	}
}

// The migrations path defaults to a RELATIVE directory, so on a non-repo deployment the most
// likely failure is "the working directory is not what the default assumes". The refusal must
// name the path it looked for and the variable that overrides it — golang-migrate's own
// "no such file or directory" names neither, and an operator cannot act on it.
func TestApplyMigrations_NamesTheUnreadablePathAndTheOverride(t *testing.T) {
	err := applyMigrations("postgres://u:p@localhost:5432/auth?sslmode=disable", "no/such/migrations")
	if err == nil {
		t.Fatal("want a refusal for a missing migrations directory")
	}
	for _, want := range []string{"no/such/migrations", "THEMIS_DASHBOARD_MIGRATIONS"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not mention %q", err, want)
		}
	}
	// A bad DSN is still rejected before anything touches the filesystem.
	if _, derr := migrationDSN("postgres://u:p@%%/auth"); derr == nil {
		t.Error("want the DSN checked first")
	}
}

// What startup SAYS about the seed, and — the part that matters — what it never says. The
// shipped default password lives in userstore's seed constant and in INSTALLATION.md; a log
// aggregator must never receive it.
func TestSeedMessagesNeverCarryThePlaintextDefault(t *testing.T) {
	for _, msg := range []string{seedCreatedMsg, seedMissingMsg, seedFailedMsg} {
		if strings.Contains(msg, userstore.DefaultAdminPassword) {
			t.Errorf("a startup log line contains the default password: %q", msg)
		}
	}
	// The missing-table warning has one job: name the flag that fixes it. Without that, an
	// operator reading "table is MISSING" has nowhere to go.
	if !strings.Contains(seedMissingMsg, "THEMIS_DASHBOARD_MIGRATE=1") {
		t.Error("the missing-table warning does not name THEMIS_DASHBOARD_MIGRATE=1")
	}
}

// A dashboard started against an auth database that never had the dashboard migrations run
// must say so ONCE and keep serving — not refuse to boot. Refusing would take the whole GUI
// down over a table one flag creates, while API-key sign-in is unaffected.
func TestReportSeed_SaysItOnceAndKeepsServing(t *testing.T) {
	cases := []struct {
		name    string
		created bool
		err     error
		want    zapcore.Level
		lines   int
		contain string
	}{
		{"never migrated", false, userstore.ErrTableMissing, zapcore.WarnLevel, 1, "THEMIS_DASHBOARD_MIGRATE=1"},
		{"store failure", false, errors.New("db down"), zapcore.WarnLevel, 1, "could not seed"},
		{"fresh install", true, nil, zapcore.InfoLevel, 1, "Admin tab"},
		{"ordinary restart", false, nil, zapcore.InfoLevel, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.DebugLevel)
			reportSeed(observability.New(zap.New(core)), tc.created, tc.err)
			if logs.Len() != tc.lines {
				t.Fatalf("logged %d lines, want %d: %v", logs.Len(), tc.lines, logs.All())
			}
			if tc.lines == 0 {
				return
			}
			entry := logs.All()[0]
			if entry.Level != tc.want {
				t.Errorf("level = %v, want %v", entry.Level, tc.want)
			}
			if !strings.Contains(entry.Message, tc.contain) {
				t.Errorf("message %q does not mention %q", entry.Message, tc.contain)
			}
			if strings.Contains(entry.Message, userstore.DefaultAdminPassword) {
				t.Error("the log line carries the default password")
			}
		})
	}
}

// A password login against a missing table fails exactly like a wrong password, while the
// API-key door keeps working — the behaviour the missing-table warning describes, and the
// reason reportSeed warns instead of refusing to boot.
func TestPasswordLoginFailsLikeAWrongPasswordWhenTheTableIsMissing(t *testing.T) {
	ctx := context.Background()
	mgr := session.NewManager(
		&stubVerifier{valid: map[string]auth.Principal{"good-key": adminKey}},
		missingTableUsers{}, 0, nil)

	if _, _, ok := mgr.LoginPassword(ctx, userstore.AdminUsername, userstore.DefaultAdminPassword); ok {
		t.Error("a password login succeeded against a missing table")
	}
	if _, _, ok := mgr.Login(ctx, "good-key"); !ok {
		t.Error("API-key sign-in stopped working because the password table was absent")
	}
}

// A fresh systemd install must self-migrate and seed, like every other node's *_MIGRATE flag
// — otherwise the first operator to enable auth gets a dashboard that offers a password form
// backed by no table. The dashboard stanza is the one this flag belongs to, so the test reads
// that stanza rather than grepping the whole script.
func TestSystemdInstallerSetsTheDashboardMigrateFlag(t *testing.T) {
	b, err := os.ReadFile("../../deploy/systemd/install-systemd.sh")
	if err != nil {
		t.Fatalf("read the installer: %v", err)
	}
	const marker = "write_env dashboard <<EOF"
	start := bytes.Index(b, []byte(marker))
	if start < 0 {
		t.Fatalf("the installer no longer has a %q stanza — this guard needs re-pointing", marker)
	}
	end := bytes.Index(b[start:], []byte("\nEOF"))
	if end < 0 {
		t.Fatal("the dashboard stanza is unterminated")
	}
	stanza := string(b[start : start+end])
	if !strings.Contains(stanza, "\nTHEMIS_DASHBOARD_MIGRATE=1") {
		t.Errorf("the dashboard env stanza does not set THEMIS_DASHBOARD_MIGRATE=1:\n%s", stanza)
	}
	// The DSN it hands the node must stay PLAIN: the migration DSN is derived internally,
	// and pgx rejects the migrations-table parameter on every runtime connection.
	if strings.Contains(stanza, "x-migrations-table") {
		t.Error("the installer put x-migrations-table on the dashboard's DSN — pgx must never see it")
	}
}

/* ---------- mounting order: the Admin routes are never proxied ---------- */

// The ORDER in mountAuthenticated is load-bearing, and nothing in the type system says so:
// the two dashboard-local Admin routes are registered BEFORE the /api/* proxy mount. If they
// were not, a password change would be forwarded to a node — an unknown-node 404 at best,
// and at worst a password sent to a service with no business seeing one. This test drives the
// real router with a proxy SPY and proves the spy is never reached.
func TestAdminRoutesAreHandledLocallyAndNeverProxied(t *testing.T) {
	ctx := context.Background()
	users := &stubUsers{rows: map[string]userstore.User{
		userstore.AdminUsername: {
			Username:          userstore.AdminUsername,
			PasswordHash:      bcryptHash(t, userstore.DefaultAdminPassword),
			IsDefaultPassword: true,
			UpdatedAt:         time.Unix(1_700_000_000, 0).UTC(),
		},
	}}
	mgr := session.NewManager(&stubVerifier{valid: map[string]auth.Principal{"good-key": adminKey}}, users, 0, nil)
	sh := session.Handler{Manager: mgr}

	var proxied []string
	spy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied = append(proxied, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	assets := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	router := chi.NewRouter()
	mountAuthenticated(router, sh, spy, assets)

	token, _, ok := mgr.LoginPassword(ctx, userstore.AdminUsername, userstore.DefaultAdminPassword)
	if !ok {
		t.Fatal("password login failed")
	}
	cookie := &http.Cookie{Name: session.CookieName, Value: token}

	call := func(method, path, body string) *httptest.ResponseRecorder {
		var r *http.Request
		if body != "" {
			r = httptest.NewRequest(method, path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
		} else {
			r = httptest.NewRequest(method, path, nil)
		}
		r.AddCookie(cookie)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, r)
		return rec
	}

	// A node route DOES reach the proxy — otherwise this test would pass with no proxy wired.
	if rec := call(http.MethodGet, "/api/governance/findings", ""); rec.Code != http.StatusOK {
		t.Fatalf("node read = %d, want 200 through the proxy", rec.Code)
	}
	if len(proxied) != 1 || proxied[0] != "/api/governance/findings" {
		t.Fatalf("proxy saw %v, want the one node read", proxied)
	}

	// The Admin routes are answered HERE.
	if rec := call(http.MethodGet, adminStatusRoute, ""); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"auth_enabled":true`) {
		t.Fatalf("admin status = %d %q, want the dashboard's own answer", rec.Code, rec.Body.String())
	}
	changeBody := `{"current":"` + userstore.DefaultAdminPassword + `","new":"quiet-mountain","confirm":"quiet-mountain"}`
	if rec := call(http.MethodPost, adminPasswordRoute, changeBody); rec.Code != http.StatusNoContent {
		t.Fatalf("password change = %d %q, want 204", rec.Code, rec.Body.String())
	}
	if len(proxied) != 1 {
		t.Fatalf("the proxy was reached by %v — an Admin route was forwarded to a node", proxied)
	}
}

// With no auth DSN there is no sign-in and no password, and the Admin status route still
// answers — locally, never through the proxy — so the tab can explain itself rather than
// render a form against a store that does not exist. There is no password route at all here:
// mounting one would mean the open edge accepted password writes from anyone.
func TestOpenEdgeAnswersTheAdminStatusLocally(t *testing.T) {
	var proxied []string
	spy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied = append(proxied, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	assets := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	router := chi.NewRouter()
	mountOpen(router, spy, assets, "operator")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, adminStatusRoute, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"auth_enabled":false`) {
		t.Fatalf("open-edge admin status = %d %q, want 200 {auth_enabled:false}", rec.Code, rec.Body.String())
	}
	if len(proxied) != 0 {
		t.Fatalf("the proxy saw %v — the Admin status route was forwarded to a node", proxied)
	}

	// A password posted to an open edge is refused HERE, not forwarded: a credential must
	// never leave this process by accident, not even as an unknown-node 404.
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, adminPasswordRoute, strings.NewReader(`{}`)))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "authentication is disabled") {
		t.Errorf("open-edge password change = %d %q, want 503 authentication-is-disabled", rec.Code, rec.Body.String())
	}
	if len(proxied) != 0 {
		t.Fatalf("the proxy saw %v — a posted password was forwarded to a node", proxied)
	}

	// And node reads still reach the proxy.
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/governance/findings", nil))
	if rec.Code != http.StatusOK || len(proxied) != 1 {
		t.Errorf("node read = %d, proxy saw %v", rec.Code, proxied)
	}
}

/* ---------- test doubles ---------- */

var adminKey = auth.Principal{KeyID: "k-1", Name: "alice", Scopes: []string{auth.ScopeAdmin}}

type stubVerifier struct{ valid map[string]auth.Principal }

func (s *stubVerifier) Verify(_ context.Context, raw string) (auth.Principal, bool) {
	p, ok := s.valid[raw]
	return p, ok
}

type stubUsers struct{ rows map[string]userstore.User }

func (s *stubUsers) GetUser(_ context.Context, username string) (userstore.User, error) {
	u, ok := s.rows[username]
	if !ok {
		return userstore.User{}, userstore.ErrNotFound
	}
	return u, nil
}

func (s *stubUsers) UpdatePassword(_ context.Context, username string, hash []byte) (time.Time, error) {
	u := s.rows[username]
	u.PasswordHash = hash
	u.IsDefaultPassword = false
	u.UpdatedAt = u.UpdatedAt.Add(time.Second)
	s.rows[username] = u
	return u.UpdatedAt, nil
}

// missingTableUsers is the un-migrated deployment: every read says the table is not there.
type missingTableUsers struct{}

func (missingTableUsers) GetUser(context.Context, string) (userstore.User, error) {
	return userstore.User{}, userstore.ErrTableMissing
}

func (missingTableUsers) UpdatePassword(context.Context, string, []byte) (time.Time, error) {
	return time.Time{}, userstore.ErrTableMissing
}

func bcryptHash(t *testing.T, password string) []byte {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return h
}
