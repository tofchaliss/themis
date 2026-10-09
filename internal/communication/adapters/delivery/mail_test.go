package delivery_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/adapters/delivery"
	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/app"
)

// --- N-M1b: the real mail sender -------------------------------------------------------------

const smtpPassword = "SMTP-PASSWORD-MUST-NEVER-APPEAR"

// smtpSession is what one delivery looked like from the server's side.
type smtpSession struct {
	from string
	to   []string
	data string
	auth string
	quit bool
}

// testSMTP is a minimal in-process SMTP server: enough of the conversation for net/smtp to
// complete one submission, and a record of what it was told. An in-proc server rather than a
// mocked sender on purpose — "does the audience resolve to these RCPT TOs" is a question only the
// wire can answer.
//
// It deliberately does NOT advertise STARTTLS, which is what lets the "STARTTLS configured but not
// offered" refusal be exercised. The TLS handshake itself is not reachable from a test without a
// trusted certificate, so that one line is the file's honest coverage gap.
type testSMTP struct {
	ln net.Listener

	// rejectRcpt is a recipient the server refuses (a 550), to prove a refusal is an outcome.
	rejectRcpt string
	// rejectData refuses the DATA command.
	rejectData bool
	// stallData accepts the connection and the envelope and then says NOTHING to DATA — the
	// unresponsive relay a dial timeout alone does not cover.
	stallData bool

	mu       sync.Mutex
	sessions []smtpSession
}

func newTestSMTP(t *testing.T) *testSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &testSMTP{ln: ln}
	go s.serve()
	t.Cleanup(s.close)
	return s
}

func (s *testSMTP) close() { _ = s.ln.Close() }

func (s *testSMTP) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *testSMTP) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *testSMTP) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	say := func(line string) {
		_, _ = w.WriteString(line + "\r\n")
		_ = w.Flush()
	}
	say("220 themis-test ESMTP ready")

	var session smtpSession
	record := func() {
		s.mu.Lock()
		s.sessions = append(s.sessions, session)
		s.mu.Unlock()
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(cmd)
		switch {
		case strings.HasPrefix(upper, "EHLO"):
			_, _ = w.WriteString("250-themis-test\r\n250-AUTH PLAIN\r\n250 SIZE 10485760\r\n")
			_ = w.Flush()
		case strings.HasPrefix(upper, "HELO"):
			say("250 themis-test")
		case strings.HasPrefix(upper, "AUTH PLAIN"):
			session.auth = strings.TrimSpace(strings.TrimPrefix(cmd, "AUTH PLAIN"))
			say("235 2.7.0 Authentication successful")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			session.from = smtpAddress(cmd)
			say("250 2.1.0 Ok")
		case strings.HasPrefix(upper, "RCPT TO:"):
			address := smtpAddress(cmd)
			if s.rejectRcpt != "" && address == s.rejectRcpt {
				say("550 5.1.1 No such mailbox")
				continue
			}
			session.to = append(session.to, address)
			say("250 2.1.5 Ok")
		case upper == "DATA":
			if s.stallData {
				<-time.After(30 * time.Second) // far beyond any configured timeout
				return
			}
			if s.rejectData {
				say("554 5.5.1 Refused")
				continue
			}
			say("354 End data with <CR><LF>.<CR><LF>")
			session.data = s.readData(r)
			say("250 2.0.0 Ok: queued")
		case upper == "QUIT":
			session.quit = true
			say("221 2.0.0 Bye")
			record()
			return
		case upper == "RSET", upper == "NOOP":
			say("250 2.0.0 Ok")
		default:
			say("502 5.5.2 Not implemented")
		}
	}
}

// readData consumes the message up to the terminating dot, undoing the dot-stuffing the client's
// writer applies.
func (s *testSMTP) readData(r *bufio.Reader) string {
	var b strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return b.String()
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "." {
			return b.String()
		}
		b.WriteString(strings.TrimPrefix(trimmed, ".") + "\n")
	}
}

func smtpAddress(cmd string) string {
	open := strings.Index(cmd, "<")
	closing := strings.LastIndex(cmd, ">")
	if open < 0 || closing < open {
		return strings.TrimSpace(cmd[strings.Index(cmd, ":")+1:])
	}
	return cmd[open+1 : closing]
}

// only returns the single recorded session, WAITING for the server to record it first.
//
// The wait is the whole point. `record()` runs in the server's own connection goroutine, on QUIT
// (see handle), while DeliverIntent returns as soon as the CLIENT has finished writing — so the two
// are unsynchronised and a test that read s.sessions immediately could observe zero. Measured
// 2026-10-09: TestRealMailDelivererFoldsNewlinesOutOfHeaders failed in CI with `sessions = 0, want
// exactly 1` on a run that took 1m37s, and passed on a re-run of the SAME commit that took 3m15s —
// the FAST run is the one that lost the race. It also passed 30/30 locally, which is why the flake
// reached main: the race only opens when the client finishes unusually early relative to the server.
//
// A sleep would not fix this, it would only move the race. Waiting for the condition does.
func (s *testSMTP) only(t *testing.T) smtpSession {
	t.Helper()
	sessions, ok := s.waitFor(1, 5*time.Second)
	if !ok {
		t.Fatalf("sessions = %d after waiting 5s, want exactly 1", s.count())
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want exactly 1", len(sessions))
	}
	return sessions[0]
}

// waitFor returns a snapshot of the recorded sessions once at least n exist, or false on timeout.
// It polls rather than signalling because the server records from an arbitrary number of
// connection goroutines and a channel would need a capacity nobody can predict.
func (s *testSMTP) waitFor(n int, within time.Duration) ([]smtpSession, bool) {
	deadline := time.Now().Add(within)
	for {
		s.mu.Lock()
		if len(s.sessions) >= n {
			snapshot := append([]smtpSession(nil), s.sessions...)
			s.mu.Unlock()
			return snapshot, true
		}
		s.mu.Unlock()
		if time.Now().After(deadline) {
			return nil, false
		}
		time.Sleep(time.Millisecond)
	}
}

func (s *testSMTP) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// mailConfig is a complete mail configuration against the in-process server.
func mailConfig(port int) delivery.MailConfig {
	return delivery.MailConfig{
		Enabled: true, Host: "127.0.0.1", Port: port, From: "themis@acme.example",
		StartTLS: false, Timeout: 5 * time.Second,
		Audiences: map[string][]string{
			"security-decisions": {"sec@acme.example", "lead@acme.example"},
			"operations":         {"ops@acme.example"},
		},
	}
}

func decisionPayload() []byte {
	return app.BuildPayload("Themis decision - Finding fnd-1 (CVE-2026-0100)",
		[]byte("A proposal about this Finding was ACCEPTED.\n\nFinding: fnd-1\n"))
}

// The happy path through the worker: the governed audience name becomes RCPT TOs, the message
// carries the snapshot body, and the intent is delivered with the recipient count recorded.
func TestRealMailDelivererSendsPlainText(t *testing.T) {
	srv := newTestSMTP(t)

	h := newHarness(t, testConfig())
	mail, err := delivery.NewRealMailDeliverer(mailConfig(srv.port()), h.logger)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	h.withDeliverers(testConfig(), map[app.IntentType]delivery.IntentDeliverer{app.IntentEmail: mail})
	id := h.seedIntent(t, h.pending(app.IntentEmail, "security-decisions", decisionPayload()))

	if n := h.runOnce(t); n != 1 {
		t.Fatalf("delivered %d, want 1", n)
	}
	in := h.intents.get(t, id)
	if in.State != app.IntentDelivered {
		t.Fatalf("state = %s, want delivered", in.State)
	}
	if in.Result["recipients"] != "2" || in.Result["audience"] != "security-decisions" || in.Result["transport"] != "smtp" {
		t.Errorf("result = %v", in.Result)
	}
	if want := "<" + id + "@themis.invalid>"; in.Result["message_id"] != want {
		t.Errorf("message id = %q, want %q (one mail per intent id)", in.Result["message_id"], want)
	}

	session := srv.only(t)
	if session.from != "themis@acme.example" {
		t.Errorf("MAIL FROM = %q", session.from)
	}
	if strings.Join(session.to, ",") != "sec@acme.example,lead@acme.example" {
		t.Errorf("RCPT TO = %v, want the audience's recipients in order", session.to)
	}
	if !session.quit {
		t.Error("the session was not closed with QUIT")
	}
	for _, want := range []string{
		"From: themis@acme.example",
		"To: sec@acme.example, lead@acme.example",
		"Subject: Themis decision - Finding fnd-1 (CVE-2026-0100)",
		"Message-ID: <" + id + "@themis.invalid>",
		"Content-Type: text/plain; charset=utf-8",
		"Auto-Submitted: auto-generated",
		"Date: " + epoch.Format(time.RFC1123Z),
	} {
		if !strings.Contains(session.data, want) {
			t.Errorf("message is missing %q:\n%s", want, session.data)
		}
	}
	// The BODY is the stored payload's body, unchanged: a sender transmits the snapshot.
	_, body := app.SplitPayload(decisionPayload())
	if _, after, ok := strings.Cut(session.data, "\n\n"); !ok || after != string(body) {
		t.Errorf("body = %q, want the materialized payload body %q", after, body)
	}
	// Unauthenticated relay: no AUTH was attempted, so no password could leak.
	if session.auth != "" {
		t.Errorf("AUTH sent to an unauthenticated relay: %q", session.auth)
	}
	h.assertNoSecretsInLogs(t, smtpPassword)
}

// The mail half of the end-to-end path: the intent service materializes the decision notification
// through the real outward serializer and the real sender puts it on the wire — so what a recipient
// reads is checked against what the renderer produced, not against a payload a test invented.
func TestOutwardPathFromDecisionToMail(t *testing.T) {
	srv := newTestSMTP(t)

	h := newHarness(t, testConfig())
	svc := app.NewDeliveryIntentService(h.intents, &seqIDs{}, fixedClock{}, app.DeliveryIntentConfig{}).
		WithPayloadRenderer(serializer.NewOutwardRenderer(nil)) // mail needs no posture read
	mail, err := delivery.NewRealMailDeliverer(mailConfig(srv.port()), h.logger)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	h.withDeliverers(testConfig(), map[app.IntentType]delivery.IntentDeliverer{app.IntentEmail: mail})

	in, err := svc.EnqueueDecisionMail(context.Background(),
		app.IntentLineage{SourceContext: "governance", EventType: "governance.proposal_accepted", EventID: "env-2"},
		"env-2", "prop-1", "fnd-1", "rel-1", "security-decisions",
		map[string]string{"cve": "CVE-2026-0100", "position_version": "2"})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if in.PayloadSHA256 == "" {
		t.Fatal("the intent was recorded without a materialized payload")
	}

	if n := h.runOnce(t); n != 1 {
		t.Fatalf("delivered %d, want 1", n)
	}
	session := srv.only(t)
	for _, want := range []string{
		"Subject: Themis decision - Finding fnd-1 (CVE-2026-0100)",
		"To: sec@acme.example, lead@acme.example",
		"ACCEPTED", "Proposal:         prop-1", "Position version: 2",
		"governance.proposal_accepted (env-2)",
	} {
		if !strings.Contains(session.data, want) {
			t.Errorf("the mail is missing %q:\n%s", want, session.data)
		}
	}
	if got := h.intents.get(t, in.ID).State; got != app.IntentDelivered {
		t.Errorf("state = %s", got)
	}
}

// A retry sends BYTE-IDENTICAL bytes: Date comes from the intent's creation time and Message-ID
// from its id, so a relay can collapse the duplicate a timed-out send may already have delivered.
func TestRealMailDelivererRetrySendsTheSameBytes(t *testing.T) {
	srv := newTestSMTP(t)
	mail, err := delivery.NewRealMailDeliverer(mailConfig(srv.port()), nil) // nil logger must not panic
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	in := app.Intent{
		ID: "int-1", Type: app.IntentEmail, Destination: "operations",
		PayloadBytes: decisionPayload(), CreatedAt: epoch,
	}
	ctx := context.Background()
	if _, err := mail.DeliverIntent(ctx, in); err != nil {
		t.Fatalf("first: %v", err)
	}
	in.Attempts = 1 // a retry of the same intent
	if _, err := mail.DeliverIntent(ctx, in); err != nil {
		t.Fatalf("retry: %v", err)
	}
	// Through waitFor for the same reason only() does: the second session is recorded by the
	// server's goroutine, not by the call that returned above.
	sessions, ok := srv.waitFor(2, 5*time.Second)
	if !ok {
		t.Fatalf("sessions = %d after waiting 5s, want 2", srv.count())
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(sessions))
	}
	if sessions[0].data != sessions[1].data {
		t.Errorf("a retry sent different bytes:\n%s\n---\n%s", sessions[0].data, sessions[1].data)
	}
}

// Authentication on a loopback relay: the credential goes out as PLAIN and NOWHERE else — not into
// the log, not into the attempt ledger.
func TestRealMailDelivererAuthenticates(t *testing.T) {
	srv := newTestSMTP(t)
	cfg := mailConfig(srv.port())
	cfg.Username, cfg.Password = "themis", smtpPassword

	h := newHarness(t, testConfig())
	mail, err := delivery.NewRealMailDeliverer(cfg, h.logger)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	h.withDeliverers(testConfig(), map[app.IntentType]delivery.IntentDeliverer{app.IntentEmail: mail})
	id := h.seedIntent(t, h.pending(app.IntentEmail, "operations", decisionPayload()))

	h.runOnce(t)

	if got := h.intents.get(t, id).State; got != app.IntentDelivered {
		t.Fatalf("state = %s", got)
	}
	session := srv.only(t)
	decoded, err := base64.StdEncoding.DecodeString(session.auth)
	if err != nil {
		t.Fatalf("AUTH payload = %q: %v", session.auth, err)
	}
	if want := "\x00themis\x00" + smtpPassword; string(decoded) != want {
		t.Errorf("AUTH payload = %q", decoded)
	}
	h.assertNoSecretsInLogs(t, smtpPassword)
	if strings.Contains(h.intents.get(t, id).LastError, smtpPassword) {
		t.Error("the password reached the attempt ledger")
	}
}

// Every SMTP refusal is an OUTCOME: recorded, retried, dead-lettered — never a pass failure and
// never a reason for Themis state to move.
func TestRealMailDelivererRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(*testSMTP, *delivery.MailConfig)
		want    string
	}{
		{"recipient refused", func(_ *testSMTP, cfg *delivery.MailConfig) {
			cfg.Audiences["operations"] = []string{"nobody@acme.example"}
		}, "RCPT TO"},
		{"data refused", func(s *testSMTP, _ *delivery.MailConfig) { s.rejectData = true }, "DATA"},
		{"starttls not offered", func(_ *testSMTP, cfg *delivery.MailConfig) { cfg.StartTLS = true }, "no STARTTLS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestSMTP(t)
			srv.rejectRcpt = "nobody@acme.example"
			cfg := mailConfig(srv.port())
			tc.prepare(srv, &cfg)

			workerCfg := testConfig()
			workerCfg.MaxAttempts = 1
			h := newHarness(t, workerCfg)
			mail, err := delivery.NewRealMailDeliverer(cfg, h.logger)
			if err != nil {
				t.Fatalf("configure: %v", err)
			}
			h.withDeliverers(workerCfg, map[app.IntentType]delivery.IntentDeliverer{app.IntentEmail: mail})
			id := h.seedIntent(t, h.pending(app.IntentEmail, "operations", decisionPayload()))

			if _, err := h.worker.RunOnce(context.Background()); err != nil {
				t.Fatalf("a channel refusal is an outcome, not a pass failure: %v", err)
			}
			in := h.intents.get(t, id)
			if in.State != app.IntentDeadLetter {
				t.Errorf("state = %s, want dead_letter", in.State)
			}
			if !strings.Contains(in.LastError, tc.want) {
				t.Errorf("last error = %q, want it to mention %q", in.LastError, tc.want)
			}
		})
	}
}

// An unreachable relay is a retry. A closed listener is the cheapest honest version of one.
func TestRealMailDelivererUnreachable(t *testing.T) {
	srv := newTestSMTP(t)
	port := srv.port()
	srv.close()

	mail, err := delivery.NewRealMailDeliverer(mailConfig(port), nil)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	_, err = mail.DeliverIntent(context.Background(), app.Intent{
		ID: "int-1", Type: app.IntentEmail, Destination: "operations", PayloadBytes: decisionPayload()})
	if err == nil {
		t.Fatal("want a transport error")
	}
	if !strings.Contains(err.Error(), "dial") {
		t.Errorf("err = %v, want it to name the dial", err)
	}
}

// A relay that accepts the connection and then stops answering must TIME OUT, not hang. Bounding
// the dial does not cover this: the connection succeeded. Without a per-operation deadline the
// worker goroutine would block in a read forever, and cfg.Workers such relays would stop the queue
// draining at all.
func TestRealMailDelivererTimesOutOnAnUnresponsiveRelay(t *testing.T) {
	srv := newTestSMTP(t)
	srv.stallData = true
	cfg := mailConfig(srv.port())
	cfg.Timeout = 250 * time.Millisecond

	mail, err := delivery.NewRealMailDeliverer(cfg, nil)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}

	errs := make(chan error, 1)
	go func() {
		_, err := mail.DeliverIntent(context.Background(), app.Intent{
			ID: "int-1", Type: app.IntentEmail, Destination: "operations", PayloadBytes: decisionPayload()})
		errs <- err
	}()
	select {
	case err := <-errs:
		if err == nil {
			t.Fatal("a stalled relay must not read as a successful send")
		}
		if !strings.Contains(err.Error(), "DATA") && !strings.Contains(err.Error(), "timeout") {
			t.Errorf("err = %v, want the stalled step named", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the sender hung on an unresponsive relay instead of timing out")
	}
}

// Cancelling the worker's context ends a conversation in flight, so shutdown is not held up by a
// relay that is still thinking.
func TestRealMailDelivererHonoursContextCancellation(t *testing.T) {
	srv := newTestSMTP(t)
	srv.stallData = true
	cfg := mailConfig(srv.port())
	cfg.Timeout = 30 * time.Second // long enough that only the cancellation can end this

	mail, err := delivery.NewRealMailDeliverer(cfg, nil)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		_, err := mail.DeliverIntent(ctx, app.Intent{
			ID: "int-1", Type: app.IntentEmail, Destination: "operations", PayloadBytes: decisionPayload()})
		errs <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-errs:
		if err == nil {
			t.Fatal("a cancelled send must not read as a successful one")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the sender ignored its context")
	}
}

// Header injection: a CR or LF in a value destined for a header would not produce a malformed
// header, it would produce ADDITIONAL ones. Values are folded at the boundary, so a subject carried
// by an old payload cannot add a Bcc or end the header block early.
func TestRealMailDelivererFoldsNewlinesOutOfHeaders(t *testing.T) {
	srv := newTestSMTP(t)
	mail, err := delivery.NewRealMailDeliverer(mailConfig(srv.port()), nil)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	// A payload whose subject carries CRLF + an injected header, then a blank line: exactly the
	// shape that would split the header block if it were written through unchanged.
	payload := []byte("Subject: innocent\r\nBcc: attacker@evil.example\nX-Injected: 1\n\nthe real body\n")
	if _, err := mail.DeliverIntent(context.Background(), app.Intent{
		ID: "int-1", Type: app.IntentEmail, Destination: "operations",
		PayloadBytes: payload, CreatedAt: epoch,
	}); err != nil {
		t.Fatalf("deliver: %v", err)
	}

	data := srv.only(t).data
	headers, body, ok := strings.Cut(data, "\n\n")
	if !ok {
		t.Fatalf("message has no header/body split:\n%s", data)
	}
	for _, line := range strings.Split(headers, "\n") {
		name, _, _ := strings.Cut(strings.TrimSpace(line), ":")
		switch name {
		case "From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type", "Auto-Submitted":
		default:
			t.Errorf("injected header %q reached the message:\n%s", line, data)
		}
	}
	if !strings.Contains(headers, "Subject: innocent Bcc: attacker@evil.example X-Injected: 1") {
		t.Errorf("the subject was not folded onto one line:\n%s", headers)
	}
	if strings.TrimSpace(body) != "the real body" {
		t.Errorf("body = %q", body)
	}
}

// An address is REFUSED rather than folded: one that cannot be read as an address is a
// configuration mistake, and a repaired one sends security mail somewhere nobody chose.
func TestMailConfigRefusesAddressesWithControlCharacters(t *testing.T) {
	cfg := mailConfig(2525)
	cfg.From = "themis@acme.example\r\nBcc: attacker@evil.example"
	if _, err := delivery.NewRealMailDeliverer(cfg, nil); err == nil {
		t.Error("a From carrying CRLF must be refused")
	} else if !strings.Contains(err.Error(), "THEMIS_COMMUNICATION_MAIL_FROM") {
		t.Errorf("err = %v, want it to name the knob", err)
	}

	// A recipient carrying CRLF is dropped at parse time, which leaves its audience unmapped — and
	// an unmapped audience refuses loudly at send time rather than mailing the injected address.
	got := delivery.ParseAudiences("operations=ops@acme.example\r\nBcc: attacker@evil.example;security-decisions=sec@acme.example")
	if _, ok := got["operations"]; ok {
		t.Errorf("a recipient with a control character must be dropped: %v", got)
	}
	if strings.Join(got["security-decisions"], ",") != "sec@acme.example" {
		t.Errorf("the well-formed audience beside it must survive: %v", got)
	}
}

// An audience with no mapping is REFUSED, never redirected to a default: the wrong people reading
// a security decision is worse than a dead letter an operator can see.
func TestRealMailDelivererRefusesAnUnknownAudience(t *testing.T) {
	srv := newTestSMTP(t)
	mail, err := delivery.NewRealMailDeliverer(mailConfig(srv.port()), nil)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	_, err = mail.DeliverIntent(context.Background(), app.Intent{
		ID: "int-1", Type: app.IntentEmail, Destination: "someone-elses-list", PayloadBytes: decisionPayload()})
	if err == nil {
		t.Fatal("an unmapped audience must be refused")
	}
	if !strings.Contains(err.Error(), "someone-elses-list") || !strings.Contains(err.Error(), "THEMIS_COMMUNICATION_MAIL_AUDIENCES") {
		t.Errorf("err = %v, want the audience and the knob to set", err)
	}
	if srv.count() != 0 {
		t.Error("a refused audience must make no connection")
	}
}

// No materialized payload, no mail (D-N-3): the sender refuses rather than rendering one now.
func TestRealMailDelivererRefusesAnUnrenderedIntent(t *testing.T) {
	srv := newTestSMTP(t)
	mail, err := delivery.NewRealMailDeliverer(mailConfig(srv.port()), nil)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	for _, payload := range [][]byte{nil, []byte("legacy body with no envelope")} {
		if _, err := mail.DeliverIntent(context.Background(), app.Intent{
			ID: "int-1", Type: app.IntentEmail, Destination: "operations", PayloadBytes: payload,
		}); !errors.Is(err, delivery.ErrNoPayload) {
			t.Errorf("payload %q: err = %v, want ErrNoPayload", payload, err)
		}
	}
	if srv.count() != 0 {
		t.Error("an unrendered intent must make no connection")
	}
}

// An intent with no creation time still gets a Date header — from its due time, the only other
// immutable instant it carries. A mail with no Date is rejected by some relays outright.
func TestRealMailDelivererFallsBackToTheDueTimeForDate(t *testing.T) {
	srv := newTestSMTP(t)
	mail, err := delivery.NewRealMailDeliverer(mailConfig(srv.port()), nil)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if _, err := mail.DeliverIntent(context.Background(), app.Intent{
		ID: "int-1", Type: app.IntentEmail, Destination: "operations",
		PayloadBytes: decisionPayload(), NextAttemptAt: epoch,
	}); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if want := "Date: " + epoch.Format(time.RFC1123Z); !strings.Contains(srv.only(t).data, want) {
		t.Errorf("message is missing %q:\n%s", want, srv.only(t).data)
	}
}

func TestParseAudiences(t *testing.T) {
	got := delivery.ParseAudiences(
		" security-decisions = sec@acme.example , lead@acme.example ; operations=ops@acme.example ; " +
			"empty= ; =nobody@acme.example ; malformed")
	if len(got) != 2 {
		t.Fatalf("audiences = %v, want the two well-formed ones", got)
	}
	if strings.Join(got["security-decisions"], ",") != "sec@acme.example,lead@acme.example" {
		t.Errorf("security-decisions = %v", got["security-decisions"])
	}
	if strings.Join(got["operations"], ",") != "ops@acme.example" {
		t.Errorf("operations = %v", got["operations"])
	}
	// An audience with no recipient is omitted, so it REFUSES at send time instead of silently
	// sending nowhere.
	if _, ok := got["empty"]; ok {
		t.Error("an audience with no recipients must be omitted")
	}
	if delivery.ParseAudiences("") != nil {
		t.Error("an empty map must be nil, so the configuration reads as incomplete")
	}
}

// Configuration refusals, at configure time, naming knobs and never values.
func TestMailConfigRefusesIncompleteConfiguration(t *testing.T) {
	complete := mailConfig(2525)
	for _, tc := range []struct {
		name string
		cfg  delivery.MailConfig
		want string
	}{
		{"nothing set", delivery.MailConfig{Enabled: true}, "THEMIS_COMMUNICATION_MAIL_HOST"},
		{"no sender", delivery.MailConfig{Enabled: true, Host: "relay", Audiences: complete.Audiences}, "THEMIS_COMMUNICATION_MAIL_FROM"},
		{"no audiences", delivery.MailConfig{Enabled: true, Host: "relay", From: "a@b"}, "THEMIS_COMMUNICATION_MAIL_AUDIENCES"},
		{
			"a password without STARTTLS to a remote relay",
			delivery.MailConfig{Enabled: true, Host: "relay.acme.example", From: "a@b", Username: "u", Password: smtpPassword, Audiences: complete.Audiences},
			"without STARTTLS",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := delivery.NewRealMailDeliverer(tc.cfg, nil)
			if err == nil {
				t.Fatal("an incomplete configuration must be refused")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
			if strings.Contains(err.Error(), smtpPassword) {
				t.Errorf("err = %v leaked the password", err)
			}
		})
	}

	// Loopback is the one exception, for exactly the reason net/smtp allows it.
	loopback := mailConfig(2525)
	loopback.Username, loopback.Password = "u", smtpPassword
	if _, err := delivery.NewRealMailDeliverer(loopback, nil); err != nil {
		t.Errorf("a loopback relay may authenticate without STARTTLS: %v", err)
	}
	named := loopback
	named.Host = "localhost"
	if _, err := delivery.NewRealMailDeliverer(named, nil); err != nil {
		t.Errorf("localhost by name is loopback too: %v", err)
	}
}

// The mail config's String() is a startup line: audience NAMES and whether a password is set —
// never the password, and never a recipient address (an address list is estate detail).
func TestMailConfigStringHidesThePasswordAndTheRecipients(t *testing.T) {
	cfg := mailConfig(2525)
	cfg.Password = smtpPassword
	got := cfg.String()
	if strings.Contains(got, smtpPassword) {
		t.Fatalf("String() leaked the password: %s", got)
	}
	if strings.Contains(got, "sec@acme.example") {
		t.Errorf("String() leaked a recipient address: %s", got)
	}
	for _, want := range []string{"password=set", "audiences=[operations security-decisions]", "port=2525"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %s, missing %q", got, want)
		}
	}
	if unset := (delivery.MailConfig{}).String(); !strings.Contains(unset, "password=unset") {
		t.Errorf("an unset password must read as unset: %s", unset)
	}
}

// Out-of-range knobs fall back to their documented defaults rather than disabling the sender they
// configure: port 0 is the submission port, timeout 0 is 15s.
func TestMailConfigDefaults(t *testing.T) {
	cfg := delivery.MailConfig{Enabled: true, Host: "relay", From: "a@b",
		Audiences: map[string][]string{"operations": {"ops@acme.example"}}}
	mail, err := delivery.NewRealMailDeliverer(cfg, nil)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	// The defaults are observable through the dial target in the error of an impossible send.
	_, err = mail.DeliverIntent(context.Background(), app.Intent{
		ID: "int-1", Type: app.IntentEmail, Destination: "operations", PayloadBytes: decisionPayload()})
	if err == nil || !strings.Contains(err.Error(), ":"+strconv.Itoa(587)) {
		t.Errorf("err = %v, want the default submission port", err)
	}
}
