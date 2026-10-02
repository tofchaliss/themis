package delivery

// mail.go is the REAL mail sender (N-M1b): plain-text SMTP over net/smtp, no attachments, no
// HTML, no third-party client.
//
// GOVERNED AUDIENCES, RESOLVED HERE. An intent carries a NAME ("security-decisions",
// "operations"), never an address — that is what lets the event reader record an obligation
// without knowing who reads it, and it is what keeps addresses out of the durable queue. This
// sender is the one place the name becomes recipients, from an environment-supplied map. An
// audience with no mapping is REFUSED rather than redirected to a default: the wrong people
// receiving a security decision is a worse outcome than a dead letter an operator can see.
//
// ONE MAIL PER INTENT (RC-5). The message is built from the intent's materialized payload and its
// CREATION time, and carries a Message-ID derived from the intent id — so a retry produces
// byte-identical bytes and a receiving relay can collapse the duplicate a timed-out send may have
// already delivered. A retry is a delivery retry, never a second communication.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/platform/observability"
)

const (
	defaultSMTPPort    = 587
	defaultMailTimeout = 15 * time.Second
	// mailIDDomain is the right-hand side of the Message-ID. It is a literal, not the From
	// address's domain, because a Message-ID is an opaque identity and not a routable address.
	mailIDDomain = "themis.invalid"
)

// MailConfig configures the real SMTP sender. The password is SECRET and comes from the
// environment only; the audience map carries addresses, which are configuration rather than
// secrets but are still never written into an intent.
type MailConfig struct {
	// Enabled turns the real sender on. Off (the default) keeps the fake wired: no network.
	Enabled bool
	// Host is the SMTP relay hostname.
	Host string
	// Port is the SMTP port (default 587, the submission port).
	Port int
	// Username is the SMTP account; empty means an unauthenticated relay (common in-estate).
	Username string
	// Password is the SMTP password. SECRET — environment only.
	Password string
	// From is the envelope and header sender address.
	From string
	// StartTLS upgrades the connection before authenticating (default ON). It is only turned off
	// for a relay on a trusted local socket — and with a username set, turning it off would send
	// the password in the clear, which is why the sender refuses that combination.
	StartTLS bool
	// Timeout bounds the connection (default 15s).
	Timeout time.Duration
	// Audiences maps a GOVERNED audience name to its recipients.
	Audiences map[string][]string
}

func mailFromEnv() MailConfig {
	return MailConfig{
		Enabled:   envBool("THEMIS_COMMUNICATION_MAIL_ENABLED", false),
		Host:      getenv("THEMIS_COMMUNICATION_MAIL_HOST"),
		Port:      envInt("THEMIS_COMMUNICATION_MAIL_PORT", defaultSMTPPort),
		Username:  getenv("THEMIS_COMMUNICATION_MAIL_USERNAME"),
		Password:  getenv("THEMIS_COMMUNICATION_MAIL_PASSWORD"),
		From:      getenv("THEMIS_COMMUNICATION_MAIL_FROM"),
		StartTLS:  envBool("THEMIS_COMMUNICATION_MAIL_STARTTLS", true),
		Timeout:   envDuration("THEMIS_COMMUNICATION_MAIL_TIMEOUT", defaultMailTimeout),
		Audiences: ParseAudiences(getenv("THEMIS_COMMUNICATION_MAIL_AUDIENCES")),
	}
}

// ParseAudiences reads the audience map from its environment form:
//
//	security-decisions=sec@acme.example,lead@acme.example;operations=ops@acme.example
//
// Audiences are separated by ";", a name from its recipients by "=", recipients by ",". Blank
// entries and malformed segments are dropped rather than guessed at — a half-parsed address is
// not a recipient — and an audience left with no recipient is omitted, which makes it refuse at
// send time instead of silently sending nowhere.
func ParseAudiences(raw string) map[string][]string {
	out := map[string][]string{}
	for _, group := range strings.Split(raw, ";") {
		name, addresses, ok := strings.Cut(group, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			continue
		}
		var to []string
		for _, address := range strings.Split(addresses, ",") {
			a := strings.TrimSpace(address)
			// A control character in an address is DROPPED, not folded: it would otherwise reach a
			// `To:` header and inject one, and an address that cannot be read as an address is a
			// mistake rather than something to repair silently. Dropping every recipient of an
			// audience leaves the audience unmapped, which the sender refuses loudly.
			if a == "" || hasControlChars(a) {
				continue
			}
			to = append(to, a)
		}
		if len(to) > 0 {
			out[name] = to
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (c MailConfig) withDefaults() MailConfig {
	if c.Port <= 0 {
		c.Port = defaultSMTPPort
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultMailTimeout
	}
	return c
}

// missing lists the environment variables a complete mail configuration needs and this one lacks.
func (c MailConfig) missing() []string {
	var out []string
	if strings.TrimSpace(c.Host) == "" {
		out = append(out, "THEMIS_COMMUNICATION_MAIL_HOST")
	}
	if strings.TrimSpace(c.From) == "" {
		out = append(out, "THEMIS_COMMUNICATION_MAIL_FROM")
	}
	if len(c.Audiences) == 0 {
		out = append(out, "THEMIS_COMMUNICATION_MAIL_AUDIENCES")
	}
	return out
}

// checkAddresses refuses a sender address carrying a control character. ParseAudiences already drops
// such recipients, so this closes the one address that does not come through it — and refusing is
// right where folding would be wrong: a From nobody can read as an address is a configuration
// mistake, and a repaired one would make every mail come from somewhere the operator never chose.
func (c MailConfig) checkAddresses() error {
	if hasControlChars(c.From) {
		return fmt.Errorf("delivery: THEMIS_COMMUNICATION_MAIL_FROM contains a control character — " +
			"a newline in a sender address injects message headers")
	}
	return nil
}

// String renders the mail knobs for a log line: the audience NAMES and whether a password is set
// — never the password, and never the recipient addresses.
func (c MailConfig) String() string {
	names := make([]string, 0, len(c.Audiences))
	for name := range c.Audiences {
		names = append(names, name)
	}
	sort.Strings(names)
	return fmt.Sprintf("enabled=%t host=%q port=%d from=%q starttls=%t username=%q password=%s audiences=%v timeout=%s",
		c.Enabled, c.Host, c.Port, c.From, c.StartTLS, c.Username, secretState(c.Password), names, c.Timeout)
}

// RealMailDeliverer sends one plain-text mail per intent to a governed audience.
type RealMailDeliverer struct {
	cfg    MailConfig
	logger *observability.Logger
}

// NewRealMailDeliverer builds the sender, refusing an incomplete configuration at configure time —
// and refusing authentication without STARTTLS, which would put the password on the wire.
func NewRealMailDeliverer(cfg MailConfig, logger *observability.Logger) (*RealMailDeliverer, error) {
	cfg = cfg.withDefaults()
	if missing := cfg.missing(); len(missing) > 0 {
		return nil, fmt.Errorf("delivery: mail configuration incomplete, unset: %s", strings.Join(missing, ", "))
	}
	if err := cfg.checkAddresses(); err != nil {
		return nil, err
	}
	if cfg.Username != "" && !cfg.StartTLS && !isLoopback(cfg.Host) {
		return nil, fmt.Errorf("delivery: refusing SMTP authentication to %q without STARTTLS — the password would "+
			"cross the network in the clear (set THEMIS_COMMUNICATION_MAIL_STARTTLS=1, or clear "+
			"THEMIS_COMMUNICATION_MAIL_USERNAME for an unauthenticated relay)", cfg.Host)
	}
	if logger == nil {
		logger = observability.Nop()
	}
	return &RealMailDeliverer{cfg: cfg, logger: logger.Component("mail")}, nil
}

// DeliverIntent resolves the intent's audience and sends its materialized payload. The payload is
// never rendered here — an intent without one is refused (ErrNoPayload).
func (d *RealMailDeliverer) DeliverIntent(ctx context.Context, in app.Intent) (Result, error) {
	subject, body := app.SplitPayload(in.PayloadBytes)
	if subject == "" || len(body) == 0 {
		return Result{Excerpt: "mail: no materialized payload"}, ErrNoPayload
	}
	to, ok := d.cfg.Audiences[in.Destination]
	if !ok {
		return Result{Excerpt: "mail: unknown audience"},
			fmt.Errorf("mail: no recipients configured for audience %q (THEMIS_COMMUNICATION_MAIL_AUDIENCES)", in.Destination)
	}

	message := d.message(in, subject, body, to)
	if err := d.send(ctx, to, message); err != nil {
		return Result{Excerpt: excerpt(err.Error())}, err
	}

	messageID := mailMessageID(in.ID)
	d.logger.Info("mail sent",
		observability.String("intent_id", in.ID),
		observability.String("audience", in.Destination),
		observability.Int("recipients", len(to)),
		observability.String("message_id", messageID))
	return Result{
		StatusCode: 250, // SMTP's own "action completed"
		Excerpt:    fmt.Sprintf("mail: accepted for %d recipient(s)", len(to)),
		Metadata: map[string]string{
			"transport":  "smtp",
			"audience":   in.Destination,
			"recipients": strconv.Itoa(len(to)),
			"message_id": messageID,
		},
	}, nil
}

// message builds the RFC 5322 message. Date comes from the intent's CREATION time and Message-ID
// from its id, both immutable — so the bytes of a retry are the bytes of the first attempt, and
// "the same snapshot was delivered" stays true of the envelope as well as the body.
func (d *RealMailDeliverer) message(in app.Intent, subject string, body []byte, to []string) []byte {
	date := in.CreatedAt
	if date.IsZero() {
		date = in.NextAttemptAt
	}
	// Every value is folded before it becomes a header. The subject is the one that could carry a
	// newline today — SplitPayload returns whatever the stored payload holds, and an N-M1a row or a
	// future renderer was never promised to have folded it — and the addresses are refused upstream;
	// folding all of them means no later caller has to know which.
	headers := []string{
		"From: " + sanitizeHeaderValue(d.cfg.From),
		"To: " + sanitizeHeaderValue(strings.Join(to, ", ")),
		"Subject: " + sanitizeHeaderValue(subject),
		"Date: " + date.UTC().Format(time.RFC1123Z),
		"Message-ID: " + sanitizeHeaderValue(mailMessageID(in.ID)),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		// Marks the mail as machine-generated so a recipient's auto-responder does not reply to
		// it — an out-of-office bouncing off a security notification is noise at estate scale.
		"Auto-Submitted: auto-generated",
	}
	var b strings.Builder
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n", "\r\n"))
	return []byte(b.String())
}

// send runs the SMTP conversation. Every step is bounded, so an unreachable OR UNRESPONSIVE relay
// costs a timeout and a retry, never a stuck worker goroutine.
//
// Bounding the dial alone was not enough, and the difference matters: a relay that accepts the
// connection and then says nothing — a stalled or overloaded one, not a hostile one — would leave a
// worker goroutine blocked in a read forever, and `cfg.Workers` such relays would stop the queue
// draining at all. deadlineConn gives every read and write its own deadline, and the context watcher
// closes the connection on shutdown so the worker's own cancellation is honoured mid-conversation.
func (d *RealMailDeliverer) send(ctx context.Context, to []string, message []byte) error {
	addr := net.JoinHostPort(d.cfg.Host, strconv.Itoa(d.cfg.Port))
	conn, err := (&net.Dialer{Timeout: d.cfg.Timeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("mail: dial %s: %w", addr, err)
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close() // unblocks whatever step is in flight; the error surfaces below
		case <-done:
		}
	}()

	client, err := smtp.NewClient(&deadlineConn{Conn: conn, timeout: d.cfg.Timeout}, d.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("mail: greeting from %s: %w", addr, err)
	}
	defer func() { _ = client.Close() }()

	if d.cfg.StartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("mail: %s offers no STARTTLS and THEMIS_COMMUNICATION_MAIL_STARTTLS is on", addr)
		}
		if err := client.StartTLS(&tls.Config{ServerName: d.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("mail: starttls: %w", err)
		}
	}
	if d.cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", d.cfg.Username, d.cfg.Password, d.cfg.Host)); err != nil {
			// The error from net/smtp carries the server's refusal, never the credential.
			return fmt.Errorf("mail: authenticate as %q: %w", d.cfg.Username, err)
		}
	}
	if err := client.Mail(d.cfg.From); err != nil {
		return fmt.Errorf("mail: MAIL FROM: %w", err)
	}
	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("mail: RCPT TO: %w", err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("mail: DATA: %w", err)
	}
	if _, err := w.Write(message); err != nil {
		return fmt.Errorf("mail: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mail: end of body: %w", err)
	}
	return client.Quit()
}

// deadlineConn refreshes the connection's deadline before every read and write, so NO single step of
// the SMTP conversation can exceed the configured timeout.
//
// It wraps the connection rather than setting one deadline for the whole exchange because the two
// are different promises: one deadline for the session would also kill a slow-but-progressing
// transfer of a large message, while a per-operation deadline only ever fires on a step that is
// genuinely not moving. STARTTLS keeps the bound — tls.Client reads and writes THROUGH this wrapper.
type deadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (c *deadlineConn) Read(b []byte) (int, error) {
	if err := c.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Read(b) // c.Conn, not c: c.Read is this method
}

func (c *deadlineConn) Write(b []byte) (int, error) {
	if err := c.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

// mailMessageID derives the stable Message-ID of an intent's one mail.
func mailMessageID(intentID string) string {
	return "<" + intentID + "@" + mailIDDomain + ">"
}
