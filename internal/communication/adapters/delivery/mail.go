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
			if a := strings.TrimSpace(address); a != "" {
				to = append(to, a)
			}
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
	headers := []string{
		"From: " + d.cfg.From,
		"To: " + strings.Join(to, ", "),
		"Subject: " + subject,
		"Date: " + date.UTC().Format(time.RFC1123Z),
		"Message-ID: " + mailMessageID(in.ID),
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

// send runs the SMTP conversation. The dial is context-bounded so an unreachable relay costs a
// timeout and a retry, never a stuck worker goroutine.
func (d *RealMailDeliverer) send(ctx context.Context, to []string, message []byte) error {
	addr := net.JoinHostPort(d.cfg.Host, strconv.Itoa(d.cfg.Port))
	conn, err := (&net.Dialer{Timeout: d.cfg.Timeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("mail: dial %s: %w", addr, err)
	}
	client, err := smtp.NewClient(conn, d.cfg.Host)
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

// isLoopback reports whether the relay is on this machine. It is the one exception to "no
// password without STARTTLS", and it is not a convenience: net/smtp's PLAIN mechanism enforces
// exactly the same rule one layer down (a password goes out unencrypted only to localhost), so a
// non-loopback relay would refuse at send time anyway. Checking it here turns a recurring dead
// letter into one startup message that says what to set.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// mailMessageID derives the stable Message-ID of an intent's one mail.
func mailMessageID(intentID string) string {
	return "<" + intentID + "@" + mailIDDomain + ">"
}
