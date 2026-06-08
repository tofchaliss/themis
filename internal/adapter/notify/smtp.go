package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
)

const channelTypeEmail = "email"

// SMTPSettings configures outbound email delivery.
type SMTPSettings struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	UseTLS   bool
}

type smtpDialer func(ctx context.Context, network, address string) (net.Conn, error)

var smtpTLSDial = tlsDial

func sendSMTP(ctx context.Context, settings SMTPSettings, to, subject, body string, dial smtpDialer) error {
	if settings.Host == "" {
		return fmt.Errorf("smtp host not configured")
	}
	if settings.From == "" {
		return fmt.Errorf("smtp from address not configured")
	}
	addr := fmt.Sprintf("%s:%d", settings.Host, settings.Port)
	message := buildSMTPMessage(settings.From, to, subject, body)

	var client *smtp.Client
	if settings.UseTLS && settings.Port == 465 {
		conn, err := smtpTLSDial(ctx, addr, settings.Host, dial)
		if err != nil {
			return err
		}
		client, err = smtp.NewClient(conn, settings.Host)
		if err != nil {
			_ = conn.Close()
			return err
		}
	} else {
		conn, err := dialContext(ctx, "tcp", addr, dial)
		if err != nil {
			return err
		}
		client, err = smtp.NewClient(conn, settings.Host)
		if err != nil {
			_ = conn.Close()
			return err
		}
		if settings.UseTLS {
			if err := startTLS(client, settings.Host); err != nil {
				_ = client.Close()
				return err
			}
		}
	}
	defer func() { _ = client.Close() }()

	if settings.Username != "" {
		auth := smtp.PlainAuth("", settings.Username, settings.Password, settings.Host)
		if err := client.Auth(auth); err != nil {
			return err
		}
	}
	if err := client.Mail(settings.From); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	return writeSMTPData(client, []byte(message))
}

var writeSMTPData = func(client *smtp.Client, message []byte) error {
	writer, err := client.Data()
	if err != nil {
		return err
	}
	return smtpDataWriter(writer, message)
}

var smtpDataWriter = func(writer interface {
	Write([]byte) (int, error)
	Close() error
}, message []byte) error {
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return err
	}
	return writer.Close()
}

func startTLS(client *smtp.Client, host string) error {
	ok, _ := client.Extension("STARTTLS")
	if !ok {
		return nil
	}
	return client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true})
}

func buildSMTPMessage(from, to, subject, body string) string {
	headers := []string{
		fmt.Sprintf("From: %s", from),
		fmt.Sprintf("To: %s", to),
		fmt.Sprintf("Subject: %s", subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + body + "\r\n"
}

func tlsDial(ctx context.Context, addr, serverName string, dial smtpDialer) (net.Conn, error) {
	conn, err := dialContext(ctx, "tcp", addr, dial)
	if err != nil {
		return nil, err
	}
	return tls.Client(conn, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}), nil
}

func dialContext(ctx context.Context, network, address string, dial smtpDialer) (net.Conn, error) {
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	type dialResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan dialResult, 1)
	go func() {
		conn, err := dial(ctx, network, address)
		ch <- dialResult{conn: conn, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-ch:
		return result.conn, result.err
	}
}
