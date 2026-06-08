package notify

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func startMockSMTPServer(t *testing.T, advertiseSTARTTLS bool) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port = atoi(portStr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMockSMTP(conn, advertiseSTARTTLS)
		}
	}()
	return host, port
}

func handleMockSMTP(conn net.Conn, advertiseSTARTTLS bool) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	tlsActive := false
	_, _ = conn.Write([]byte("220 mock SMTP ready\r\n"))
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		upper := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			if advertiseSTARTTLS && !tlsActive {
				_, _ = conn.Write([]byte("250-mock.local Hello\r\n250-SIZE 1024000\r\n250 STARTTLS\r\n"))
			} else {
				_, _ = conn.Write([]byte("250-mock.local Hello\r\n250 SIZE 1024000\r\n"))
			}
		case upper == "STARTTLS":
			_, _ = conn.Write([]byte("220 Ready to start TLS\r\n"))
			tlsConn := tls.Server(conn, mockTLSConfig())
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			reader = bufio.NewReader(tlsConn)
			conn = tlsConn
			tlsActive = true
		case strings.HasPrefix(upper, "AUTH"):
			_, _ = conn.Write([]byte("235 Authentication successful\r\n"))
		case strings.HasPrefix(upper, "MAIL FROM"):
			_, _ = conn.Write([]byte("250 OK\r\n"))
		case strings.HasPrefix(upper, "RCPT TO"):
			_, _ = conn.Write([]byte("250 OK\r\n"))
		case upper == "DATA":
			_, _ = conn.Write([]byte("354 End data with <CR><LF>.<CR><LF>\r\n"))
		case upper == ".":
			_, _ = conn.Write([]byte("250 Message accepted\r\n"))
			return
		case upper == "QUIT":
			_, _ = conn.Write([]byte("221 Bye\r\n"))
			return
		default:
			_, _ = conn.Write([]byte("250 OK\r\n"))
		}
	}
}

func mockTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mock-smtp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}},
	}
}

func atoi(v string) int {
	var n int
	_, _ = fmt.Sscanf(v, "%d", &n)
	return n
}

func TestSendSMTP(t *testing.T) {
	host, port := startMockSMTPServer(t, false)
	err := sendSMTP(context.Background(), SMTPSettings{
		Host: host, Port: port, From: "alerts@themis.local", UseTLS: false,
	}, "ops@example.com", "subject", "body", (&net.Dialer{}).DialContext)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSendSMTPDirectTLS(t *testing.T) {
	err := sendSMTP(context.Background(), SMTPSettings{
		Host: "127.0.0.1", Port: 465, From: "alerts@themis.local", UseTLS: true,
	}, "ops@example.com", "subject", "body", func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("dial failed")
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSendSMTPUseTLSWithoutExtension(t *testing.T) {
	host, port := startMockSMTPServer(t, false)
	err := sendSMTP(context.Background(), SMTPSettings{
		Host: host, Port: port, From: "alerts@themis.local", UseTLS: true,
	}, "ops@example.com", "subject", "body", (&net.Dialer{}).DialContext)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSendSMTPStartTLS(t *testing.T) {
	host, port := startMockSMTPServer(t, true)
	err := sendSMTP(context.Background(), SMTPSettings{
		Host: host, Port: port, From: "alerts@themis.local", UseTLS: true,
	}, "ops@example.com", "subject", "body", (&net.Dialer{}).DialContext)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSendSMTPWithAuth(t *testing.T) {
	host, port := startMockSMTPServer(t, false)
	err := sendSMTP(context.Background(), SMTPSettings{
		Host: host, Port: port, From: "alerts@themis.local", Username: "user", Password: "pass", UseTLS: false,
	}, "ops@example.com", "subject", "body", (&net.Dialer{}).DialContext)
	if err != nil {
		t.Fatal(err)
	}
}

func startMockSMTPSSLServer(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, mockTLSConfig())
	t.Cleanup(func() { _ = tlsLn.Close() })
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port = atoi(portStr)
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go handleMockSMTP(conn, false)
		}
	}()
	return host, port
}

func TestSendSMTPPort465Branch(t *testing.T) {
	host, port := startMockSMTPServer(t, false)
	orig := smtpTLSDial
	smtpTLSDial = func(ctx context.Context, _, _ string, dial smtpDialer) (net.Conn, error) {
		return dial(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	}
	t.Cleanup(func() { smtpTLSDial = orig })

	err := sendSMTP(context.Background(), SMTPSettings{
		Host: host, Port: 465, From: "alerts@themis.local", UseTLS: true,
	}, "ops@example.com", "subject", "body", (&net.Dialer{}).DialContext)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSendSMTPStartTLSError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		handleMockSMTPBrokenSTARTTLS(conn)
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	err = sendSMTP(context.Background(), SMTPSettings{
		Host: host, Port: atoi(portStr), From: "alerts@themis.local", UseTLS: true,
	}, "ops@example.com", "subject", "body", (&net.Dialer{}).DialContext)
	if err == nil {
		t.Fatal("expected starttls error")
	}
}

func handleMockSMTPBrokenSTARTTLS(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	_, _ = conn.Write([]byte("220 mock SMTP ready\r\n"))
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		upper := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			_, _ = conn.Write([]byte("250-mock.local Hello\r\n250 STARTTLS\r\n"))
		case upper == "STARTTLS":
			_, _ = conn.Write([]byte("454 TLS not available\r\n"))
			return
		default:
			_, _ = conn.Write([]byte("250 OK\r\n"))
		}
	}
}

func TestTLSDialSuccess(t *testing.T) {
	host, port := startMockSMTPSSLServer(t)
	conn, err := tlsDial(context.Background(), fmt.Sprintf("%s:%d", host, port), host, (&net.Dialer{}).DialContext)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func TestSendSMTPAuthFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		handleMockSMTPRejectAuth(conn)
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	err = sendSMTP(context.Background(), SMTPSettings{
		Host: host, Port: atoi(portStr), From: "alerts@themis.local", Username: "user", Password: "bad", UseTLS: false,
	}, "ops@example.com", "subject", "body", (&net.Dialer{}).DialContext)
	if err == nil {
		t.Fatal("expected auth error")
	}
}

func handleMockSMTPRejectAuth(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	_, _ = conn.Write([]byte("220 mock SMTP ready\r\n"))
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		upper := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			_, _ = conn.Write([]byte("250-mock.local Hello\r\n250 SIZE 1024000\r\n"))
		case strings.HasPrefix(upper, "AUTH"):
			_, _ = conn.Write([]byte("535 Authentication failed\r\n"))
			return
		default:
			_, _ = conn.Write([]byte("250 OK\r\n"))
		}
	}
}

func TestSendSMTPRcptFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		handleMockSMTPRejectRcpt(conn)
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	err = sendSMTP(context.Background(), SMTPSettings{
		Host: host, Port: atoi(portStr), From: "alerts@themis.local", UseTLS: false,
	}, "bad@example.com", "subject", "body", (&net.Dialer{}).DialContext)
	if err == nil {
		t.Fatal("expected rcpt error")
	}
}

func handleMockSMTPRejectRcpt(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	_, _ = conn.Write([]byte("220 mock SMTP ready\r\n"))
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		upper := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			_, _ = conn.Write([]byte("250-mock.local Hello\r\n250 SIZE 1024000\r\n"))
		case strings.HasPrefix(upper, "MAIL FROM"):
			_, _ = conn.Write([]byte("250 OK\r\n"))
		case strings.HasPrefix(upper, "RCPT TO"):
			_, _ = conn.Write([]byte("550 No such user\r\n"))
			return
		default:
			_, _ = conn.Write([]byte("250 OK\r\n"))
		}
	}
}

func TestSendSMTPNewClientError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	_ = serverConn.Close()
	err := sendSMTP(context.Background(), SMTPSettings{
		Host: "localhost", Port: 587, From: "alerts@themis.local",
	}, "ops@example.com", "s", "b", func(context.Context, string, string) (net.Conn, error) {
		return clientConn, nil
	})
	if err == nil {
		t.Fatal("expected new client error")
	}
}

func TestTLSDialError(t *testing.T) {
	_, err := tlsDial(context.Background(), "127.0.0.1:1", "localhost", func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("dial failed")
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSendSMTPMissingHost(t *testing.T) {
	err := sendSMTP(context.Background(), SMTPSettings{}, "ops@example.com", "s", "b", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSendSMTPMissingFrom(t *testing.T) {
	err := sendSMTP(context.Background(), SMTPSettings{Host: "localhost", Port: 25}, "ops@example.com", "s", "b", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildSMTPMessage(t *testing.T) {
	msg := buildSMTPMessage("from@x", "to@x", "sub", "hello")
	if !strings.Contains(msg, "Subject: sub") || !strings.Contains(msg, "hello") {
		t.Fatalf("msg=%q", msg)
	}
}

func TestDialContextSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()
	conn, err := dialContext(context.Background(), "tcp", ln.Addr().String(), (&net.Dialer{}).DialContext)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func TestSendSMTPDialError(t *testing.T) {
	err := sendSMTP(context.Background(), SMTPSettings{
		Host: "127.0.0.1", Port: 1, From: "alerts@themis.local",
	}, "ops@example.com", "s", "b", func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("dial failed")
	})
	if err == nil {
		t.Fatal("expected dial error")
	}
}

func TestSendSMTPMailFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		handleMockSMTPRejectMail(conn)
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	err = sendSMTP(context.Background(), SMTPSettings{
		Host: host, Port: atoi(portStr), From: "bad@", UseTLS: false,
	}, "ops@example.com", "s", "b", (&net.Dialer{}).DialContext)
	if err == nil {
		t.Fatal("expected mail error")
	}
}

func handleMockSMTPRejectMail(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	_, _ = conn.Write([]byte("220 mock SMTP ready\r\n"))
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		upper := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			_, _ = conn.Write([]byte("250-mock.local Hello\r\n250 SIZE 1024000\r\n"))
		case strings.HasPrefix(upper, "MAIL FROM"):
			_, _ = conn.Write([]byte("550 Invalid sender\r\n"))
			return
		default:
			_, _ = conn.Write([]byte("250 OK\r\n"))
		}
	}
}

func TestSendSMTPPort465NewClientError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	_ = serverConn.Close()
	orig := smtpTLSDial
	smtpTLSDial = func(context.Context, string, string, smtpDialer) (net.Conn, error) {
		return clientConn, nil
	}
	t.Cleanup(func() { smtpTLSDial = orig })
	err := sendSMTP(context.Background(), SMTPSettings{
		Host: "localhost", Port: 465, From: "alerts@themis.local", UseTLS: true,
	}, "ops@example.com", "s", "b", (&net.Dialer{}).DialContext)
	if err == nil {
		t.Fatal("expected new client error")
	}
}

func TestSendSMTPDataCommandError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		handleMockSMTPRejectData(conn)
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	err = sendSMTP(context.Background(), SMTPSettings{
		Host: host, Port: atoi(portStr), From: "alerts@themis.local", UseTLS: false,
	}, "ops@example.com", "s", "b", (&net.Dialer{}).DialContext)
	if err == nil {
		t.Fatal("expected data error")
	}
}

func handleMockSMTPRejectData(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	_, _ = conn.Write([]byte("220 mock SMTP ready\r\n"))
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		upper := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			_, _ = conn.Write([]byte("250-mock.local Hello\r\n250 SIZE 1024000\r\n"))
		case strings.HasPrefix(upper, "MAIL FROM"), strings.HasPrefix(upper, "RCPT TO"):
			_, _ = conn.Write([]byte("250 OK\r\n"))
		case upper == "DATA":
			_, _ = conn.Write([]byte("554 Transaction failed\r\n"))
			return
		default:
			_, _ = conn.Write([]byte("250 OK\r\n"))
		}
	}
}

func TestSendSMTPWriteError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		handleMockSMTPCloseOnData(conn)
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	err = sendSMTP(context.Background(), SMTPSettings{
		Host: host, Port: atoi(portStr), From: "alerts@themis.local", UseTLS: false,
	}, "ops@example.com", "s", "b", (&net.Dialer{}).DialContext)
	if err == nil {
		t.Fatal("expected write/close error")
	}
}

func handleMockSMTPCloseOnData(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	_, _ = conn.Write([]byte("220 mock SMTP ready\r\n"))
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		upper := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			_, _ = conn.Write([]byte("250-mock.local Hello\r\n250 SIZE 1024000\r\n"))
		case strings.HasPrefix(upper, "MAIL FROM"), strings.HasPrefix(upper, "RCPT TO"):
			_, _ = conn.Write([]byte("250 OK\r\n"))
		case upper == "DATA":
			_, _ = conn.Write([]byte("354 Go ahead\r\n"))
			return
		default:
			_, _ = conn.Write([]byte("250 OK\r\n"))
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("write failed") }
func (failingWriter) Close() error              { return nil }

func TestSMTPDataWriterWriteError(t *testing.T) {
	err := smtpDataWriter(failingWriter{}, []byte("msg"))
	if err == nil {
		t.Fatal("expected write error")
	}
}

func TestDialContextNilDialer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()
	conn, err := dialContext(context.Background(), "tcp", ln.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func TestDialContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := dialContext(ctx, "tcp", "127.0.0.1:1", (&net.Dialer{}).DialContext)
	if err == nil {
		t.Fatal("expected cancel error")
	}
}
