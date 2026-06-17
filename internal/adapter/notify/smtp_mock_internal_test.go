package notify

import (
	"bufio"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func startMockSMTP(t *testing.T, advertiseSTARTTLS bool) (host string, port int, received func() bool) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mailReceived atomic.Bool
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ = strconv.Atoi(portStr)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleIntegrationSMTP(conn, advertiseSTARTTLS, &mailReceived)
		}
	}()
	return host, port, mailReceived.Load
}

func TestHandleIntegrationSMTPPlainSession(t *testing.T) {
	host, port, received := startMockSMTP(t, false)
	conn := dialSMTP(t, host, port)
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	readLine(t, reader)

	for _, cmd := range []string{
		"HELO test\r\n",
		"AUTH PLAIN dummy\r\n",
		"MAIL FROM:<a@b.com>\r\n",
		"RCPT TO:<c@d.com>\r\n",
	} {
		writeLine(t, conn, cmd)
		readLine(t, reader)
	}
	writeLine(t, conn, "DATA\r\n")
	readLine(t, reader)
	writeLine(t, conn, "line one\r\n")
	writeLine(t, conn, "line two\r\n")
	writeLine(t, conn, ".\r\n")
	readLine(t, reader)
	waitReceived(t, received)
}

func TestHandleIntegrationSMTPWithSTARTTLS(t *testing.T) {
	host, port, received := startMockSMTP(t, true)
	conn := dialSMTP(t, host, port)
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	readLine(t, reader)

	writeLine(t, conn, "EHLO test\r\n")
	for i := 0; i < 3; i++ {
		readLine(t, reader)
	}
	writeLine(t, conn, "STARTTLS\r\n")
	readLine(t, reader)

	tlsConn := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	reader = bufio.NewReader(tlsConn)
	writeLine(t, tlsConn, "EHLO test\r\n")
	readLine(t, reader)
	writeLine(t, tlsConn, "MAIL FROM:<a@b.com>\r\n")
	readLine(t, reader)
	writeLine(t, tlsConn, "RCPT TO:<c@d.com>\r\n")
	readLine(t, reader)
	writeLine(t, tlsConn, "DATA\r\n")
	readLine(t, reader)
	writeLine(t, tlsConn, "body\r\n.\r\n")
	readLine(t, reader)
	waitReceived(t, received)
}

func TestHandleIntegrationSMTPQuit(t *testing.T) {
	host, port, _ := startMockSMTP(t, false)
	conn := dialSMTP(t, host, port)
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	readLine(t, reader)
	writeLine(t, conn, "QUIT\r\n")
	readLine(t, reader)
}

func TestHandleIntegrationSMTPDefaultCommand(t *testing.T) {
	host, port, _ := startMockSMTP(t, false)
	conn := dialSMTP(t, host, port)
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	readLine(t, reader)
	writeLine(t, conn, "NOOP\r\n")
	readLine(t, reader)
	writeLine(t, conn, "QUIT\r\n")
	readLine(t, reader)
}

func TestIntegrationMockTLSConfig(t *testing.T) {
	if cfg := integrationMockTLSConfig(); cfg == nil || cfg.MinVersion == 0 {
		t.Fatal("expected tls config")
	}
}

func TestIntegrationMockTLSConfigFallbacks(t *testing.T) {
	origKey := generateTestRSAKey
	origCreate := createTestCertificate
	origParse := parseTestCertificate
	t.Cleanup(func() {
		generateTestRSAKey = origKey
		createTestCertificate = origCreate
		parseTestCertificate = origParse
	})

	generateTestRSAKey = func(io.Reader, int) (*rsa.PrivateKey, error) {
		return nil, errors.New("key generation failed")
	}
	if cfg := integrationMockTLSConfig(); !cfg.InsecureSkipVerify {
		t.Fatal("expected insecure fallback config")
	}

	generateTestRSAKey = origKey
	createTestCertificate = func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error) {
		return nil, errors.New("create cert failed")
	}
	if cfg := integrationMockTLSConfig(); cfg.MinVersion != tls.VersionTLS12 || len(cfg.Certificates) != 0 {
		t.Fatal("expected minimal tls config")
	}

	createTestCertificate = origCreate
	parseTestCertificate = func([]byte) (*x509.Certificate, error) {
		return nil, errors.New("parse cert failed")
	}
	if cfg := integrationMockTLSConfig(); cfg.MinVersion != tls.VersionTLS12 || len(cfg.Certificates) != 0 {
		t.Fatal("expected parse fallback config")
	}
}

func TestHandleIntegrationSMTPClientDisconnect(t *testing.T) {
	host, port, _ := startMockSMTP(t, false)
	conn := dialSMTP(t, host, port)
	reader := bufio.NewReader(conn)
	readLine(t, reader)
	_ = conn.Close()
	time.Sleep(50 * time.Millisecond)
}

func TestHandleIntegrationSMTPSTARTTLSHandshakeFailure(t *testing.T) {
	host, port, _ := startMockSMTP(t, true)
	conn := dialSMTP(t, host, port)
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	readLine(t, reader)
	writeLine(t, conn, "EHLO test\r\n")
	for i := 0; i < 3; i++ {
		readLine(t, reader)
	}
	writeLine(t, conn, "STARTTLS\r\n")
	readLine(t, reader)
	_, _ = conn.Write([]byte("not-a-tls-handshake\r\n"))
	time.Sleep(50 * time.Millisecond)
}

func TestStartIntegrationSMTPServerAcceptLoopEnds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mailReceived atomic.Bool
	done := make(chan struct{})
	go func() {
		serveIntegrationSMTP(ln, false, &mailReceived)
		close(done)
	}()
	_ = ln.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("accept loop did not exit")
	}
}

func TestStartIntegrationSMTPServerReceivesMail(t *testing.T) {
	host, port, received := StartIntegrationSMTPServer(t)
	conn, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{
		"EHLO test\r\n",
		"MAIL FROM:<alerts@themis.local>\r\n",
		"RCPT TO:<ops@example.com>\r\n",
		"DATA\r\n",
		"Subject: test\r\n\r\nhello\r\n.\r\n",
		"QUIT\r\n",
	} {
		if _, err := conn.Write([]byte(cmd)); err != nil {
			t.Fatal(err)
		}
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
	}

	waitReceived(t, received)
}

func dialSMTP(t *testing.T, host string, port int) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func writeLine(t *testing.T, conn net.Conn, line string) {
	t.Helper()
	if _, err := conn.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
}

func readLine(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func waitReceived(t *testing.T, received func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if received() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("expected message to be received")
}

func TestStartIntegrationSMTPServerListenError(t *testing.T) {
	originalListen := integrationSMTPListen
	integrationSMTPListen = func() (net.Listener, error) {
		return nil, errors.New("listen failed")
	}
	t.Cleanup(func() { integrationSMTPListen = originalListen })

	t.Run("skip", func(t *testing.T) {
		StartIntegrationSMTPServer(t)
	})
	if _, _, _, err := startIntegrationSMTPServer(t); err == nil {
		t.Fatal("expected listen error")
	}
}
