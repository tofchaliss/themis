package notify

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// StartIntegrationSMTPServer starts a mock SMTP server for cross-package integration tests.
// received reports whether at least one message body was accepted.
func StartIntegrationSMTPServer(t *testing.T) (host string, port int, received func() bool) {
	t.Helper()
	var mailReceived atomic.Bool
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ = strconv.Atoi(portStr)

	go serveIntegrationSMTP(ln, false, &mailReceived)
	return host, port, mailReceived.Load
}

func serveIntegrationSMTP(ln net.Listener, advertiseSTARTTLS bool, received *atomic.Bool) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleIntegrationSMTP(conn, advertiseSTARTTLS, received)
	}
}

func handleIntegrationSMTP(conn net.Conn, advertiseSTARTTLS bool, received *atomic.Bool) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	tlsActive := false
	inData := false
	var data strings.Builder
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
			tlsConn := tls.Server(conn, integrationMockTLSConfig())
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
			inData = true
			data.Reset()
			_, _ = conn.Write([]byte("354 End data with <CR><LF>.<CR><LF>\r\n"))
		case upper == ".":
			if inData {
				received.Store(true)
				inData = false
			}
			_, _ = conn.Write([]byte("250 Message accepted\r\n"))
			return
		case inData:
			data.WriteString(line)
		case upper == "QUIT":
			_, _ = conn.Write([]byte("221 Bye\r\n"))
			return
		default:
			_, _ = conn.Write([]byte("250 OK\r\n"))
		}
	}
}

var generateTestRSAKey = rsa.GenerateKey
var createTestCertificate = x509.CreateCertificate
var parseTestCertificate = x509.ParseCertificate

func integrationMockTLSConfig() *tls.Config {
	key, err := generateTestRSAKey(rand.Reader, 2048)
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
	der, err := createTestCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	cert, err := parseTestCertificate(der)
	if err != nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}},
	}
}
