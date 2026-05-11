package imap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestIMAPAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := NewAuthenticator(func(_ context.Context, _ strategy.Target, cred strategy.Credential) error {
		if cred.Username != "mail" || cred.Password != "secret" {
			t.Fatalf("unexpected credential: %+v", cred)
		}
		return nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "mail.local",
		IP:       "127.0.0.1",
		Port:     143,
		Protocol: "imap",
	}, strategy.Credential{
		Username: "mail",
		Password: "secret",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	if out.Result.Username != "mail" || out.Result.Password != "secret" {
		t.Fatalf("expected credential echo, got %+v", out.Result)
	}
	if out.Result.Evidence != "IMAP authentication succeeded" {
		t.Fatalf("unexpected evidence: %+v", out.Result)
	}
	if out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("unexpected finding type: %+v", out.Result)
	}
}

func TestIMAPAuthenticatorAuthenticateOnceMapsFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want result.ErrorCode
	}{
		{name: "authentication", err: errors.New("a001 NO [AUTHENTICATIONFAILED] invalid credentials"), want: result.ErrorCodeAuthentication},
		{name: "connection", err: errors.New("dial tcp 127.0.0.1:143: connect: connection refused"), want: result.ErrorCodeConnection},
		{name: "starttls required", err: errors.New("a001 NO [PRIVACYREQUIRED] must issue a STARTTLS command first"), want: result.ErrorCodeInsufficientConfirmation},
		{name: "insufficient confirmation", err: errors.New("unexpected imap banner"), want: result.ErrorCodeInsufficientConfirmation},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
				return tt.err
			})

			out := auth.AuthenticateOnce(context.Background(), strategy.Target{
				Host:     "mail.local",
				IP:       "127.0.0.1",
				Port:     143,
				Protocol: "imap",
			}, strategy.Credential{
				Username: "mail",
				Password: "wrong",
			})

			if out.Result.Success {
				t.Fatalf("expected failure, got %+v", out)
			}
			if out.Result.ErrorCode != tt.want {
				t.Fatalf("expected %q, got %+v", tt.want, out)
			}
		})
	}
}

func TestIMAPAuthenticatorAuthenticateOnceUsesPlainTCPOnPort143(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	transcript := make(chan string, 4)
	serverErr := make(chan error, 1)
	go serveIMAP(t, listener, nil, transcript, serverErr)

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "mail.local",
		IP:       "127.0.0.1",
		Port:     listener.Addr().(*net.TCPAddr).Port,
		Protocol: "imap",
	}, strategy.Credential{
		Username: "mail",
		Password: "secret",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}

	loginCmd := <-transcript
	if !strings.Contains(loginCmd, `a001 LOGIN "mail" "secret"`) {
		t.Fatalf("unexpected login command: %q", loginCmd)
	}
	logoutCmd := <-transcript
	if !strings.Contains(logoutCmd, "a002 LOGOUT") {
		t.Fatalf("unexpected logout command: %q", logoutCmd)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	default:
	}
}

func TestIMAPAuthenticatorAuthenticateOnceUsesTLSOnPort993(t *testing.T) {
	cert := mustTestCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("listen tls: %v", err)
	}
	defer listener.Close()

	transcript := make(chan string, 4)
	serverErr := make(chan error, 1)
	go serveIMAP(t, listener, nil, transcript, serverErr)

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "mail.local",
		IP:       "127.0.0.1",
		Port:     listener.Addr().(*net.TCPAddr).Port,
		Protocol: "imaps",
	}, strategy.Credential{
		Username: "mail",
		Password: "secret",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}

	loginCmd := <-transcript
	if !strings.Contains(loginCmd, `a001 LOGIN "mail" "secret"`) {
		t.Fatalf("unexpected login command: %q", loginCmd)
	}
	logoutCmd := <-transcript
	if !strings.Contains(logoutCmd, "a002 LOGOUT") {
		t.Fatalf("unexpected logout command: %q", logoutCmd)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	default:
	}
}

func serveIMAP(t *testing.T, listener net.Listener, _ *tls.Config, transcript chan<- string, serverErr chan<- error) {
	t.Helper()

	conn, err := listener.Accept()
	if err != nil {
		serverErr <- err
		return
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		serverErr <- err
		return
	}
	if _, err := fmt.Fprint(conn, "* OK IMAP4rev1 Service Ready\r\n"); err != nil {
		serverErr <- err
		return
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		serverErr <- err
		return
	}
	loginCmd := string(buf[:n])
	transcript <- loginCmd
	if !strings.Contains(loginCmd, `a001 LOGIN "mail" "secret"`) {
		serverErr <- fmt.Errorf("unexpected login command %q", loginCmd)
		return
	}
	if _, err := fmt.Fprint(conn, "a001 OK LOGIN completed\r\n"); err != nil {
		serverErr <- err
		return
	}

	n, err = conn.Read(buf)
	if err != nil {
		serverErr <- err
		return
	}
	logoutCmd := string(buf[:n])
	transcript <- logoutCmd
	if _, err := fmt.Fprint(conn, "* BYE Logging out\r\na002 OK LOGOUT completed\r\n"); err != nil {
		serverErr <- err
		return
	}
	serverErr <- nil
}

func mustTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	return cert
}
