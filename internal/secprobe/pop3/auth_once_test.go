package pop3

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

func TestPOP3AuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := NewAuthenticator(func(_ context.Context, _ strategy.Target, cred strategy.Credential) error {
		if cred.Username != "mail" || cred.Password != "secret" {
			t.Fatalf("unexpected credential: %+v", cred)
		}
		return nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "mail.local",
		IP:       "127.0.0.1",
		Port:     110,
		Protocol: "pop3",
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
	if out.Result.Evidence != "POP3 authentication succeeded" {
		t.Fatalf("unexpected evidence: %+v", out.Result)
	}
	if out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("unexpected finding type: %+v", out.Result)
	}
}

func TestPOP3AuthenticatorAuthenticateOnceMapsFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want result.ErrorCode
	}{
		{name: "authentication", err: errors.New("-ERR invalid login or password"), want: result.ErrorCodeAuthentication},
		{name: "connection", err: errors.New("dial tcp 127.0.0.1:110: connect: connection refused"), want: result.ErrorCodeConnection},
		{name: "tls required", err: errors.New("-ERR must use STLS or SSL first"), want: result.ErrorCodeInsufficientConfirmation},
		{name: "timeout", err: context.DeadlineExceeded, want: result.ErrorCodeTimeout},
		{name: "canceled", err: context.Canceled, want: result.ErrorCodeCanceled},
		{name: "insufficient confirmation", err: errors.New("unexpected pop3 banner"), want: result.ErrorCodeInsufficientConfirmation},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
				return tt.err
			})

			out := auth.AuthenticateOnce(context.Background(), strategy.Target{
				Host:     "mail.local",
				IP:       "127.0.0.1",
				Port:     110,
				Protocol: "pop3",
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

func TestPOP3AuthenticatorAuthenticateOnceUsesPlainTCPOnPort110(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	transcript := make(chan string, 4)
	serverErr := make(chan error, 1)
	go servePOP3(t, listener, transcript, serverErr)

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "mail.local",
		IP:       "127.0.0.1",
		Port:     listener.Addr().(*net.TCPAddr).Port,
		Protocol: "pop3",
	}, strategy.Credential{
		Username: "mail",
		Password: "secret",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}

	userCmd := <-transcript
	if !strings.Contains(userCmd, "USER mail\r\n") {
		t.Fatalf("unexpected user command: %q", userCmd)
	}
	passCmd := <-transcript
	if !strings.Contains(passCmd, "PASS secret\r\n") {
		t.Fatalf("unexpected pass command: %q", passCmd)
	}
	quitCmd := <-transcript
	if !strings.Contains(quitCmd, "QUIT\r\n") {
		t.Fatalf("unexpected quit command: %q", quitCmd)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	default:
	}
}

func TestPOP3AuthenticatorAuthenticateOnceUsesTLSOnPort995(t *testing.T) {
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
	go servePOP3(t, listener, transcript, serverErr)

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "mail.local",
		IP:       "127.0.0.1",
		Port:     listener.Addr().(*net.TCPAddr).Port,
		Protocol: "pop3s",
	}, strategy.Credential{
		Username: "mail",
		Password: "secret",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}

	userCmd := <-transcript
	if !strings.Contains(userCmd, "USER mail\r\n") {
		t.Fatalf("unexpected user command: %q", userCmd)
	}
	passCmd := <-transcript
	if !strings.Contains(passCmd, "PASS secret\r\n") {
		t.Fatalf("unexpected pass command: %q", passCmd)
	}
	quitCmd := <-transcript
	if !strings.Contains(quitCmd, "QUIT\r\n") {
		t.Fatalf("unexpected quit command: %q", quitCmd)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	default:
	}
}

func TestPOP3AuthenticatorAuthenticateOnceKeepsSuccessWhenServerClosesAfterPASS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
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
		if _, err := fmt.Fprint(conn, "+OK POP3 server ready\r\n"); err != nil {
			serverErr <- err
			return
		}

		buf := make([]byte, 512)
		if _, err := conn.Read(buf); err != nil {
			serverErr <- err
			return
		}
		if _, err := fmt.Fprint(conn, "+OK user accepted\r\n"); err != nil {
			serverErr <- err
			return
		}

		if _, err := conn.Read(buf); err != nil {
			serverErr <- err
			return
		}
		if _, err := fmt.Fprint(conn, "+OK maildrop locked and ready\r\n"); err != nil {
			serverErr <- err
			return
		}

		// 认证成功后立即断开，模拟服务端不等待 QUIT 收尾。
		serverErr <- nil
	}()

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "mail.local",
		IP:       "127.0.0.1",
		Port:     listener.Addr().(*net.TCPAddr).Port,
		Protocol: "pop3",
	}, strategy.Credential{
		Username: "mail",
		Password: "secret",
	})

	if !out.Result.Success {
		t.Fatalf("expected success even when quit teardown fails, got %+v", out)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	default:
	}
}

func servePOP3(t *testing.T, listener net.Listener, transcript chan<- string, serverErr chan<- error) {
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
	if _, err := fmt.Fprint(conn, "+OK POP3 server ready\r\n"); err != nil {
		serverErr <- err
		return
	}

	buf := make([]byte, 512)

	n, err := conn.Read(buf)
	if err != nil {
		serverErr <- err
		return
	}
	userCmd := string(buf[:n])
	transcript <- userCmd
	if userCmd != "USER mail\r\n" {
		serverErr <- fmt.Errorf("unexpected user command %q", userCmd)
		return
	}
	if _, err := fmt.Fprint(conn, "+OK user accepted\r\n"); err != nil {
		serverErr <- err
		return
	}

	n, err = conn.Read(buf)
	if err != nil {
		serverErr <- err
		return
	}
	passCmd := string(buf[:n])
	transcript <- passCmd
	if passCmd != "PASS secret\r\n" {
		serverErr <- fmt.Errorf("unexpected pass command %q", passCmd)
		return
	}
	if _, err := fmt.Fprint(conn, "+OK maildrop locked and ready\r\n"); err != nil {
		serverErr <- err
		return
	}

	n, err = conn.Read(buf)
	if err != nil {
		serverErr <- err
		return
	}
	quitCmd := string(buf[:n])
	transcript <- quitCmd
	if quitCmd != "QUIT\r\n" {
		serverErr <- fmt.Errorf("unexpected quit command %q", quitCmd)
		return
	}
	if _, err := fmt.Fprint(conn, "+OK dewey POP3 server signing off\r\n"); err != nil {
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
