package ldap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestLDAPAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := NewAuthenticator(func(_ context.Context, _ strategy.Target, cred strategy.Credential) error {
		if cred.Username != "cn=admin,dc=example,dc=com" || cred.Password != "secret" {
			t.Fatalf("unexpected credential: %+v", cred)
		}
		return nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "ldap.local",
		IP:       "127.0.0.1",
		Port:     389,
		Protocol: "ldap",
	}, strategy.Credential{
		Username: "cn=admin,dc=example,dc=com",
		Password: "secret",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	if out.Result.Username != "cn=admin,dc=example,dc=com" || out.Result.Password != "secret" {
		t.Fatalf("expected credential echo, got %+v", out.Result)
	}
	if out.Result.Evidence != "LDAP bind authentication succeeded" {
		t.Fatalf("unexpected evidence: %+v", out.Result)
	}
	if out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("unexpected finding type: %+v", out.Result)
	}
}

func TestLDAPAuthenticatorAuthenticateOnceMapsFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want result.ErrorCode
	}{
		{name: "authentication", err: errLDAPAuthenticationFailed},
		{name: "invalid credentials", err: errors.New("LDAP Result Code 49 \"Invalid Credentials\": 80090308"), want: result.ErrorCodeAuthentication},
		{name: "connection", err: errors.New("dial tcp 127.0.0.1:389: connect: connection refused"), want: result.ErrorCodeConnection},
		{name: "confirmation insufficient", err: errors.New("ldap strong(er) authentication required"), want: result.ErrorCodeInsufficientConfirmation},
		{name: "timeout", err: context.DeadlineExceeded, want: result.ErrorCodeTimeout},
		{name: "canceled", err: context.Canceled, want: result.ErrorCodeCanceled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.want
			if want == "" {
				want = result.ErrorCodeAuthentication
			}

			auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
				return tt.err
			})

			out := auth.AuthenticateOnce(context.Background(), strategy.Target{
				Host:     "ldap.local",
				IP:       "127.0.0.1",
				Port:     389,
				Protocol: "ldap",
			}, strategy.Credential{
				Username: "cn=admin,dc=example,dc=com",
				Password: "wrong",
			})

			if out.Result.Success {
				t.Fatalf("expected failure, got %+v", out)
			}
			if out.Result.ErrorCode != want {
				t.Fatalf("expected %q, got %+v", want, out)
			}
		})
	}
}

func TestLDAPAuthenticatorAuthenticateOnceUsesPlainBindOnPort389(t *testing.T) {
	server, cleanup := newTestLDAPServer(t, false)
	defer cleanup()

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "ldap.local",
		IP:       "127.0.0.1",
		Port:     server.port(),
		Protocol: "ldap",
	}, strategy.Credential{
		Username: "cn=admin,dc=example,dc=com",
		Password: "secret",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	server.assertBind(t, "cn=admin,dc=example,dc=com", "secret")
	if server.tlsSeen() {
		t.Fatal("expected plain LDAP on port 389 path")
	}
}

func TestLDAPAuthenticatorAuthenticateOnceUsesTLSOnPort636(t *testing.T) {
	server, cleanup := newTestLDAPServerAtAddr(t, true, "127.0.0.1:636")
	defer cleanup()

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "ldap.local",
		IP:       "127.0.0.1",
		Port:     636,
		Protocol: "ldap",
	}, strategy.Credential{
		Username: "cn=admin,dc=example,dc=com",
		Password: "secret",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	server.assertBind(t, "cn=admin,dc=example,dc=com", "secret")
	if !server.tlsSeen() {
		t.Fatal("expected LDAPS on port 636 path")
	}
}

func TestLDAPAuthenticatorAuthenticateOnceUsesTLSForLDAPSProtocol(t *testing.T) {
	server, cleanup := newTestLDAPServer(t, true)
	defer cleanup()

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "ldap.local",
		IP:       "127.0.0.1",
		Port:     server.port(),
		Protocol: "ldaps",
	}, strategy.Credential{
		Username: "cn=service,dc=example,dc=com",
		Password: "secret",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	server.assertBind(t, "cn=service,dc=example,dc=com", "secret")
	if !server.tlsSeen() {
		t.Fatal("expected LDAPS when protocol is ldaps")
	}
}

type testLDAPServer struct {
	listener net.Listener
	binds    chan strategy.Credential
	tlsConn  chan bool
}

func newTestLDAPServer(t *testing.T, useTLS bool) (*testLDAPServer, func()) {
	return newTestLDAPServerAtAddr(t, useTLS, "127.0.0.1:0")
}

func newTestLDAPServerAtAddr(t *testing.T, useTLS bool, addr string) (*testLDAPServer, func()) {
	t.Helper()

	var (
		listener net.Listener
		err      error
	)
	if useTLS {
		cert := mustLDAPTestCertificate(t)
		listener, err = tls.Listen("tcp", addr, &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
	} else {
		listener, err = net.Listen("tcp", addr)
	}
	if err != nil {
		t.Skipf("listen %s: %v", addr, err)
	}

	server := &testLDAPServer{
		listener: listener,
		binds:    make(chan strategy.Credential, 1),
		tlsConn:  make(chan bool, 1),
	}

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		if tlsConn, ok := conn.(*tls.Conn); ok {
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			server.tlsConn <- true
		} else {
			server.tlsConn <- false
		}

		username, password, err := readLDAPSimpleBind(conn)
		if err != nil {
			return
		}
		server.binds <- strategy.Credential{Username: username, Password: password}
		_, _ = conn.Write(successBindResponse())
	}()

	return server, func() {
		_ = listener.Close()
	}
}

func (s *testLDAPServer) port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

func (s *testLDAPServer) assertBind(t *testing.T, username, password string) {
	t.Helper()

	select {
	case got := <-s.binds:
		if got.Username != username || got.Password != password {
			t.Fatalf("unexpected bind credential: %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for bind")
	}
}

func (s *testLDAPServer) tlsSeen() bool {
	select {
	case got := <-s.tlsConn:
		return got
	case <-time.After(5 * time.Second):
		return false
	}
}

func mustLDAPTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "ldap.local",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"ldap.local"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("x509 key pair: %v", err)
	}
	return cert
}
