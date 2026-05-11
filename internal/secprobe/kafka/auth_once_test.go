package kafka

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestKafkaAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := NewAuthenticator(func(_ context.Context, _ strategy.Target, cred strategy.Credential) error {
		if cred.Username != "admin" || cred.Password != "secret" {
			t.Fatalf("unexpected credential: %+v", cred)
		}
		return nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "kafka.local",
		IP:       "127.0.0.1",
		Port:     9092,
		Protocol: "kafka",
	}, strategy.Credential{
		Username: "admin",
		Password: "secret",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	if out.Result.Username != "admin" || out.Result.Password != "secret" {
		t.Fatalf("expected credential echo, got %+v", out.Result)
	}
	if out.Result.Evidence != "Kafka SASL authentication succeeded" {
		t.Fatalf("unexpected evidence: %+v", out.Result)
	}
	if out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("unexpected finding type: %+v", out.Result)
	}
}

func TestKafkaAuthenticatorAuthenticateOnceMapsFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want result.ErrorCode
	}{
		{name: "authentication", err: errKafkaAuthenticationFailed, want: result.ErrorCodeAuthentication},
		{name: "unsupported mechanism", err: errKafkaUnsupportedMechanism, want: result.ErrorCodeInsufficientConfirmation},
		{name: "connection", err: errors.New("dial tcp 127.0.0.1:9092: connect: connection refused"), want: result.ErrorCodeConnection},
		{name: "timeout", err: context.DeadlineExceeded, want: result.ErrorCodeTimeout},
		{name: "canceled", err: context.Canceled, want: result.ErrorCodeCanceled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
				return tt.err
			})

			out := auth.AuthenticateOnce(context.Background(), strategy.Target{
				Host:     "kafka.local",
				IP:       "127.0.0.1",
				Port:     9092,
				Protocol: "kafka",
			}, strategy.Credential{
				Username: "admin",
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

func TestKafkaAuthenticatorAuthenticateOnceUsesPlainSASLOnPort9092(t *testing.T) {
	server, cleanup := newTestKafkaServer(t, false)
	defer cleanup()

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "kafka.local",
		IP:       "127.0.0.1",
		Port:     server.port(),
		Protocol: "kafka",
	}, strategy.Credential{
		Username: "admin",
		Password: "secret",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	server.assertAuth(t, "PLAIN", "admin", "secret")
	if server.tlsSeen() {
		t.Fatal("expected plaintext Kafka SASL on port 9092 path")
	}
}

func TestKafkaAuthenticatorAuthenticateOnceUsesTLSOnPort9093(t *testing.T) {
	server, cleanup := newTestKafkaServerAtAddr(t, true, "127.0.0.1:9093")
	defer cleanup()

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "kafka.local",
		IP:       "127.0.0.1",
		Port:     9093,
		Protocol: "kafka",
	}, strategy.Credential{
		Username: "admin",
		Password: "secret",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	server.assertAuth(t, "PLAIN", "admin", "secret")
	if !server.tlsSeen() {
		t.Fatal("expected TLS Kafka SASL on port 9093 path")
	}
}

type testKafkaServer struct {
	listener   net.Listener
	handshakes chan string
	auths      chan strategy.Credential
	tlsConn    chan bool
}

func newTestKafkaServer(t *testing.T, useTLS bool) (*testKafkaServer, func()) {
	return newTestKafkaServerAtAddr(t, useTLS, "127.0.0.1:0")
}

func newTestKafkaServerAtAddr(t *testing.T, useTLS bool, addr string) (*testKafkaServer, func()) {
	t.Helper()

	var (
		listener net.Listener
		err      error
	)
	if useTLS {
		cert := mustKafkaTestCertificate(t)
		listener, err = tls.Listen("tcp", addr, &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
	} else {
		listener, err = net.Listen("tcp", addr)
	}
	if err != nil {
		t.Skipf("listen %s: %v", addr, err)
	}

	server := &testKafkaServer{
		listener:   listener,
		handshakes: make(chan string, 1),
		auths:      make(chan strategy.Credential, 1),
		tlsConn:    make(chan bool, 1),
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

		handshakeReq, err := readKafkaRequest(conn)
		if err != nil {
			return
		}
		if handshakeReq.apiKey != 17 {
			return
		}
		mechanism, err := decodeKafkaString(handshakeReq.body)
		if err != nil {
			return
		}
		server.handshakes <- mechanism
		if err := writeKafkaResponse(conn, handshakeReq.correlationID, buildHandshakeResponseBody(0, []string{"PLAIN"})); err != nil {
			return
		}

		authReq, err := readKafkaRequest(conn)
		if err != nil {
			return
		}
		if authReq.apiKey != 36 {
			return
		}
		authBytes, err := decodeKafkaBytes(authReq.body)
		if err != nil {
			return
		}
		username, password, err := decodeKafkaPlainToken(authBytes)
		if err != nil {
			return
		}
		server.auths <- strategy.Credential{Username: username, Password: password}
		_ = writeKafkaResponse(conn, authReq.correlationID, buildAuthenticateResponseBody(0, "", nil))
	}()

	return server, func() {
		_ = listener.Close()
	}
}

func (s *testKafkaServer) port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

func (s *testKafkaServer) assertAuth(t *testing.T, mechanism, username, password string) {
	t.Helper()

	select {
	case gotMechanism := <-s.handshakes:
		if gotMechanism != mechanism {
			t.Fatalf("unexpected mechanism: %q", gotMechanism)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for sasl handshake")
	}

	select {
	case got := <-s.auths:
		if got.Username != username || got.Password != password {
			t.Fatalf("unexpected auth credential: %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for sasl auth")
	}
}

func (s *testKafkaServer) tlsSeen() bool {
	select {
	case got := <-s.tlsConn:
		return got
	case <-time.After(5 * time.Second):
		return false
	}
}

type kafkaTestRequest struct {
	apiKey        int16
	apiVersion    int16
	correlationID int32
	clientID      string
	body          []byte
}

func readKafkaRequest(r io.Reader) (kafkaTestRequest, error) {
	payload, err := readKafkaTestFrame(r)
	if err != nil {
		return kafkaTestRequest{}, err
	}
	if len(payload) < 10 {
		return kafkaTestRequest{}, io.ErrUnexpectedEOF
	}

	req := kafkaTestRequest{
		apiKey:        int16(binary.BigEndian.Uint16(payload[0:2])),
		apiVersion:    int16(binary.BigEndian.Uint16(payload[2:4])),
		correlationID: int32(binary.BigEndian.Uint32(payload[4:8])),
	}

	clientID, rest, err := readKafkaTestStringField(payload[8:])
	if err != nil {
		return kafkaTestRequest{}, err
	}
	req.clientID = clientID
	req.body = rest
	return req, nil
}

func writeKafkaResponse(w io.Writer, correlationID int32, body []byte) error {
	payload := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(payload, uint32(correlationID))
	payload = append(payload, body...)

	frame := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	frame = append(frame, payload...)
	_, err := w.Write(frame)
	return err
}

func buildHandshakeResponseBody(errorCode int16, mechanisms []string) []byte {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, uint16(errorCode))
	body = appendKafkaStringArray(body, mechanisms)
	return body
}

func buildAuthenticateResponseBody(errorCode int16, message string, authBytes []byte) []byte {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, uint16(errorCode))
	body = appendKafkaNullableString(body, message)
	body = appendKafkaBytes(body, authBytes)
	return body
}

func decodeKafkaString(data []byte) (string, error) {
	value, _, err := readKafkaTestStringField(data)
	return value, err
}

func decodeKafkaBytes(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, io.ErrUnexpectedEOF
	}
	length := int(int32(binary.BigEndian.Uint32(data[:4])))
	if length < 0 || len(data) < 4+length {
		return nil, io.ErrUnexpectedEOF
	}
	return append([]byte(nil), data[4:4+length]...), nil
}

func decodeKafkaPlainToken(token []byte) (string, string, error) {
	parts := splitKafkaPlainToken(token)
	if len(parts) != 3 {
		return "", "", errors.New("invalid sasl plain token")
	}
	return string(parts[1]), string(parts[2]), nil
}

func splitKafkaPlainToken(token []byte) [][]byte {
	parts := make([][]byte, 0, 3)
	start := 0
	for i, b := range token {
		if b != 0 {
			continue
		}
		parts = append(parts, append([]byte(nil), token[start:i]...))
		start = i + 1
	}
	parts = append(parts, append([]byte(nil), token[start:]...))
	return parts
}

func readKafkaTestFrame(r io.Reader) ([]byte, error) {
	var sizeBuf [4]byte
	if _, err := io.ReadFull(r, sizeBuf[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint32(sizeBuf[:]))
	if size < 0 {
		return nil, errors.New("negative kafka frame size")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func readKafkaTestStringField(data []byte) (string, []byte, error) {
	if len(data) < 2 {
		return "", nil, io.ErrUnexpectedEOF
	}
	length := int(int16(binary.BigEndian.Uint16(data[:2])))
	if length < 0 || len(data) < 2+length {
		return "", nil, io.ErrUnexpectedEOF
	}
	return string(data[2 : 2+length]), data[2+length:], nil
}

func appendKafkaStringArray(dst []byte, values []string) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(len(values)))
	dst = append(dst, buf...)
	for _, value := range values {
		dst = appendKafkaString(dst, value)
	}
	return dst
}

func appendKafkaString(dst []byte, value string) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(value)))
	dst = append(dst, buf...)
	return append(dst, value...)
}

func appendKafkaNullableString(dst []byte, value string) []byte {
	if value == "" {
		return append(dst, 0xff, 0xff)
	}
	return appendKafkaString(dst, value)
}

func appendKafkaBytes(dst, value []byte) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(len(value)))
	dst = append(dst, buf...)
	return append(dst, value...)
}

func mustKafkaTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "kafka.local",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"kafka.local"},
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
