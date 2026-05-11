package activemq

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestActiveMQAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := NewAuthenticator(func(_ context.Context, _ strategy.Target, cred strategy.Credential) error {
		if cred.Username != "admin" || cred.Password != "secret" {
			t.Fatalf("unexpected credential: %+v", cred)
		}
		return nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "mq.local",
		IP:       "127.0.0.1",
		Port:     61613,
		Protocol: "activemq",
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
	if out.Result.Evidence != "ActiveMQ STOMP authentication succeeded" {
		t.Fatalf("unexpected evidence: %+v", out.Result)
	}
	if out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("unexpected finding type: %+v", out.Result)
	}
}

func TestActiveMQAuthenticatorAuthenticateOnceMapsFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want result.ErrorCode
	}{
		{name: "authentication", err: errActiveMQAuthenticationFailed, want: result.ErrorCodeAuthentication},
		{name: "connection", err: errors.New("dial tcp 127.0.0.1:61613: connect: connection refused"), want: result.ErrorCodeConnection},
		{name: "timeout", err: context.DeadlineExceeded, want: result.ErrorCodeTimeout},
		{name: "canceled", err: context.Canceled, want: result.ErrorCodeCanceled},
		{name: "insufficient confirmation", err: errors.New("stomp broker returned receipt without connected frame"), want: result.ErrorCodeInsufficientConfirmation},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
				return tt.err
			})

			out := auth.AuthenticateOnce(context.Background(), strategy.Target{
				Host:     "mq.local",
				IP:       "127.0.0.1",
				Port:     61613,
				Protocol: "activemq",
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

func TestActiveMQAuthenticatorAuthenticateOnceUsesSTOMPConnect(t *testing.T) {
	server, cleanup := newTestSTOMPServer(t, func(frame testSTOMPFrame) testSTOMPFrame {
		if frame.command != "STOMP" {
			t.Fatalf("expected STOMP command, got %q", frame.command)
		}
		if got := frame.headers["login"]; got != "admin" {
			t.Fatalf("expected login header, got %q", got)
		}
		if got := frame.headers["passcode"]; got != "secret" {
			t.Fatalf("expected passcode header, got %q", got)
		}
		if got := frame.headers["accept-version"]; !strings.Contains(got, "1.2") {
			t.Fatalf("expected accept-version header, got %q", got)
		}
		return testSTOMPFrame{
			command: "CONNECTED",
			headers: map[string]string{
				"version": "1.2",
			},
		}
	})
	defer cleanup()

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "mq.local",
		IP:       "127.0.0.1",
		Port:     server.port(),
		Protocol: "activemq",
	}, strategy.Credential{
		Username: "admin",
		Password: "secret",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
}

func TestActiveMQAuthenticatorAuthenticateOnceRealAuthenticationFailure(t *testing.T) {
	server, cleanup := newTestSTOMPServer(t, func(frame testSTOMPFrame) testSTOMPFrame {
		if frame.headers["login"] != "admin" || frame.headers["passcode"] != "wrong" {
			t.Fatalf("unexpected credential: %+v", frame.headers)
		}
		return testSTOMPFrame{
			command: "ERROR",
			headers: map[string]string{"message": "Authentication failed"},
			body:    "invalid credentials",
		}
	})
	defer cleanup()

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "mq.local",
		IP:       "127.0.0.1",
		Port:     server.port(),
		Protocol: "activemq",
	}, strategy.Credential{
		Username: "admin",
		Password: "wrong",
	})

	if out.Result.Success {
		t.Fatalf("expected failure, got %+v", out)
	}
	if out.Result.ErrorCode != result.ErrorCodeAuthentication {
		t.Fatalf("expected authentication failure, got %+v", out.Result)
	}
}

func TestActiveMQAuthenticatorAuthenticateOnceReturnsTimeoutOnDeadline(t *testing.T) {
	server, cleanup := newTestSTOMPServer(t, func(frame testSTOMPFrame) testSTOMPFrame {
		time.Sleep(200 * time.Millisecond)
		return testSTOMPFrame{command: "CONNECTED", headers: map[string]string{"version": "1.2"}}
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	out := NewAuthenticator(nil).AuthenticateOnce(ctx, strategy.Target{
		Host:     "mq.local",
		IP:       "127.0.0.1",
		Port:     server.port(),
		Protocol: "activemq",
	}, strategy.Credential{
		Username: "admin",
		Password: "secret",
	})

	if out.Result.Success {
		t.Fatalf("expected timeout failure, got %+v", out)
	}
	if out.Result.ErrorCode != result.ErrorCodeTimeout {
		t.Fatalf("expected timeout, got %+v", out.Result)
	}
}

func TestActiveMQAuthenticatorAuthenticateOnceReturnsCanceledWhenContextCanceled(t *testing.T) {
	server, cleanup := newTestSTOMPServer(t, func(frame testSTOMPFrame) testSTOMPFrame {
		time.Sleep(200 * time.Millisecond)
		return testSTOMPFrame{command: "CONNECTED", headers: map[string]string{"version": "1.2"}}
	})
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	out := NewAuthenticator(nil).AuthenticateOnce(ctx, strategy.Target{
		Host:     "mq.local",
		IP:       "127.0.0.1",
		Port:     server.port(),
		Protocol: "activemq",
	}, strategy.Credential{
		Username: "admin",
		Password: "secret",
	})

	if out.Result.Success {
		t.Fatalf("expected canceled failure, got %+v", out)
	}
	if out.Result.ErrorCode != result.ErrorCodeCanceled {
		t.Fatalf("expected canceled, got %+v", out.Result)
	}
}

type testSTOMPServer struct {
	listener net.Listener
}

func newTestSTOMPServer(t *testing.T, handler func(testSTOMPFrame) testSTOMPFrame) (*testSTOMPServer, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := &testSTOMPServer{listener: listener}
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		frame, err := readSTOMPFrame(bufio.NewReader(conn))
		if err != nil {
			return
		}
		response := handler(testSTOMPFrame{
			command: frame.command,
			headers: frame.headers,
			body:    frame.body,
		})
		_, _ = conn.Write(encodeSTOMPFrame(response))
	}()

	return server, func() {
		_ = listener.Close()
	}
}

func (s *testSTOMPServer) port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

type testSTOMPFrame struct {
	command string
	headers map[string]string
	body    string
}

func encodeSTOMPFrame(frame testSTOMPFrame) []byte {
	var buf bytes.Buffer
	buf.WriteString(frame.command)
	buf.WriteByte('\n')
	for key, value := range frame.headers {
		buf.WriteString(key)
		buf.WriteByte(':')
		buf.WriteString(value)
		buf.WriteByte('\n')
	}
	buf.WriteByte('\n')
	buf.WriteString(frame.body)
	buf.WriteByte(0)
	return buf.Bytes()
}
