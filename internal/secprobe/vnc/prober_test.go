package vnc

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type fakeClient struct{}

func (fakeClient) Close() error { return nil }

func TestVNCProberFindsValidCredentialAndConfirmsStage(t *testing.T) {
	originalDialContext := dialContext
	originalNewClient := newClient
	t.Cleanup(func() {
		dialContext = originalDialContext
		newClient = originalNewClient
	})

	var gotPasswords []string

	dialContext = func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		return client, nil
	}
	newClient = func(_ net.Conn, password string) (clientConn, error) {
		gotPasswords = append(gotPasswords, password)
		if password == "correct" {
			return fakeClient{}, nil
		}
		return nil, errors.New("authentication failed")
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "vnc.local",
		ResolvedIP: "127.0.0.1",
		Port:       5900,
		Service:    "vnc",
	}, core.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []core.Credential{
		{Username: "unexpected-user", Password: "wrong"},
		{Username: "", Password: "correct"},
	})

	if !result.Success {
		t.Fatalf("expected vnc success, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
	if result.FindingType != core.FindingTypeCredentialValid {
		t.Fatalf("expected credential-valid finding type, got %+v", result)
	}
	if result.Username != "" {
		t.Fatalf("expected empty username on success, got %+v", result)
	}
	if result.Password != "correct" {
		t.Fatalf("expected password from successful credential, got %+v", result)
	}
	if len(gotPasswords) != 2 || gotPasswords[0] != "wrong" || gotPasswords[1] != "correct" {
		t.Fatalf("expected password-only attempts in order, got %v", gotPasswords)
	}
}

func TestVNCProberClassifiesAuthenticationFailure(t *testing.T) {
	originalDialContext := dialContext
	originalNewClient := newClient
	t.Cleanup(func() {
		dialContext = originalDialContext
		newClient = originalNewClient
	})

	dialContext = func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		return client, nil
	}
	newClient = func(net.Conn, string) (clientConn, error) {
		return nil, errors.New("authentication failed")
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "vnc.local",
		ResolvedIP: "127.0.0.1",
		Port:       5900,
		Service:    "vnc",
	}, core.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, []core.Credential{
		{Username: "", Password: "bad"},
	})

	if result.Success {
		t.Fatalf("expected vnc failure, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure, got %+v", result)
	}
}
