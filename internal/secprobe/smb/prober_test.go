package smb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type fakeSession struct {
	mountFn func(string) error
	logoff  bool
}

func (s *fakeSession) Mount(share string) error {
	if s.mountFn != nil {
		return s.mountFn(share)
	}
	return nil
}

func (s *fakeSession) Logoff() error {
	s.logoff = true
	return nil
}

func TestSMBProberFindsValidCredentialAndConfirmsStage(t *testing.T) {
	originalDial := dialSMBSession
	t.Cleanup(func() {
		dialSMBSession = originalDial
	})

	var attempts []core.Credential
	dialSMBSession = func(_ context.Context, _ string, cred core.Credential, _ time.Duration) (smbSession, error) {
		attempts = append(attempts, cred)
		if cred.Password != "correct" {
			return nil, errors.New("authentication failed")
		}
		return &fakeSession{}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       445,
		Service:    "smb",
	}, core.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []core.Credential{
		{Username: "alice", Password: "wrong"},
		{Username: "alice", Password: "correct"},
	})

	if !result.Success {
		t.Fatalf("expected smb success, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
	if result.FindingType != core.FindingTypeCredentialValid {
		t.Fatalf("expected credential-valid finding type, got %+v", result)
	}
	if result.FailureReason != "" {
		t.Fatalf("expected empty failure reason on success, got %+v", result)
	}
	if len(attempts) != 2 {
		t.Fatalf("expected two credential attempts, got %d", len(attempts))
	}
}

func TestSMBProberClassifiesAuthenticationFailure(t *testing.T) {
	originalDial := dialSMBSession
	t.Cleanup(func() {
		dialSMBSession = originalDial
	})

	dialSMBSession = func(context.Context, string, core.Credential, time.Duration) (smbSession, error) {
		return nil, errors.New("authentication failed")
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       445,
		Service:    "smb",
	}, core.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, []core.Credential{
		{Username: "alice", Password: "wrong"},
	})

	if result.Success {
		t.Fatalf("expected smb failure, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure reason, got %+v", result)
	}
}

func TestDefaultDialSMBSessionUsesIPCSuccessConfirmation(t *testing.T) {
	originalOpen := openSMBConn
	t.Cleanup(func() {
		openSMBConn = originalOpen
	})

	var gotAddress string
	var gotTimeout time.Duration
	var gotCred core.Credential
	var mountedShare string
	session := &fakeSession{
		mountFn: func(share string) error {
			mountedShare = share
			return nil
		},
	}

	openSMBConn = func(_ context.Context, network, address string, timeout time.Duration, cred core.Credential) (smbSession, error) {
		gotAddress = address
		gotTimeout = timeout
		gotCred = cred
		return session, nil
	}

	gotSession, err := defaultDialSMBSession(context.Background(), "127.0.0.1:445", core.Credential{
		Username: "alice",
		Password: "secret",
	}, 3*time.Second)
	if err != nil {
		t.Fatalf("expected default dial to succeed, got %v", err)
	}
	if gotSession == nil {
		t.Fatal("expected returned session")
	}
	if gotAddress != "127.0.0.1:445" {
		t.Fatalf("expected address 127.0.0.1:445, got %q", gotAddress)
	}
	if gotTimeout != 3*time.Second {
		t.Fatalf("expected timeout 3s, got %v", gotTimeout)
	}
	if gotCred.Username != "alice" || gotCred.Password != "secret" {
		t.Fatalf("expected credential passthrough, got %+v", gotCred)
	}
	if mountedShare != "IPC$" {
		t.Fatalf("expected IPC$ mount for confirmation, got %q", mountedShare)
	}
}
