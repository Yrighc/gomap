package snmp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type fakeSNMPClient struct {
	connectErr error
	getErr     error
	closed     bool
}

func (c *fakeSNMPClient) Connect() error { return c.connectErr }

func (c *fakeSNMPClient) Get([]string) (string, error) {
	if c.getErr != nil {
		return "", c.getErr
	}
	return "Linux test-agent", nil
}

func (c *fakeSNMPClient) Close() error {
	c.closed = true
	return nil
}

func TestSNMPProberFindsValidCommunity(t *testing.T) {
	originalOpen := openSNMP
	t.Cleanup(func() { openSNMP = originalOpen })

	openSNMP = func(context.Context, core.SecurityCandidate, string, time.Duration) (snmpClient, error) {
		return &fakeSNMPClient{}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       161,
		Service:    "snmp",
	}, core.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []core.Credential{
		{Username: "", Password: "public"},
	})

	if !result.Success {
		t.Fatalf("expected snmp success, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
	if result.FindingType != core.FindingTypeCredentialValid {
		t.Fatalf("expected credential-valid finding type, got %+v", result)
	}
}

func TestSNMPProberUsesCredentialPasswordAsCommunity(t *testing.T) {
	originalOpen := openSNMP
	t.Cleanup(func() { openSNMP = originalOpen })

	var gotCommunity string
	openSNMP = func(_ context.Context, _ core.SecurityCandidate, community string, _ time.Duration) (snmpClient, error) {
		gotCommunity = community
		return &fakeSNMPClient{}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       161,
		Service:    "snmp",
	}, core.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []core.Credential{
		{Username: "", Password: "private"},
	})

	if !result.Success {
		t.Fatalf("expected snmp success, got %+v", result)
	}
	if gotCommunity != "private" {
		t.Fatalf("expected password field to map to community, got %q", gotCommunity)
	}
}

func TestSNMPProberClassifiesAuthenticationFailure(t *testing.T) {
	originalOpen := openSNMP
	t.Cleanup(func() { openSNMP = originalOpen })

	openSNMP = func(context.Context, core.SecurityCandidate, string, time.Duration) (snmpClient, error) {
		return &fakeSNMPClient{getErr: errors.New("authorizationError: community invalid")}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       161,
		Service:    "snmp",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, []core.Credential{
		{Username: "", Password: "wrong"},
	})

	if result.Success {
		t.Fatalf("expected snmp failure, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure reason, got %+v", result)
	}
}

func TestSNMPProberClassifiesConnectionFailure(t *testing.T) {
	originalOpen := openSNMP
	t.Cleanup(func() { openSNMP = originalOpen })

	openSNMP = func(context.Context, core.SecurityCandidate, string, time.Duration) (snmpClient, error) {
		return &fakeSNMPClient{connectErr: errors.New("dial udp 127.0.0.1:161: connect: connection refused")}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       161,
		Service:    "snmp",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, []core.Credential{
		{Username: "", Password: "public"},
	})

	if result.Success {
		t.Fatalf("expected snmp connection failure, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonConnection {
		t.Fatalf("expected connection failure reason, got %+v", result)
	}
}

func TestSNMPProberClassifiesInsufficientConfirmation(t *testing.T) {
	originalOpen := openSNMP
	t.Cleanup(func() { openSNMP = originalOpen })

	openSNMP = func(context.Context, core.SecurityCandidate, string, time.Duration) (snmpClient, error) {
		return &fakeSNMPClient{getErr: errors.New("snmp returned unexpected response state")}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       161,
		Service:    "snmp",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, []core.Credential{
		{Username: "", Password: "public"},
	})

	if result.Success {
		t.Fatalf("expected snmp insufficient-confirmation failure, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonInsufficientConfirmation {
		t.Fatalf("expected insufficient-confirmation failure reason, got %+v", result)
	}
}

func TestSNMPProberClassifiesCanceledContextBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := New().Probe(ctx, core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       161,
		Service:    "snmp",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, []core.Credential{
		{Username: "", Password: "public"},
	})

	if result.Stage != "" {
		t.Fatalf("expected empty stage before any credential attempt, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonCanceled {
		t.Fatalf("expected canceled failure reason, got %+v", result)
	}
}

func TestSNMPProberClassifiesDeadlineExceededBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	result := New().Probe(ctx, core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       161,
		Service:    "snmp",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, []core.Credential{
		{Username: "", Password: "public"},
	})

	if result.Stage != "" {
		t.Fatalf("expected empty stage before any credential attempt, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonTimeout {
		t.Fatalf("expected timeout failure reason, got %+v", result)
	}
}
