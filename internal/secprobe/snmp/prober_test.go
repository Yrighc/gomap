package snmp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/yrighc/gomap/internal/secprobe/core"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
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

func TestSNMPAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := NewAuthenticator(func(_ context.Context, _ strategy.Target, cred strategy.Credential) error {
		if cred.Password != "public" {
			t.Fatalf("expected password field to carry community, got %+v", cred)
		}
		return nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "router.local",
		IP:       "127.0.0.1",
		Port:     161,
		Protocol: "snmp",
	}, strategy.Credential{
		Username: "",
		Password: "public",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	if out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("expected credential-valid finding type, got %+v", out)
	}
	if out.Result.Evidence != "SNMP v2c community succeeded" {
		t.Fatalf("expected deterministic evidence, got %+v", out)
	}
	if out.Result.Password != "public" {
		t.Fatalf("expected password recorded as winning community, got %+v", out)
	}
}

func TestSNMPAuthenticatorAuthenticateOncePropagatesContextDeadlineAsTimeout(t *testing.T) {
	originalOpen := openSNMP
	t.Cleanup(func() { openSNMP = originalOpen })

	var gotTimeout time.Duration
	openSNMP = func(_ context.Context, _ core.SecurityCandidate, _ string, timeout time.Duration) (snmpClient, error) {
		gotTimeout = timeout
		return &fakeSNMPClient{}, nil
	}

	deadline := time.Now().Add(12 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	out := NewAuthenticator(nil).AuthenticateOnce(ctx, strategy.Target{
		Host:     "router.local",
		IP:       "127.0.0.1",
		Port:     161,
		Protocol: "snmp",
	}, strategy.Credential{
		Password: "public",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	if gotTimeout <= 0 {
		t.Fatalf("expected positive timeout derived from context deadline, got %v", gotTimeout)
	}
	if gotTimeout > 12*time.Second || gotTimeout < 10*time.Second {
		t.Fatalf("expected timeout close to remaining deadline, got %v", gotTimeout)
	}
}

func TestSNMPAuthenticatorAuthenticateOnceMapsAuthenticationFailure(t *testing.T) {
	auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
		return errors.New("authorizationError: community invalid")
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "router.local",
		IP:       "127.0.0.1",
		Port:     161,
		Protocol: "snmp",
	}, strategy.Credential{
		Password: "private",
	})

	if out.Result.Success {
		t.Fatalf("expected authentication failure, got %+v", out)
	}
	if out.Result.ErrorCode != result.ErrorCodeAuthentication {
		t.Fatalf("expected authentication error code, got %+v", out)
	}
	if out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("expected credential-valid finding type, got %+v", out)
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

func TestValidateSNMPResponseRejectsProtocolErrorStatus(t *testing.T) {
	err := validateSNMPResponse(&gosnmp.SnmpPacket{
		Error: gosnmp.NoAccess,
		Variables: []gosnmp.SnmpPDU{{
			Name:  sysDescrOID,
			Type:  gosnmp.OctetString,
			Value: []byte("Linux"),
		}},
	}, sysDescrOID)
	if err == nil {
		t.Fatal("expected snmp error status to be rejected")
	}
}

func TestValidateSNMPResponseRejectsNoSuchInstance(t *testing.T) {
	err := validateSNMPResponse(&gosnmp.SnmpPacket{
		Error: gosnmp.NoError,
		Variables: []gosnmp.SnmpPDU{{
			Name: sysDescrOID,
			Type: gosnmp.NoSuchInstance,
		}},
	}, sysDescrOID)
	if err == nil {
		t.Fatal("expected non-readable varbind type to be rejected")
	}
}

func TestValidateSNMPResponseRejectsUnexpectedOID(t *testing.T) {
	err := validateSNMPResponse(&gosnmp.SnmpPacket{
		Error: gosnmp.NoError,
		Variables: []gosnmp.SnmpPDU{{
			Name:  ".1.3.6.1.2.1.1.5.0",
			Type:  gosnmp.OctetString,
			Value: []byte("other"),
		}},
	}, sysDescrOID)
	if err == nil {
		t.Fatal("expected unexpected oid to be rejected")
	}
}

func TestOpenSNMPPropagatesContextToClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := openSNMP(ctx, core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       161,
		Service:    "snmp",
	}, "public", 5*time.Second)
	if err != nil {
		t.Fatalf("open snmp client: %v", err)
	}

	goClient, ok := client.(*goSNMPClient)
	if !ok {
		t.Fatalf("expected goSNMPClient, got %T", client)
	}
	if goClient.client.Context != ctx {
		t.Fatal("expected SNMP client to reuse caller context")
	}
}
