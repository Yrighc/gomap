package vnc

import (
	"bytes"
	"context"
	"crypto/des"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

func TestVNCProberFindsValidCredentialForRFB38(t *testing.T) {
	result := runProbeWithServer(t, vncServerScript{
		version:       "RFB 003.008\n",
		securityTypes: []byte{securityTypeVNCAuth},
		password:      "correct",
		authResult:    vncAuthOK,
	}, []core.Credential{
		{Username: "", Password: "wrong"},
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
	if result.Username != "" || result.Password != "correct" {
		t.Fatalf("expected password-only credential success, got %+v", result)
	}
}

func TestVNCProberFindsValidCredentialForRFB33(t *testing.T) {
	result := runProbeWithServer(t, vncServerScript{
		version:        "RFB 003.003\n",
		securityType33: securityTypeVNCAuth,
		password:       "legacy",
		authResult:     vncAuthOK,
	}, []core.Credential{
		{Username: "", Password: "legacy"},
	})

	if !result.Success {
		t.Fatalf("expected vnc success for rfb 3.3, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
}

func TestVNCProberDoesNotTreatUnsupportedSecurityTypeAsSuccess(t *testing.T) {
	result := runProbeWithServer(t, vncServerScript{
		version:       "RFB 003.008\n",
		securityTypes: []byte{securityTypeNone},
	}, []core.Credential{
		{Username: "", Password: "irrelevant"},
	})

	if result.Success {
		t.Fatalf("expected unsupported security type to fail, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonInsufficientConfirmation {
		t.Fatalf("expected insufficient-confirmation, got %+v", result)
	}
}

func TestVNCProberClassifiesAuthenticationFailure(t *testing.T) {
	result := runProbeWithServer(t, vncServerScript{
		version:       "RFB 003.008\n",
		securityTypes: []byte{securityTypeVNCAuth},
		password:      "correct",
		authResult:    vncAuthFailed,
		failureReason: "authentication failed",
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

func TestVNCProberClassifiesCanceledContextBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := New().Probe(ctx, core.SecurityCandidate{
		Target:     "vnc.local",
		ResolvedIP: "127.0.0.1",
		Port:       5900,
		Service:    "vnc",
	}, core.CredentialProbeOptions{Timeout: time.Second}, []core.Credential{
		{Username: "", Password: "secret"},
	})

	if result.Stage != "" {
		t.Fatalf("expected empty stage before attempts, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonCanceled {
		t.Fatalf("expected canceled failure reason, got %+v", result)
	}
}

func TestReadSecuritySelectionRejectsUnsupportedType(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)
		_, err := readSecuritySelection(server, rfbVersion{major: 3, minor: 8})
		errCh <- err
	}()

	if _, err := client.Write([]byte{1, securityTypeNone}); err != nil {
		t.Fatalf("write security types: %v", err)
	}

	err := <-errCh
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "no supported") {
		t.Fatalf("expected unsupported type error, got %v", err)
	}
}

func TestParseProtocolVersionSupports37(t *testing.T) {
	version, err := parseProtocolVersion([]byte("RFB 003.007\n"))
	if err != nil {
		t.Fatalf("expected rfb 3.7 support, got %v", err)
	}
	if version.major != 3 || version.minor != 7 {
		t.Fatalf("unexpected version: %+v", version)
	}
}

type vncServerScript struct {
	version        string
	securityTypes  []byte
	securityType33 uint32
	password       string
	authResult     uint32
	failureReason  string
}

func runProbeWithServer(t *testing.T, script vncServerScript, creds []core.Credential) core.SecurityResult {
	t.Helper()

	originalDialContext := dialContext
	t.Cleanup(func() {
		dialContext = originalDialContext
	})

	dialContext = func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			runVNCServer(server, script)
		}()
		return client, nil
	}

	return New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "vnc.local",
		ResolvedIP: "127.0.0.1",
		Port:       5900,
		Service:    "vnc",
	}, core.CredentialProbeOptions{
		Timeout:       2 * time.Second,
		StopOnSuccess: true,
	}, creds)
}

func runVNCServer(conn net.Conn, script vncServerScript) {
	_, _ = conn.Write([]byte(script.version))

	clientVersion := make([]byte, len(script.version))
	if _, err := io.ReadFull(conn, clientVersion); err != nil {
		return
	}

	version, err := parseProtocolVersion(clientVersion)
	if err != nil {
		return
	}

	if version.minor == 3 {
		if script.securityType33 == 0 {
			script.securityType33 = securityTypeVNCAuth
		}
		if err := binary.Write(conn, binary.BigEndian, script.securityType33); err != nil {
			return
		}
	} else {
		if len(script.securityTypes) == 0 {
			script.securityTypes = []byte{securityTypeVNCAuth}
		}
		if _, err := conn.Write(append([]byte{byte(len(script.securityTypes))}, script.securityTypes...)); err != nil {
			return
		}
		selection := make([]byte, 1)
		if _, err := io.ReadFull(conn, selection); err != nil {
			return
		}
		if len(script.securityTypes) > 0 && selection[0] != script.securityTypes[0] {
			return
		}
	}

	switch {
	case version.minor == 3 && script.securityType33 != securityTypeVNCAuth:
		return
	case version.minor != 3 && (len(script.securityTypes) == 0 || script.securityTypes[0] != securityTypeVNCAuth):
		return
	}

	challenge := []byte("0123456789abcdef")
	if _, err := conn.Write(challenge); err != nil {
		return
	}

	response := make([]byte, len(challenge))
	if _, err := io.ReadFull(conn, response); err != nil {
		return
	}
	expected, err := encryptChallenge(script.password, challenge)
	if err != nil {
		return
	}
	if !bytes.Equal(response, expected) {
		script.authResult = vncAuthFailed
		if script.failureReason == "" {
			script.failureReason = "authentication failed"
		}
	}

	if err := binary.Write(conn, binary.BigEndian, script.authResult); err != nil {
		return
	}

	if script.authResult != vncAuthOK && version.minor >= 8 {
		_ = binary.Write(conn, binary.BigEndian, uint32(len(script.failureReason)))
		_, _ = conn.Write([]byte(script.failureReason))
	}
}

func encryptChallenge(password string, challenge []byte) ([]byte, error) {
	key := vncPasswordKey(password)
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	crypted := make([]byte, len(challenge))
	block.Encrypt(crypted[:8], challenge[:8])
	block.Encrypt(crypted[8:], challenge[8:])
	return crypted, nil
}
