package postgresql_test

import (
	"context"
	"errors"
	"testing"
	"time"

	postgresqlprobe "github.com/yrighc/gomap/internal/secprobe/postgresql"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
	"github.com/yrighc/gomap/pkg/secprobe"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := postgresqlprobe.NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
		return nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "demo",
		IP:       "127.0.0.1",
		Port:     5432,
		Protocol: "postgresql",
	}, strategy.Credential{Username: "gomap", Password: "gomap-pass"})

	if !out.Result.Success || out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("unexpected attempt %+v", out)
	}
}

func TestAuthenticatorAuthenticateOnceMapsFailuresToStandardCodes(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want result.ErrorCode
	}{
		{name: "authentication", err: errors.New("pq: password authentication failed for user \"gomap\""), want: result.ErrorCodeAuthentication},
		{name: "timeout", err: context.DeadlineExceeded, want: result.ErrorCodeTimeout},
		{name: "connection", err: errors.New("dial tcp 127.0.0.1:5432: connect: connection refused"), want: result.ErrorCodeConnection},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := postgresqlprobe.NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
				return tt.err
			})

			out := auth.AuthenticateOnce(context.Background(), strategy.Target{
				Host:     "demo",
				IP:       "127.0.0.1",
				Port:     5432,
				Protocol: "postgresql",
			}, strategy.Credential{Username: "gomap", Password: "wrong"})

			if out.Result.ErrorCode != tt.want {
				t.Fatalf("expected %q, got %+v", tt.want, out)
			}
		})
	}
}

func TestPostgreSQLProberFindsValidCredential(t *testing.T) {
	container := testutil.StartPostgreSQL(t, testutil.PostgreSQLConfig{
		Database: "gomap",
		Username: "gomap",
		Password: "gomap-pass",
	})

	prober := postgresqlprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "postgresql",
	}, secprobe.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []secprobe.Credential{
		{Username: "gomap", Password: "wrong-pass"},
		{Username: "gomap", Password: "gomap-pass"},
	})

	if !result.Success {
		t.Fatalf("expected postgresql success, got %+v", result)
	}
	if result.Evidence == "" {
		t.Fatalf("expected postgresql success evidence, got %+v", result)
	}
}

func TestPostgreSQLProberReturnsErrorOnFailure(t *testing.T) {
	container := testutil.StartPostgreSQL(t, testutil.PostgreSQLConfig{
		Database: "gomap",
		Username: "gomap",
		Password: "gomap-pass",
	})

	prober := postgresqlprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "postgresql",
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, []secprobe.Credential{
		{Username: "gomap", Password: "wrong-pass"},
	})

	if result.Success {
		t.Fatalf("expected postgresql failure, got %+v", result)
	}
	if result.Error == "" {
		t.Fatalf("expected postgresql failure error, got %+v", result)
	}
}

func TestPostgreSQLProberHandlesSpecialCharactersInPassword(t *testing.T) {
	container := testutil.StartPostgreSQL(t, testutil.PostgreSQLConfig{
		Database: "gomap",
		Username: "gomap",
		Password: "pa ss",
	})

	prober := postgresqlprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "postgresql",
	}, secprobe.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []secprobe.Credential{
		{Username: "gomap", Password: "wrong-pass"},
		{Username: "gomap", Password: "pa ss"},
	})

	if !result.Success {
		t.Fatalf("expected postgresql success with spaced password, got %+v", result)
	}
}
