package mysql_test

import (
	"context"
	"errors"
	"testing"
	"time"

	mysqlprobe "github.com/yrighc/gomap/internal/secprobe/mysql"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
	"github.com/yrighc/gomap/pkg/secprobe"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := mysqlprobe.NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
		return nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "demo",
		IP:       "127.0.0.1",
		Port:     3306,
		Protocol: "mysql",
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
		{name: "authentication", err: errors.New("Error 1045 (28000): Access denied for user 'gomap'"), want: result.ErrorCodeAuthentication},
		{name: "timeout", err: context.DeadlineExceeded, want: result.ErrorCodeTimeout},
		{name: "connection", err: errors.New("dial tcp 127.0.0.1:3306: connect: connection refused"), want: result.ErrorCodeConnection},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := mysqlprobe.NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
				return tt.err
			})

			out := auth.AuthenticateOnce(context.Background(), strategy.Target{
				Host:     "demo",
				IP:       "127.0.0.1",
				Port:     3306,
				Protocol: "mysql",
			}, strategy.Credential{Username: "gomap", Password: "wrong"})

			if out.Result.ErrorCode != tt.want {
				t.Fatalf("expected %q, got %+v", tt.want, out)
			}
		})
	}
}

func TestMySQLProberFindsValidCredential(t *testing.T) {
	container := testutil.StartMySQL(t, testutil.MySQLConfig{
		Database: "gomap",
		Username: "gomap",
		Password: "gomap-pass",
	})

	prober := mysqlprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "mysql",
	}, secprobe.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []secprobe.Credential{
		{Username: "gomap", Password: "wrong-pass"},
		{Username: "gomap", Password: "gomap-pass"},
	})

	if !result.Success {
		t.Fatalf("expected mysql success, got %+v", result)
	}
	if result.Evidence == "" {
		t.Fatalf("expected mysql success evidence, got %+v", result)
	}
}

func TestMySQLProberReturnsErrorOnFailure(t *testing.T) {
	container := testutil.StartMySQL(t, testutil.MySQLConfig{
		Database: "gomap",
		Username: "gomap",
		Password: "gomap-pass",
	})

	prober := mysqlprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "mysql",
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, []secprobe.Credential{
		{Username: "gomap", Password: "wrong-pass"},
	})

	if result.Success {
		t.Fatalf("expected mysql failure, got %+v", result)
	}
	if result.Error == "" {
		t.Fatalf("expected mysql failure error, got %+v", result)
	}
}
