package engine

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/yrighc/gomap/pkg/secprobe/result"
	atomregistry "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestRunnerStopsCredentialLoopOnFirstSuccess(t *testing.T) {
	var attempts atomic.Int32
	auth := stubAuthenticator(func(context.Context, strategy.Target, strategy.Credential) atomregistry.Attempt {
		n := attempts.Add(1)
		if n == 2 {
			return atomregistry.Attempt{Result: result.Attempt{Success: true, FindingType: result.FindingTypeCredentialValid}}
		}
		return atomregistry.Attempt{Result: result.Attempt{Error: "bad password", ErrorCode: result.ErrorCodeAuthentication}}
	})

	plan := strategy.Plan{
		Capabilities: []strategy.Capability{strategy.CapabilityCredential},
		Execution:    strategy.ExecutionPolicy{StopOnFirstSuccess: true},
	}

	out := Run(context.Background(), plan, Input{
		Credentials: []strategy.Credential{
			{Username: "a", Password: "1"},
			{Username: "a", Password: "2"},
			{Username: "a", Password: "3"},
		},
		Authenticator: auth,
	})

	if !out.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("expected 2 attempts, got %d", got)
	}
}

func TestRunnerContinuesCredentialLoopAfterConnectionFailure(t *testing.T) {
	var attempts atomic.Int32
	auth := stubAuthenticator(func(context.Context, strategy.Target, strategy.Credential) atomregistry.Attempt {
		n := attempts.Add(1)
		if n == 2 {
			return atomregistry.Attempt{Result: result.Attempt{Success: true, FindingType: result.FindingTypeCredentialValid}}
		}
		return atomregistry.Attempt{Result: result.Attempt{Error: "dial failed", ErrorCode: result.ErrorCodeConnection}}
	})

	plan := strategy.Plan{
		Capabilities: []strategy.Capability{strategy.CapabilityCredential},
		Execution:    strategy.ExecutionPolicy{StopOnFirstSuccess: true},
	}

	out := Run(context.Background(), plan, Input{
		Credentials: []strategy.Credential{
			{Username: "a", Password: "1"},
			{Username: "a", Password: "2"},
		},
		Authenticator: auth,
	})

	if !out.Success {
		t.Fatalf("expected later credential success, got %+v", out)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("expected 2 attempts, got %d", got)
	}
}

func TestRunnerPrefersUnauthorizedBeforeCredential(t *testing.T) {
	var (
		authAttempts  atomic.Int32
		checkAttempts atomic.Int32
	)

	auth := stubAuthenticator(func(context.Context, strategy.Target, strategy.Credential) atomregistry.Attempt {
		authAttempts.Add(1)
		return atomregistry.Attempt{Result: result.Attempt{Success: true, FindingType: result.FindingTypeCredentialValid}}
	})
	checker := stubUnauthorizedChecker(func(context.Context, strategy.Target) atomregistry.Attempt {
		checkAttempts.Add(1)
		return atomregistry.Attempt{Result: result.Attempt{Success: true, FindingType: result.FindingTypeUnauthorizedAccess}}
	})

	plan := strategy.Plan{
		Capabilities: []strategy.Capability{strategy.CapabilityUnauthorized, strategy.CapabilityCredential},
		Execution:    strategy.ExecutionPolicy{StopOnFirstSuccess: true},
	}

	out := Run(context.Background(), plan, Input{
		Credentials:        []strategy.Credential{{Username: "a", Password: "1"}},
		Authenticator:      auth,
		UnauthorizedChecker: checker,
	})

	if !out.Success {
		t.Fatalf("expected unauthorized success, got %+v", out)
	}
	if out.Capability != strategy.CapabilityUnauthorized {
		t.Fatalf("expected unauthorized capability, got %q", out.Capability)
	}
	if got := checkAttempts.Load(); got != 1 {
		t.Fatalf("expected 1 unauthorized attempt, got %d", got)
	}
	if got := authAttempts.Load(); got != 0 {
		t.Fatalf("expected credential loop to stay idle, got %d", got)
	}
}

func TestRunnerContinuesAfterSuccessWhenStopDisabled(t *testing.T) {
	var attempts atomic.Int32
	auth := stubAuthenticator(func(_ context.Context, _ strategy.Target, cred strategy.Credential) atomregistry.Attempt {
		attempts.Add(1)
		return atomregistry.Attempt{Result: result.Attempt{
			Success:     true,
			Username:    cred.Username,
			Password:    cred.Password,
			FindingType: result.FindingTypeCredentialValid,
		}}
	})

	plan := strategy.Plan{
		Capabilities: []strategy.Capability{strategy.CapabilityCredential},
		Execution:    strategy.ExecutionPolicy{StopOnFirstSuccess: false},
	}

	out := Run(context.Background(), plan, Input{
		Credentials: []strategy.Credential{
			{Username: "a", Password: "1"},
			{Username: "b", Password: "2"},
		},
		Authenticator: auth,
	})

	if !out.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("expected 2 attempts, got %d", got)
	}
	if out.Attempt.Result.Username != "b" || out.Attempt.Result.Password != "2" {
		t.Fatalf("expected last success to win when stop is disabled, got %+v", out.Attempt.Result)
	}
}

func TestRunnerStopsCredentialLoopOnTimeout(t *testing.T) {
	var attempts atomic.Int32
	auth := stubAuthenticator(func(context.Context, strategy.Target, strategy.Credential) atomregistry.Attempt {
		attempts.Add(1)
		return atomregistry.Attempt{Result: result.Attempt{Error: "deadline exceeded", ErrorCode: result.ErrorCodeTimeout}}
	})

	plan := strategy.Plan{
		Capabilities: []strategy.Capability{strategy.CapabilityCredential},
		Execution:    strategy.ExecutionPolicy{StopOnFirstSuccess: false},
	}

	out := Run(context.Background(), plan, Input{
		Credentials: []strategy.Credential{
			{Username: "a", Password: "1"},
			{Username: "b", Password: "2"},
		},
		Authenticator: auth,
	})

	if out.Success {
		t.Fatalf("expected timeout failure, got %+v", out)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("expected timeout to stop loop after 1 attempt, got %d", got)
	}
}

type stubAuthenticator func(context.Context, strategy.Target, strategy.Credential) atomregistry.Attempt

func (f stubAuthenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) atomregistry.Attempt {
	return f(ctx, target, cred)
}

var _ atomregistry.CredentialAuthenticator = stubAuthenticator(nil)

type stubUnauthorizedChecker func(context.Context, strategy.Target) atomregistry.Attempt

func (f stubUnauthorizedChecker) CheckUnauthorizedOnce(ctx context.Context, target strategy.Target) atomregistry.Attempt {
	return f(ctx, target)
}

var _ atomregistry.UnauthorizedChecker = stubUnauthorizedChecker(nil)
