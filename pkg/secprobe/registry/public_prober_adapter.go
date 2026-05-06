package registry

import (
	"context"
	"strings"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type PublicCredentialAdapter struct {
	Prober  core.Prober
	Timeout time.Duration
}

func (a PublicCredentialAdapter) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) Attempt {
	return probePublicOnce(ctx, a.Prober, target, a.Timeout, core.ProbeKindCredential, []core.Credential{{
		Username: cred.Username,
		Password: cred.Password,
	}})
}

type PublicUnauthorizedAdapter struct {
	Prober  core.Prober
	Timeout time.Duration
}

func (a PublicUnauthorizedAdapter) CheckUnauthorizedOnce(ctx context.Context, target strategy.Target) Attempt {
	return probePublicOnce(ctx, a.Prober, target, a.Timeout, core.ProbeKindUnauthorized, nil)
}

func probePublicOnce(ctx context.Context, prober core.Prober, target strategy.Target, timeout time.Duration, kind core.ProbeKind, creds []core.Credential) Attempt {
	if prober == nil {
		return Attempt{}
	}

	probeCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		probeCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	legacy := normalizePublicProbeResult(core.SecurityResult{
		Target:      target.Host,
		ResolvedIP:  target.IP,
		Port:        target.Port,
		Service:     target.Protocol,
		ProbeKind:   kind,
		FindingType: defaultFindingTypeForKind(kind),
	}, prober.Probe(probeCtx, core.SecurityCandidate{
		Target:     target.Host,
		ResolvedIP: target.IP,
		Port:       target.Port,
		Service:    target.Protocol,
	}, core.CredentialProbeOptions{
		Timeout:       timeout,
		StopOnSuccess: true,
	}, creds), kind)

	return Attempt{
		Result: result.Attempt{
			Success:     legacy.Success,
			Username:    legacy.Username,
			Password:    legacy.Password,
			Evidence:    legacy.Evidence,
			Error:       legacy.Error,
			ErrorCode:   publicProbeFailureReason(legacy),
			FindingType: publicProbeFindingType(legacy, kind),
		},
		Legacy: legacy,
	}
}

func normalizePublicProbeResult(base core.SecurityResult, out core.SecurityResult, kind core.ProbeKind) core.SecurityResult {
	if out.Target == "" {
		out.Target = base.Target
	}
	if out.ResolvedIP == "" {
		out.ResolvedIP = base.ResolvedIP
	}
	if out.Port == 0 {
		out.Port = base.Port
	}
	if out.Service == "" {
		out.Service = base.Service
	}
	if out.ProbeKind == "" {
		out.ProbeKind = kind
	}
	if out.FindingType == "" {
		out.FindingType = defaultFindingTypeForKind(kind)
	}
	if out.FailureReason == "" && !out.Success {
		out.FailureReason = inferPublicProbeFailure(out.Error)
	}
	return out
}

func publicProbeFindingType(out core.SecurityResult, kind core.ProbeKind) result.FindingType {
	if parsed, ok := result.ParseFindingType(out.FindingType); ok {
		return parsed
	}
	if kind == core.ProbeKindUnauthorized {
		return result.FindingTypeUnauthorizedAccess
	}
	return result.FindingTypeCredentialValid
}

func publicProbeFailureReason(out core.SecurityResult) result.ErrorCode {
	if parsed, ok := result.ParseErrorCode(string(out.FailureReason)); ok {
		return parsed
	}
	return inferPublicProbeFailure(out.Error)
}

func defaultFindingTypeForKind(kind core.ProbeKind) string {
	if kind == core.ProbeKindUnauthorized {
		return core.FindingTypeUnauthorizedAccess
	}
	return core.FindingTypeCredentialValid
}

func inferPublicProbeFailure(message string) result.ErrorCode {
	text := strings.ToLower(message)
	switch {
	case text == "":
		return result.ErrorCodeInsufficientConfirmation
	case strings.Contains(text, "context canceled"):
		return result.ErrorCodeCanceled
	case strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return result.ErrorCodeTimeout
	case strings.Contains(text, "auth"), strings.Contains(text, "password"), strings.Contains(text, "login"), strings.Contains(text, "access denied"), strings.Contains(text, "permission denied"):
		return result.ErrorCodeAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "connection"), strings.Contains(text, "refused"), strings.Contains(text, "reset by peer"), strings.Contains(text, "no route"):
		return result.ErrorCodeConnection
	default:
		return result.ErrorCodeInsufficientConfirmation
	}
}
