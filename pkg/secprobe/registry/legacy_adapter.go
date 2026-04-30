package registry

import (
	"context"
	"strings"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type LegacyCredentialAdapter struct {
	Prober  core.Prober
	Timeout time.Duration
}

func (a LegacyCredentialAdapter) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) Attempt {
	return a.probeOnce(ctx, target, core.ProbeKindCredential, []core.Credential{{
		Username: cred.Username,
		Password: cred.Password,
	}})
}

type LegacyUnauthorizedAdapter struct {
	Prober  core.Prober
	Timeout time.Duration
}

func (a LegacyUnauthorizedAdapter) CheckUnauthorizedOnce(ctx context.Context, target strategy.Target) Attempt {
	return a.probeOnce(ctx, target, core.ProbeKindUnauthorized, nil)
}

func (a LegacyCredentialAdapter) probeOnce(ctx context.Context, target strategy.Target, kind core.ProbeKind, creds []core.Credential) Attempt {
	return probeLegacyOnce(ctx, a.Prober, target, a.Timeout, kind, creds)
}

func (a LegacyUnauthorizedAdapter) probeOnce(ctx context.Context, target strategy.Target, kind core.ProbeKind, creds []core.Credential) Attempt {
	return probeLegacyOnce(ctx, a.Prober, target, a.Timeout, kind, creds)
}

func probeLegacyOnce(ctx context.Context, prober core.Prober, target strategy.Target, timeout time.Duration, kind core.ProbeKind, creds []core.Credential) Attempt {
	if prober == nil {
		return Attempt{}
	}

	probeCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		probeCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	legacy := normalizeLegacyResult(core.SecurityResult{
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
			ErrorCode:   legacyFailureReason(legacy),
			FindingType: legacyFindingType(legacy, kind),
		},
		Legacy: legacy,
	}
}

func normalizeLegacyResult(base core.SecurityResult, out core.SecurityResult, kind core.ProbeKind) core.SecurityResult {
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
		out.FailureReason = inferFailureReason(out.Error)
	}
	return out
}

func legacyFindingType(out core.SecurityResult, kind core.ProbeKind) result.FindingType {
	if parsed, ok := result.ParseFindingType(out.FindingType); ok {
		return parsed
	}
	if kind == core.ProbeKindUnauthorized {
		return result.FindingTypeUnauthorizedAccess
	}
	return result.FindingTypeCredentialValid
}

func legacyFailureReason(out core.SecurityResult) result.ErrorCode {
	if parsed, ok := result.ParseErrorCode(string(out.FailureReason)); ok {
		return parsed
	}
	return inferFailureReason(out.Error)
}

func defaultFindingTypeForKind(kind core.ProbeKind) string {
	if kind == core.ProbeKindUnauthorized {
		return core.FindingTypeUnauthorizedAccess
	}
	return core.FindingTypeCredentialValid
}

func inferFailureReason(message string) result.ErrorCode {
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
