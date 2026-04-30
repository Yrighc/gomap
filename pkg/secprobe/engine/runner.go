package engine

import (
	"context"

	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type Input struct {
	Credentials         []strategy.Credential
	CredentialLoader    func() ([]strategy.Credential, error)
	Authenticator       registrybridge.CredentialAuthenticator
	UnauthorizedChecker registrybridge.UnauthorizedChecker
}

type Output struct {
	Success         bool
	Attempted       bool
	Capability      strategy.Capability
	Attempt         registrybridge.Attempt
	CredentialError error
}

func Run(ctx context.Context, plan strategy.Plan, in Input) Output {
	var (
		out         Output
		loaded      bool
		cachedCreds []strategy.Credential
		cachedErr   error
	)

	loadCredentials := func() ([]strategy.Credential, error) {
		if loaded {
			return cachedCreds, cachedErr
		}
		loaded = true
		if in.CredentialLoader != nil {
			cachedCreds, cachedErr = in.CredentialLoader()
		} else {
			cachedCreds = in.Credentials
		}
		return cachedCreds, cachedErr
	}

	for _, capability := range plan.Capabilities {
		switch capability {
		case strategy.CapabilityUnauthorized:
			if in.UnauthorizedChecker == nil {
				continue
			}
			attempt := in.UnauthorizedChecker.CheckUnauthorizedOnce(ctx, plan.Target)
			out.Attempted = true
			out.Capability = capability
			out.Attempt = attempt
			if attempt.Result.Success {
				out.Success = true
				return out
			}
		case strategy.CapabilityCredential:
			if in.Authenticator == nil {
				continue
			}
			creds, err := loadCredentials()
			if err != nil {
				out.Capability = capability
				out.CredentialError = err
				return out
			}
			for _, cred := range creds {
				attempt := in.Authenticator.AuthenticateOnce(ctx, plan.Target, cred)
				if attempt.Result.Success {
					out.Attempted = true
					out.Capability = capability
					out.Attempt = attempt
					out.Success = true
					if plan.Execution.StopOnFirstSuccess {
						return out
					}
					continue
				}
				if out.Success {
					if isCredentialTerminal(attempt.Result.ErrorCode) {
						return out
					}
					continue
				}
				out.Attempted = true
				out.Capability = capability
				out.Attempt = attempt
				if isCredentialTerminal(attempt.Result.ErrorCode) {
					return out
				}
			}
		}
	}

	return out
}

func isCredentialTerminal(code result.ErrorCode) bool {
	return code == result.ErrorCodeCanceled || code == result.ErrorCodeTimeout
}
