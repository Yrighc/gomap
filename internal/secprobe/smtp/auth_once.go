package smtp

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type Authenticator struct {
	auth func(context.Context, strategy.Target, strategy.Credential) error
}

var errSMTPUnsupportedAuth = errors.New("smtp server does not advertise AUTH PLAIN or AUTH LOGIN")

func NewAuthenticator(auth func(context.Context, strategy.Target, strategy.Credential) error) Authenticator {
	if auth == nil {
		auth = authWithCredential
	}
	return Authenticator{auth: auth}
}

func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	if err := a.auth(ctx, target, cred); err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   result.ErrorCode(classifySMTPFailure(err)),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "SMTP authentication succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}

func authWithCredential(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	candidate := core.SecurityCandidate{
		Target:     target.Host,
		ResolvedIP: target.IP,
		Port:       target.Port,
		Service:    target.Protocol,
	}
	addr := net.JoinHostPort(target.IP, strconv.Itoa(target.Port))
	plan := buildDialPlan(candidate)
	var lastErr error
	for _, mechanism := range []string{"PLAIN", "LOGIN"} {
		_, attempted, err := attemptSMTPAuth(ctx, candidate, addr, plan, timeoutFromContext(ctx), core.Credential{
			Username: cred.Username,
			Password: cred.Password,
		}, mechanism)
		if !attempted {
			continue
		}
		if err == nil {
			return nil
		}
		lastErr = err
		if isTerminalSMTPFailure(classifySMTPFailure(err)) {
			return err
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return errSMTPUnsupportedAuth
}

func timeoutFromContext(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		if timeout := time.Until(deadline); timeout > 0 {
			return timeout
		}
	}
	return 0
}
