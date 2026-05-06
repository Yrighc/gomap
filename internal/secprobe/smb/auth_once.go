package smb

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type Authenticator struct {
	login func(context.Context, strategy.Target, strategy.Credential) error
}

func NewAuthenticator(login func(context.Context, strategy.Target, strategy.Credential) error) Authenticator {
	if login == nil {
		login = loginOnce
	}
	return Authenticator{login: login}
}

func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	if err := a.login(ctx, target, cred); err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   result.ErrorCode(classifySMBFailure(err)),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    `SMB authentication succeeded by mounting IPC$`,
		FindingType: result.FindingTypeCredentialValid,
	}}
}

func loginOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	session, err := dialSMBSession(ctx, net.JoinHostPort(target.IP, strconv.Itoa(target.Port)), core.Credential{
		Username: cred.Username,
		Password: cred.Password,
	}, effectiveTimeout(smbAuthTimeout(ctx)))
	if session != nil {
		defer session.Logoff()
	}
	return err
}

func smbAuthTimeout(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		if timeout := time.Until(deadline); timeout > 0 {
			return timeout
		}
	}
	return 0
}
