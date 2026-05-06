package snmp

import (
	"context"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type Authenticator struct {
	auth func(context.Context, strategy.Target, strategy.Credential) error
}

func NewAuthenticator(auth func(context.Context, strategy.Target, strategy.Credential) error) Authenticator {
	if auth == nil {
		auth = authenticateOnce
	}
	return Authenticator{auth: auth}
}

func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	if err := a.auth(ctx, target, cred); err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   result.ErrorCode(classifySNMPFailure(err)),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "SNMP v2c community succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}

func authenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	candidate := coreCandidate(target)
	timeout := time.Duration(0)
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 {
			timeout = remaining
		}
	}
	client, err := openSNMP(ctx, candidate, cred.Password, timeout)
	if err != nil {
		return err
	}
	if err := client.Connect(); err != nil {
		_ = client.Close()
		return err
	}
	_, err = client.Get([]string{sysDescrOID})
	_ = client.Close()
	return err
}

func coreCandidate(target strategy.Target) core.SecurityCandidate {
	return core.SecurityCandidate{
		Target:     target.Host,
		ResolvedIP: target.IP,
		Port:       target.Port,
		Service:    target.Protocol,
	}
}
