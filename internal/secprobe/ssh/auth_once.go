package ssh

import (
	"context"
	"net"
	"strconv"
	"time"

	gssh "golang.org/x/crypto/ssh"

	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type Authenticator struct {
	dial func(network, addr string, config *gssh.ClientConfig) (*gssh.Client, error)
}

func NewAuthenticator(dial func(string, string, *gssh.ClientConfig) (*gssh.Client, error)) Authenticator {
	if dial == nil {
		dial = gssh.Dial
	}
	return Authenticator{dial: dial}
}

func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	config := &gssh.ClientConfig{
		User:            cred.Username,
		Auth:            []gssh.AuthMethod{gssh.Password(cred.Password)},
		HostKeyCallback: gssh.InsecureIgnoreHostKey(),
	}
	if deadline, ok := ctx.Deadline(); ok {
		if timeout := time.Until(deadline); timeout > 0 {
			config.Timeout = timeout
		}
	}
	client, err := a.dial("tcp", net.JoinHostPort(target.IP, strconv.Itoa(target.Port)), config)
	if err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   result.ErrorCode(classifySSHFailure(err)),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	if client != nil {
		_ = client.Close()
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "SSH authentication succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}
