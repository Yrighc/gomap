package ftp

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"

	jftp "github.com/jlaffaye/ftp"

	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type Authenticator struct {
	login func(context.Context, strategy.Target, strategy.Credential) error
}

func NewAuthenticator(login func(context.Context, strategy.Target, strategy.Credential) error) Authenticator {
	if login == nil {
		login = loginWithAuth
	}
	return Authenticator{login: login}
}

func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	if err := a.login(ctx, target, cred); err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   classifyFTPFailure(err),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "FTP authentication succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}

func loginWithAuth(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	conn, err := jftp.Dial(net.JoinHostPort(target.IP, strconv.Itoa(target.Port)), jftp.DialWithContext(ctx))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Quit() }()
	return conn.Login(cred.Username, cred.Password)
}

func classifyFTPFailure(err error) result.ErrorCode {
	if err == nil {
		return ""
	}
	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), strings.Contains(text, "context canceled"):
		return result.ErrorCodeCanceled
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return result.ErrorCodeTimeout
	case strings.Contains(text, "login"), strings.Contains(text, "auth"), strings.Contains(text, "password"), strings.Contains(text, "530"):
		return result.ErrorCodeAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "connection"), strings.Contains(text, "refused"), strings.Contains(text, "reset by peer"), strings.Contains(text, "no route"):
		return result.ErrorCodeConnection
	default:
		return result.ErrorCodeInsufficientConfirmation
	}
}
