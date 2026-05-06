package telnet

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

var errTelnetAuthFailed = errors.New("authentication failed")

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
			ErrorCode:   classifyTelnetFailure(err),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "Telnet authentication succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}

func loginWithAuth(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timeout := timeoutFromContext(ctx)
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.IP, strconv.Itoa(target.Port)))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString(':'); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(conn, "%s\n", cred.Username); err != nil {
		return err
	}
	if _, err := reader.ReadString(':'); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(conn, "%s\n", cred.Password); err != nil {
		return err
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(line, "Welcome") {
		return errTelnetAuthFailed
	}
	return nil
}

func classifyTelnetFailure(err error) result.ErrorCode {
	if err == nil {
		return ""
	}
	if errors.Is(err, errTelnetAuthFailed) {
		return result.ErrorCodeAuthentication
	}
	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), strings.Contains(text, "context canceled"):
		return result.ErrorCodeCanceled
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return result.ErrorCodeTimeout
	case strings.Contains(text, "auth"), strings.Contains(text, "login"), strings.Contains(text, "password"):
		return result.ErrorCodeAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "connection"), strings.Contains(text, "refused"), strings.Contains(text, "reset by peer"), strings.Contains(text, "no route"):
		return result.ErrorCodeConnection
	default:
		return result.ErrorCodeInsufficientConfirmation
	}
}

func timeoutFromContext(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		if timeout := time.Until(deadline); timeout > 0 {
			return timeout
		}
	}
	return 0
}
