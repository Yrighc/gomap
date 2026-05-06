package mysql

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	gmysql "github.com/go-sql-driver/mysql"

	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type Authenticator struct {
	ping func(context.Context, strategy.Target, strategy.Credential) error
}

func NewAuthenticator(ping func(context.Context, strategy.Target, strategy.Credential) error) Authenticator {
	if ping == nil {
		ping = pingWithAuth
	}
	return Authenticator{ping: ping}
}

func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	if err := a.ping(ctx, target, cred); err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   classifyMySQLFailure(err),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "MySQL authentication succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}

func pingWithAuth(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timeout := timeoutFromContext(ctx)
	cfg := gmysql.Config{
		User:                 cred.Username,
		Passwd:               cred.Password,
		Net:                  "tcp",
		Addr:                 net.JoinHostPort(target.IP, strconv.Itoa(target.Port)),
		Timeout:              timeout,
		ReadTimeout:          timeout,
		WriteTimeout:         timeout,
		AllowNativePasswords: true,
	}
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	pingCtx, cancel := pingContextFromParent(ctx)
	defer cancel()
	return db.PingContext(pingCtx)
}

func classifyMySQLFailure(err error) result.ErrorCode {
	if err == nil {
		return ""
	}
	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), strings.Contains(text, "context canceled"):
		return result.ErrorCodeCanceled
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return result.ErrorCodeTimeout
	case strings.Contains(text, "access denied"), strings.Contains(text, "authentication"), strings.Contains(text, "password"), strings.Contains(text, "credential"), strings.Contains(text, "1045"):
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

func pingContextFromParent(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := timeoutFromContext(ctx)
	if timeout > 0 {
		return context.WithTimeout(ctx, timeout)
	}
	return context.WithCancel(ctx)
}
