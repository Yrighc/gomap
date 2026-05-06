package postgresql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

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
			ErrorCode:   classifyPostgreSQLFailure(err),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "PostgreSQL authentication succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}

func pingWithAuth(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	connectTimeout := int(math.Ceil(timeoutFromContext(ctx).Seconds()))
	if connectTimeout < 1 {
		connectTimeout = 1
	}
	query := url.Values{
		"dbname":          []string{"postgres"},
		"sslmode":         []string{"disable"},
		"connect_timeout": []string{fmt.Sprintf("%d", connectTimeout)},
	}
	dsn := fmt.Sprintf(
		"postgres://%s@%s:%d?%s",
		url.UserPassword(cred.Username, cred.Password).String(),
		target.IP,
		target.Port,
		query.Encode(),
	)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	pingCtx, cancel := pingContextFromParent(ctx)
	defer cancel()
	return db.PingContext(pingCtx)
}

func classifyPostgreSQLFailure(err error) result.ErrorCode {
	if err == nil {
		return ""
	}
	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), strings.Contains(text, "context canceled"):
		return result.ErrorCodeCanceled
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return result.ErrorCodeTimeout
	case strings.Contains(text, "password authentication failed"), strings.Contains(text, "authentication"), strings.Contains(text, "password"), strings.Contains(text, "credential"):
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
