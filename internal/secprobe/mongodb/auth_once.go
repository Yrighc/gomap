package mongodb

import (
	"context"
	"errors"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
	"go.mongodb.org/mongo-driver/bson"
)

var errMongoNoVisibleDatabases = errors.New("listDatabaseNames returned no visible databases")

type Authenticator struct {
	auth func(context.Context, strategy.Target, strategy.Credential) (registrybridge.Attempt, error)
}

func NewAuthenticator(auth func(context.Context, strategy.Target, strategy.Credential) (registrybridge.Attempt, error)) Authenticator {
	if auth == nil {
		auth = authenticateOnce
	}
	return Authenticator{auth: auth}
}

func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	attempt, err := a.auth(ctx, target, cred)
	if err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   result.ErrorCode(classifyMongoCredentialFailure(err)),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}

	if attempt.Result == (result.Attempt{}) && legacyPopulated(attempt.Legacy) {
		attempt.Result = result.Attempt{
			Success:     attempt.Legacy.Success,
			Username:    attempt.Legacy.Username,
			Password:    attempt.Legacy.Password,
			Evidence:    attempt.Legacy.Evidence,
			Error:       attempt.Legacy.Error,
			ErrorCode:   result.ErrorCode(attempt.Legacy.FailureReason),
			FindingType: result.FindingTypeCredentialValid,
		}
	}
	if attempt.Result.FindingType == "" {
		attempt.Result.FindingType = result.FindingTypeCredentialValid
	}
	if attempt.Result.Success && attempt.Result.Username == "" {
		attempt.Result.Username = cred.Username
	}
	if attempt.Result.Success && attempt.Result.Password == "" {
		attempt.Result.Password = cred.Password
	}
	return attempt
}

func authenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) (registrybridge.Attempt, error) {
	timeout := authTimeoutFromContext(ctx)
	client, err := openMongoCredentialClient(ctx, coreCandidate(target), timeout, core.Credential{
		Username: cred.Username,
		Password: cred.Password,
	})
	if err != nil {
		return registrybridge.Attempt{}, err
	}
	disconnectCtx := context.Background()
	disconnectCancel := func() {}
	if timeout > 0 {
		disconnectCtx, disconnectCancel = context.WithTimeout(context.Background(), timeout)
	}
	defer disconnectCancel()
	defer func() {
		_ = client.Disconnect(disconnectCtx)
	}()

	names, err := client.ListDatabaseNames(ctx, bson.D{})
	if err != nil {
		return registrybridge.Attempt{}, err
	}
	if len(names) == 0 {
		return registrybridge.Attempt{}, errMongoNoVisibleDatabases
	}

	legacy := core.SecurityResult{
		Target:       target.Host,
		ResolvedIP:   target.IP,
		Port:         target.Port,
		Service:      target.Protocol,
		ProbeKind:    core.ProbeKindCredential,
		FindingType:  core.FindingTypeCredentialValid,
		Success:      true,
		Username:     cred.Username,
		Password:     cred.Password,
		Evidence:     "listDatabaseNames succeeded after authentication",
		Stage:        core.StageConfirmed,
		Capabilities: []core.Capability{core.CapabilityEnumerable},
	}

	return registrybridge.Attempt{
		Result: result.Attempt{
			Success:     true,
			Username:    cred.Username,
			Password:    cred.Password,
			Evidence:    legacy.Evidence,
			FindingType: result.FindingTypeCredentialValid,
		},
		Legacy: legacy,
	}, nil
}

func coreCandidate(target strategy.Target) core.SecurityCandidate {
	return core.SecurityCandidate{
		Target:     target.Host,
		ResolvedIP: target.IP,
		Port:       target.Port,
		Service:    target.Protocol,
	}
}

func authTimeoutFromContext(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		if timeout := time.Until(deadline); timeout > 0 {
			return timeout
		}
	}
	return 0
}

func legacyPopulated(out core.SecurityResult) bool {
	return out.Target != "" || out.ResolvedIP != "" || out.Port != 0 || out.Service != "" || out.Success || out.Error != "" || out.FailureReason != ""
}
