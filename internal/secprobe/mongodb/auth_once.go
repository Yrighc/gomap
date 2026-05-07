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

// errMongoNoVisibleDatabases 是一个自定义错误，表示没有找到可见的数据库
var errMongoNoVisibleDatabases = errors.New("listDatabaseNames returned no visible databases")

// Authenticator 结构体用于MongoDB认证，包含一个认证函数
type Authenticator struct {
	// auth 是一个认证函数，接受上下文、目标和凭据，返回尝试结果和可能的错误
	auth func(context.Context, strategy.Target, strategy.Credential) (registrybridge.Attempt, error)
}

// NewAuthenticator 创建一个新的Authenticator实例
// 参数:
//   - auth: 认证函数，如果为nil则使用默认的authenticateOnce函数
//
// 返回值:
//   - Authenticator: 新创建的认证器实例
func NewAuthenticator(auth func(context.Context, strategy.Target, strategy.Credential) (registrybridge.Attempt, error)) Authenticator {
	if auth == nil {
		auth = authenticateOnce
	}
	return Authenticator{auth: auth}
}

// AuthenticateOnce 执行一次认证尝试
// 参数:
//   - ctx: 上下文，用于控制请求的超时和取消
//   - target: 目标信息，包含主机、IP、端口和协议
//   - cred: 凭据信息，包含用户名和密码
//
// 返回值:
//   - registrybridge.Attempt: 认证尝试的结果
func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	attempt, err := a.auth(ctx, target, cred)
	if err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   result.ErrorCode(classifyMongoCredentialFailure(err)),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}

	// 处理旧版结果
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

// authenticateOnce 执行一次MongoDB认证
// 参数:
//   - ctx: 上下文，用于控制请求的超时和取消
//   - target: 目标信息，包含主机、IP、端口和协议
//   - cred: 凭据信息，包含用户名和密码
//
// 返回值:
//   - registrybridge.Attempt: 认证尝试的结果
//   - error: 可能发生的错误
func authenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) (registrybridge.Attempt, error) {
	// 从上下文中获取超时时间
	timeout := authTimeoutFromContext(ctx)
	// 打开MongoDB客户端
	client, err := openMongoCredentialClient(ctx, coreCandidate(target), timeout, core.Credential{
		Username: cred.Username,
		Password: cred.Password,
	})
	if err != nil {
		return registrybridge.Attempt{}, err
	}
	// 设置断开连接的上下文和取消函数
	disconnectCtx := context.Background()
	disconnectCancel := func() {}
	if timeout > 0 {
		disconnectCtx, disconnectCancel = context.WithTimeout(context.Background(), timeout)
	}
	defer disconnectCancel()
	defer func() {
		_ = client.Disconnect(disconnectCtx)
	}()

	// 列出数据库名称
	names, err := client.ListDatabaseNames(ctx, bson.D{})
	if err != nil {
		return registrybridge.Attempt{}, err
	}
	if len(names) == 0 {
		return registrybridge.Attempt{}, errMongoNoVisibleDatabases
	}

	// 构建旧版安全结果
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

	// 返回认证结果
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

// coreCandidate 将策略目标转换为安全候选者
// 参数:
//   - target: 策略目标
//
// 返回值:
//   - core.SecurityCandidate: 转换后的安全候选者
func coreCandidate(target strategy.Target) core.SecurityCandidate {
	return core.SecurityCandidate{
		Target:     target.Host,
		ResolvedIP: target.IP,
		Port:       target.Port,
		Service:    target.Protocol,
	}
}

// authTimeoutFromContext 从上下文中获取认证超时时间
// 参数:
//   - ctx: 上下文
//
// 返回值:
//   - time.Duration: 超时时间
func authTimeoutFromContext(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		if timeout := time.Until(deadline); timeout > 0 {
			return timeout
		}
	}
	return 0
}

// legacyPopulated 检查旧版结果是否已填充
// 参数:
//   - out: 安全结果
//
// 返回值:
//   - bool: 如果结果已填充则返回true，否则返回false
func legacyPopulated(out core.SecurityResult) bool {
	return out.Target != "" || out.ResolvedIP != "" || out.Port != 0 || out.Service != "" || out.Success || out.Error != "" || out.FailureReason != ""
}
