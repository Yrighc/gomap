package registry

import (
	"context"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

// Attempt 结构体用于封装认证尝试的结果
type Attempt struct {
	Result result.Attempt      // 认证尝试的结果
	Legacy core.SecurityResult // 传统安全结果
}

// CredentialAuthenticator 认证器接口，定义了一次认证的行为
type CredentialAuthenticator interface {
	// AuthenticateOnce 执行一次认证操作
	// ctx: 上下文信息，用于控制请求的超时和取消
	// target: 认证目标，包含需要认证的资源信息
	// cred: 凭据，包含认证所需的身份验证信息
	// 返回: Attempt结构体，包含认证结果
	AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) Attempt
}

// UnauthorizedChecker 未授权检查器接口，定义了检查未授权状态的行为
type UnauthorizedChecker interface {
	// CheckUnauthorizedOnce 执行一次未授权状态检查
	// ctx: 上下文信息，用于控制请求的超时和取消
	// target: 检查目标，包含需要检查的资源信息
	// 返回: Attempt结构体，包含检查结果
	CheckUnauthorizedOnce(ctx context.Context, target strategy.Target) Attempt
}

// Enricher 丰富器接口，用于丰富认证尝试的信息
type Enricher interface {
	// EnrichOnce 对已有的认证尝试信息进行丰富
	// ctx: 上下文信息，用于控制请求的超时和取消
	// target: 丰富目标，包含需要丰富的资源信息
	// attempt: 已有的认证尝试信息
	// 返回: 经过丰富后的Attempt结构体
	EnrichOnce(ctx context.Context, target strategy.Target, attempt Attempt) Attempt
}
