# secprobe 新协议最小接入示例

日期：2026-05-07

本文给出一个面向扩展开发者的最小示例，目标不是展示完整协议实现，而是说明在当前 `secprobe` 架构下，新增一个协议最少需要补哪些东西，分别应该放在哪里。

如果你还没看过完整约束，建议先参考：

- [docs/secprobe-protocol-extension-guide.md](/Users/yrighc/work/hzyz/project/GoMap/docs/secprobe-protocol-extension-guide.md)
- [docs/secprobe-third-party-migration-guide.md](/Users/yrighc/work/hzyz/project/GoMap/docs/secprobe-third-party-migration-guide.md)

## 1. 示例目标

假设我们要新增一个协议 `demoauth`，它具备下面特征：

- 支持用户名密码认证
- 暂不支持 enrichment
- 暂不支持复杂未授权确认
- 使用内置默认字典 `demoauth.txt`

这个协议的最小接入面通常包括：

1. 一份 metadata YAML
2. 一个 atomic `credential` provider
3. 默认 registry 注册
4. 至少一组测试

## 2. 第一步：补 metadata

文件位置：

`app/secprobe/protocols/demoauth.yaml`

最小示例：

```yaml
name: demoauth
aliases:
  - demo
ports:
  - 9000
capabilities:
  credential: true
  unauthorized: false
  enrichment: false
policy_tags:
  lockout_risk: medium
  auth_family: password
  transport: tcp
dictionary:
  default_sources:
    - demoauth
  allow_empty_username: false
  allow_empty_password: false
  expansion_profile: basic
results:
  credential_success_type: credential-valid
  unauthorized_success_type: unauthorized-access
  evidence_profile: default
templates:
  unauthorized: ""
```

这份 YAML 只负责声明静态信息，不负责：

- 网络交互
- 字典循环
- 重试
- 停止条件
- 状态机

## 3. 第二步：补默认字典

如果协议要支持默认内置字典，还需要补：

`app/secprobe/dicts/demoauth.txt`

例如：

```txt
admin:admin
root:root
test:test123
```

如果协议不需要默认内置字典，也可以只依赖调用方外部传入字典目录或 inline credentials。

## 4. 第三步：实现 atomic credential provider

目录位置：

`internal/secprobe/demoauth/`

推荐文件：

`internal/secprobe/demoauth/authenticator.go`

最小骨架示例：

```go
package demoauth

import (
    "context"
    "fmt"

    registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
    "github.com/yrighc/gomap/pkg/secprobe/result"
    "github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type Authenticator struct{}

func NewAuthenticator(_ any) Authenticator {
    return Authenticator{}
}

func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
    _ = ctx
    _ = target

    if cred.Username == "admin" && cred.Password == "admin" {
        return registrybridge.Attempt{
            Result: result.Attempt{
                Success:     true,
                Username:    cred.Username,
                Password:    cred.Password,
                Evidence:    "demoauth authentication succeeded",
                FindingType: result.FindingTypeCredentialValid,
            },
        }
    }

    return registrybridge.Attempt{
        Result: result.Attempt{
            Username:    cred.Username,
            Password:    cred.Password,
            Error:       fmt.Sprintf("demoauth authentication failed for %s", cred.Username),
            ErrorCode:   result.ErrorCodeAuthentication,
            FindingType: result.FindingTypeCredentialValid,
        },
    }
}
```

这里最重要的不是示例逻辑本身，而是职责边界：

- 只做一次认证尝试
- 输入是一对用户名密码
- 输出是单次尝试结果

不要在这里做：

- 整本字典循环
- `stop-on-success`
- capability 回退控制
- 通用 retry

这些都属于 engine。

## 5. 第四步：如有需要，再补 unauthorized provider

如果协议确实支持未授权确认，并且这个确认动作不是 simple template 能表达的，可以再补：

`internal/secprobe/demoauth/unauthorized.go`

最小骨架示例：

```go
package demoauth

import (
    "context"

    registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
    "github.com/yrighc/gomap/pkg/secprobe/result"
    "github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type UnauthorizedChecker struct{}

func NewUnauthorizedChecker(_ any) UnauthorizedChecker {
    return UnauthorizedChecker{}
}

func (c UnauthorizedChecker) CheckUnauthorizedOnce(ctx context.Context, target strategy.Target) registrybridge.Attempt {
    _ = ctx
    _ = target

    return registrybridge.Attempt{
        Result: result.Attempt{
            Error:       "unauthorized not implemented",
            ErrorCode:   result.ErrorCodeInsufficientConfirmation,
            FindingType: result.FindingTypeUnauthorizedAccess,
        },
    }
}
```

同样地，这里只负责一次确认动作，不负责更高层执行控制。

## 6. 第五步：注册到默认 registry

如果你希望这个协议进入内置默认能力，需要修改：

`pkg/secprobe/default_registry.go`

最小接线示例：

```go
import demoauthprobe "github.com/yrighc/gomap/internal/secprobe/demoauth"
```

```go
r.RegisterAtomicCredential("demoauth", demoauthprobe.NewAuthenticator(nil))
```

如果同时支持未授权：

```go
r.RegisterAtomicUnauthorized("demoauth", demoauthprobe.NewUnauthorizedChecker(nil))
```

这里推荐使用：

- `RegisterAtomicCredential(...)`
- `RegisterAtomicUnauthorized(...)`

而不是优先写成 legacy `Registry.Register(...)`。

## 7. 第六步：什么时候可以改用模板未授权

如果协议的未授权确认满足下面条件，可以考虑不写 `unauthorized.go`，而改走 simple template executor：

- 只需要一次请求
- 只需要一次读响应
- 成功判定可以靠简单字符串匹配
- 不需要会话维持
- 不需要多轮握手

这时可以补：

- `app/secprobe/templates/unauthorized/<protocol>.yaml`
- protocol metadata 中的 `templates.unauthorized`

但如果协议需要：

- 多阶段交互
- session client
- 复杂状态切换

就不要用模板，直接写 code-backed provider。

## 8. 第七步：最小测试建议

至少建议补这些测试：

1. `AuthenticateOnce` 成功
2. `AuthenticateOnce` 失败
3. 失败分类是否正确
4. `Evidence` 是否稳定
5. `RunWithRegistry` 是否能实际调度到该 provider
6. metadata 是否能被协议名和别名命中
7. 字典来源是否能正确解析

如果支持 unauthorized，再加：

1. `CheckUnauthorizedOnce` 成功
2. `CheckUnauthorizedOnce` 失败
3. unauthorized 与 credential 的顺序和回退行为

如果支持 enrichment，再加：

1. 成功结果能否补采
2. 补采失败是否不改变主 finding 成败

## 9. 一个最小接入完成后你应该检查什么

做完后至少检查这几件事：

1. `BuildCandidates` 是否能识别该协议
2. `Run` / `RunWithRegistry` 是否能执行该协议
3. 结果的 `FindingType` 是否正确
4. 失败是否被正确分类
5. 没有把 loop / stop / retry 写回 provider
6. 没有把复杂逻辑硬塞进 YAML

## 10. 总结

当前版本下，新增协议的最小可用路径可以简单记成：

`metadata + atomic provider + registry wiring + tests`

如果你发现自己在实现新协议时开始想做下面这些事：

- 在 YAML 里写流程控制
- 在 provider 里自己跑完整字典
- 在 `run.go` 里加协议特判

那通常说明你已经偏离当前 `secprobe` 的推荐扩展方式了。
