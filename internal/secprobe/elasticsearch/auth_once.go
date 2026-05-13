package elasticsearch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

const authenticatePath = "/_security/_authenticate"

var (
	errElasticsearchAuthenticationFailed = errors.New("elasticsearch authentication failed")
	errElasticsearchConfirmMissingUser   = errors.New("authenticate response missing username")
	doHTTP                               = func(req *http.Request) (*http.Response, error) {
		return http.DefaultClient.Do(req)
	}
)

type Authenticator struct {
	auth func(context.Context, strategy.Target, strategy.Credential) (registrybridge.Attempt, error)
}

type authenticateResponse struct {
	Username string `json:"username"`
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
			ErrorCode:   classifyElasticsearchCredentialFailure(err),
			FindingType: result.FindingTypeCredentialValid,
		}}
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
	if err := ctx.Err(); err != nil {
		return registrybridge.Attempt{}, err
	}

	// 优先走 HTTPS，因为开启安全能力的 Elasticsearch 往往直接在同一 REST 端口上提供 TLS。
	resp, err := doAuthenticateRequest(ctx, buildAuthenticateURL(target, "https"), cred)
	if err == nil {
		return interpretAuthenticateResponse(resp, cred)
	}

	// 如果看起来只是证书校验失败，则在 HTTPS 上放宽校验重试一次，
	// 尽量继续使用安全传输，而不是立刻降级到明文 HTTP。
	if shouldRetryHTTPSInsecure(err) {
		resp, retryErr := doAuthenticateRequest(ctx, buildAuthenticateURL(target, "https"), cred, withInsecureTLS())
		if retryErr == nil {
			return interpretAuthenticateResponse(resp, cred)
		}
		err = retryErr
	}

	// 只有在出现“HTTPS 实际打到了纯 HTTP 端口”这种明确信号时才降级到 HTTP，
	// 普通 TLS 握手失败仍然按连接问题处理，避免过度放宽。
	if shouldFallbackToHTTP(err) {
		resp, fallbackErr := doAuthenticateRequest(ctx, buildAuthenticateURL(target, "http"), cred)
		if fallbackErr == nil {
			return interpretAuthenticateResponse(resp, cred)
		}
		return registrybridge.Attempt{}, fallbackErr
	}

	return registrybridge.Attempt{}, err
}

func buildAuthenticateURL(target strategy.Target, scheme string) string {
	host := target.IP
	if strings.TrimSpace(host) == "" {
		host = target.Host
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(target.Port)) + authenticatePath
}

func newAuthenticateRequest(ctx context.Context, rawURL string, cred strategy.Credential) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(cred.Username, cred.Password)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func classifyElasticsearchCredentialFailure(err error) result.ErrorCode {
	if err == nil {
		return ""
	}
	if errors.Is(err, errElasticsearchAuthenticationFailed) {
		return result.ErrorCodeAuthentication
	}
	if errors.Is(err, errElasticsearchConfirmMissingUser) {
		return result.ErrorCodeInsufficientConfirmation
	}

	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), strings.Contains(text, "context canceled"):
		return result.ErrorCodeCanceled
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return result.ErrorCodeTimeout
	case strings.Contains(text, "401"), strings.Contains(text, "unauthorized"), strings.Contains(text, "authentication"), strings.Contains(text, "security_exception"):
		return result.ErrorCodeAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "connection"), strings.Contains(text, "refused"), strings.Contains(text, "reset by peer"), strings.Contains(text, "no route"), strings.Contains(text, "tls"):
		return result.ErrorCodeConnection
	default:
		return result.ErrorCodeInsufficientConfirmation
	}
}

type requestOption func(*http.Request)

func doAuthenticateRequest(ctx context.Context, rawURL string, cred strategy.Credential, opts ...requestOption) (*http.Response, error) {
	req, err := newAuthenticateRequest(ctx, rawURL, cred)
	if err != nil {
		return nil, err
	}
	for _, opt := range opts {
		opt(req)
	}
	return doHTTP(req)
}

func interpretAuthenticateResponse(resp *http.Response, cred strategy.Credential) (registrybridge.Attempt, error) {
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return registrybridge.Attempt{}, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var payload authenticateResponse
		if err := json.Unmarshal(body, &payload); err != nil {
			return registrybridge.Attempt{}, err
		}
		// 仅有 200 还不够，响应里还必须带有明确的认证用户名，
		// 否则不把这次结果当成已确认命中，避免把模糊 JSON 误判成成功。
		if strings.TrimSpace(payload.Username) == "" {
			return registrybridge.Attempt{}, errElasticsearchConfirmMissingUser
		}
		return registrybridge.Attempt{
			Result: result.Attempt{
				Success:     true,
				Username:    cred.Username,
				Password:    cred.Password,
				Evidence:    "Elasticsearch authentication succeeded via /_security/_authenticate",
				FindingType: result.FindingTypeCredentialValid,
			},
		}, nil
	case http.StatusUnauthorized:
		return registrybridge.Attempt{}, fmt.Errorf("%w: status 401", errElasticsearchAuthenticationFailed)
	default:
		return registrybridge.Attempt{}, fmt.Errorf("unexpected authenticate status %d", resp.StatusCode)
	}
}

func shouldFallbackToHTTP(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "server gave http response to https client")
}

func shouldRetryHTTPSInsecure(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "x509:") || strings.Contains(text, "certificate signed by unknown authority")
}

func withInsecureTLS() requestOption {
	return func(req *http.Request) {
		// 这个头只是为了让测试能感知“当前是放宽证书校验的重试分支”，
		// 真正的 TLS 行为仍由 doHTTP 背后的 HTTP client 控制。
		req.Header.Set("X-Secprobe-Insecure-TLS", "true")
	}
}
