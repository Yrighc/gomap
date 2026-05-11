package zabbix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/httpauth"
	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

const zabbixLoginPath = "/api_jsonrpc.php"

var (
	errZabbixAuthenticationFailed = errors.New("zabbix authentication failed")
	errZabbixMissingToken         = errors.New("zabbix login response missing token")
)

type Authenticator struct {
	auth func(context.Context, strategy.Target, strategy.Credential) error
}

func NewAuthenticator(auth func(context.Context, strategy.Target, strategy.Credential) error) Authenticator {
	if auth == nil {
		auth = authWithCredential
	}
	return Authenticator{auth: auth}
}

func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	if err := a.auth(ctx, target, cred); err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   classifyZabbixFailure(err),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "Zabbix HTTP login succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}

func authWithCredential(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	client := httpauth.NewClient(httpauth.Config{
		Timeout:            timeoutFromContext(ctx),
		InsecureSkipVerify: target.Port == 443 || target.Port == 8443,
	})

	resp, err := client.Do(ctx, httpauth.Request{
		Method: http.MethodPost,
		URL:    buildZabbixLoginURL(target),
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   []byte(buildZabbixJSONRPCLogin(cred.Username, cred.Password)),
	})
	if err != nil {
		return err
	}

	return interpretZabbixLoginResponse(resp)
}

func buildZabbixLoginURL(target strategy.Target) string {
	return "http://" + targetAddress(target) + zabbixLoginPath
}

func buildZabbixJSONRPCLogin(username, password string) string {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"method":  "user.login",
		"params": map[string]string{
			"username": username,
			"password": password,
		},
		"id": 1,
	}
	body, _ := json.Marshal(payload)
	return string(body)
}

func interpretZabbixLoginResponse(resp httpauth.Response) error {
	switch resp.StatusCode {
	case http.StatusOK:
		var payload struct {
			Result string `json:"result"`
			Error  any    `json:"error"`
		}
		if err := json.Unmarshal(resp.Body, &payload); err != nil {
			return err
		}
		if strings.TrimSpace(payload.Result) == "" {
			if payload.Error != nil {
				return fmt.Errorf("%w: rpc error present", errZabbixAuthenticationFailed)
			}
			return errZabbixMissingToken
		}
		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: status 401", errZabbixAuthenticationFailed)
	default:
		return fmt.Errorf("unexpected zabbix login status %d", resp.StatusCode)
	}
}

func classifyZabbixFailure(err error) result.ErrorCode {
	if err == nil {
		return ""
	}
	if errors.Is(err, errZabbixAuthenticationFailed) {
		return result.ErrorCodeAuthentication
	}
	if errors.Is(err, errZabbixMissingToken) {
		return result.ErrorCodeInsufficientConfirmation
	}
	if code := httpauth.ClassifyTransportError(err); code != result.ErrorCodeInsufficientConfirmation {
		return code
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "401"), strings.Contains(text, "unauthorized"), strings.Contains(text, "login"), strings.Contains(text, "rpc error"):
		return result.ErrorCodeAuthentication
	default:
		return result.ErrorCodeInsufficientConfirmation
	}
}

func targetAddress(target strategy.Target) string {
	host := target.IP
	if strings.TrimSpace(host) == "" {
		host = target.Host
	}
	return host + ":" + strconv.Itoa(target.Port)
}

func timeoutFromContext(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		if timeout := time.Until(deadline); timeout > 0 {
			return timeout
		}
	}
	return 0
}
