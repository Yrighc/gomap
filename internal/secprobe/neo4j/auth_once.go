package neo4j

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

const neo4jLoginPath = "/db/neo4j/tx/commit"

var (
	errNeo4jAuthenticationFailed = errors.New("neo4j authentication failed")
	errNeo4jMissingConfirmation  = errors.New("neo4j login response missing confirmation")
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
			ErrorCode:   classifyNeo4jFailure(err),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "Neo4j HTTP login succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}

func authWithCredential(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	client := httpauth.NewClient(httpauth.Config{
		Timeout:            timeoutFromContext(ctx),
		InsecureSkipVerify: target.Port == 7473,
	})

	req, err := buildNeo4jRequest(target, cred)
	if err != nil {
		return err
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return err
	}

	return interpretNeo4jLoginResponse(resp)
}

func buildNeo4jRequest(target strategy.Target, cred strategy.Credential) (httpauth.Request, error) {
	req, err := http.NewRequest(http.MethodPost, "http://"+targetAddress(target)+neo4jLoginPath, strings.NewReader(`{"statements":[{"statement":"RETURN 1"}]}`))
	if err != nil {
		return httpauth.Request{}, err
	}
	req.SetBasicAuth(cred.Username, cred.Password)
	req.Header.Set("Content-Type", "application/json")

	return httpauth.Request{
		Method: req.Method,
		URL:    req.URL.String(),
		Header: req.Header.Clone(),
		Body:   []byte(`{"statements":[{"statement":"RETURN 1"}]}`),
	}, nil
}

func interpretNeo4jLoginResponse(resp httpauth.Response) error {
	switch resp.StatusCode {
	case http.StatusOK:
		var payload struct {
			Results []any `json:"results"`
			Errors  []any `json:"errors"`
		}
		if err := json.Unmarshal(resp.Body, &payload); err != nil {
			return err
		}
		if len(payload.Errors) > 0 {
			return fmt.Errorf("%w: response contains errors", errNeo4jAuthenticationFailed)
		}
		if len(payload.Results) == 0 {
			return errNeo4jMissingConfirmation
		}
		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: status 401", errNeo4jAuthenticationFailed)
	default:
		return fmt.Errorf("unexpected neo4j login status %d", resp.StatusCode)
	}
}

func classifyNeo4jFailure(err error) result.ErrorCode {
	if err == nil {
		return ""
	}
	if errors.Is(err, errNeo4jAuthenticationFailed) {
		return result.ErrorCodeAuthentication
	}
	if errors.Is(err, errNeo4jMissingConfirmation) {
		return result.ErrorCodeInsufficientConfirmation
	}
	if code := httpauth.ClassifyTransportError(err); code != result.ErrorCodeInsufficientConfirmation {
		return code
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "401"), strings.Contains(text, "unauthorized"), strings.Contains(text, "auth"), strings.Contains(text, "response contains errors"):
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
