package oracle

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/sijms/go-ora/v2"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

type oracleDB interface {
	PingContext(ctx context.Context) error
	Close() error
}

type sqlOracleDB struct {
	db *sql.DB
}

func (db sqlOracleDB) PingContext(ctx context.Context) error { return db.db.PingContext(ctx) }

func (db sqlOracleDB) Close() error { return db.db.Close() }

var openOracle = func(_ context.Context, dsn string) (oracleDB, error) {
	db, err := sql.Open("oracle", dsn)
	if err != nil {
		return nil, err
	}
	return sqlOracleDB{db: db}, nil
}

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "oracle" }

func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }

func (prober) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "oracle"
}

func (prober) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, creds []core.Credential) core.SecurityResult {
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
	}
	successResult := result
	successFound := false
	attempted := false
	attemptTimeout := oracleAttemptTimeout(opts.Timeout)

	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			if successFound {
				return successResult
			}
			result.Error = err.Error()
			result.FailureReason = classifyOracleFailure(err)
			return result
		}
		if !attempted {
			attempted = true
			result.Stage = core.StageAttempted
		}

		for _, dsn := range buildOracleDSNAttempts(candidate, cred, opts) {
			db, err := openOracle(ctx, dsn)
			if err != nil {
				result.Error = err.Error()
				result.FailureReason = classifyOracleFailure(err)
				if isTerminalOracleFailure(result.FailureReason) {
					if successFound {
						return successResult
					}
					return result
				}
				continue
			}

			pingCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
			err = db.PingContext(pingCtx)
			cancel()
			_ = db.Close()
			if err == nil {
				successResult.Success = true
				successResult.Username = cred.Username
				successResult.Password = cred.Password
				successResult.Evidence = "Oracle authentication succeeded"
				successResult.Error = ""
				successResult.Stage = core.StageConfirmed
				successResult.FailureReason = ""
				successFound = true
				if opts.StopOnSuccess {
					return successResult
				}
				break
			}

			result.Error = err.Error()
			result.FailureReason = classifyOracleFailure(err)
			if isTerminalOracleFailure(result.FailureReason) {
				if successFound {
					return successResult
				}
				return result
			}
		}
	}

	if successFound {
		return successResult
	}
	return result
}

func buildOracleDSNAttempts(candidate core.SecurityCandidate, cred core.Credential, opts core.CredentialProbeOptions) []string {
	host := candidate.ResolvedIP
	if host == "" {
		host = candidate.Target
	}

	timeoutSeconds := int(oracleAttemptTimeout(opts.Timeout).Seconds())
	if timeoutSeconds <= 0 {
		timeoutSeconds = 5
	}

	serviceNames := []string{"XEPDB1", "ORCLPDB1", "XE", "ORCL"}
	out := make([]string, 0, len(serviceNames))
	for _, serviceName := range serviceNames {
		query := url.Values{}
		query.Set("timeout", fmt.Sprintf("%d", timeoutSeconds))
		out = append(out, (&url.URL{
			Scheme:   "oracle",
			User:     url.UserPassword(cred.Username, cred.Password),
			Host:     fmt.Sprintf("%s:%d", host, candidate.Port),
			Path:     serviceName,
			RawQuery: query.Encode(),
		}).String())
	}
	return out
}

func oracleAttemptTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return 5 * time.Second
	}
	return timeout
}

func classifyOracleFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "ora-01017"), strings.Contains(text, "invalid username/password"), strings.Contains(text, "logon denied"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "ora-12514"), strings.Contains(text, "ora-12541"), strings.Contains(text, "listener"), strings.Contains(text, "refused"), strings.Contains(text, "no route"):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}

func ctxFailureReason(err error) core.FailureReason {
	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), strings.Contains(text, "context canceled"):
		return core.FailureReasonCanceled
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return core.FailureReasonTimeout
	default:
		return ""
	}
}

func isTerminalOracleFailure(reason core.FailureReason) bool {
	return reason == core.FailureReasonCanceled || reason == core.FailureReasonTimeout
}
