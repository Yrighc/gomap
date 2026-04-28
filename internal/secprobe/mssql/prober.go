package mssql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"

	_ "github.com/microsoft/go-mssqldb"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

func New() core.Prober { return prober{} }

type prober struct{}

type rowScanner interface {
	Scan(dest ...any) error
}

type mssqlDB interface {
	PingContext(ctx context.Context) error
	QueryRowContext(ctx context.Context, query string, args ...any) rowScanner
	Close() error
}

type sqlMSSQLDB struct {
	db *sql.DB
}

func (db sqlMSSQLDB) PingContext(ctx context.Context) error {
	return db.db.PingContext(ctx)
}

func (db sqlMSSQLDB) QueryRowContext(ctx context.Context, query string, args ...any) rowScanner {
	return db.db.QueryRowContext(ctx, query, args...)
}

func (db sqlMSSQLDB) Close() error {
	return db.db.Close()
}

var openMSSQL = func(_ context.Context, dsn string) (mssqlDB, error) {
	db, err := sql.Open("sqlserver", dsn)
	if err != nil {
		return nil, err
	}
	return sqlMSSQLDB{db: db}, nil
}

func (prober) Name() string { return "mssql" }

func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }

func (prober) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "mssql"
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

	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			if successFound {
				return successResult
			}
			result.Error = err.Error()
			result.FailureReason = classifyMSSQLFailure(err)
			return result
		}
		if !attempted {
			attempted = true
			result.Stage = core.StageAttempted
		}

		for _, dsn := range buildDSNAttempts(candidate, cred, opts) {
			db, err := openMSSQL(ctx, dsn)
			if err != nil {
				result.Error = err.Error()
				result.FailureReason = classifyMSSQLFailure(err)
				if isTerminalContextError(err) {
					if successFound {
						return successResult
					}
					return result
				}
				if shouldContinueDSNAttempts(result.FailureReason) {
					continue
				}
				break
			}

			pingCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
			err = db.PingContext(pingCtx)
			cancel()
			if err == nil {
				successResult.Success = true
				successResult.Username = cred.Username
				successResult.Password = cred.Password
				successResult.Evidence = mssqlEvidence(ctx, db, opts)
				successResult.Error = ""
				successResult.Stage = core.StageConfirmed
				successResult.FailureReason = ""
				successFound = true
				_ = db.Close()
				if opts.StopOnSuccess {
					return successResult
				}
				break
			}

			result.Error = err.Error()
			result.FailureReason = classifyMSSQLFailure(err)
			_ = db.Close()
			if isTerminalContextError(err) {
				if successFound {
					return successResult
				}
				return result
			}
			if shouldContinueDSNAttempts(result.FailureReason) {
				continue
			}
			break
		}
	}

	if successFound {
		return successResult
	}
	return result
}

func buildDSNAttempts(candidate core.SecurityCandidate, cred core.Credential, opts core.CredentialProbeOptions) []string {
	return []string{
		buildDSN(candidate, cred, opts, "true"),
		buildDSN(candidate, cred, opts, "disable"),
	}
}

func buildDSN(candidate core.SecurityCandidate, cred core.Credential, opts core.CredentialProbeOptions, encryptMode string) string {
	query := url.Values{
		"database": []string{"master"},
		"encrypt":  []string{encryptMode},
		"app name": []string{"gomap-secprobe"},
	}
	if encryptMode != "disable" {
		query.Set("TrustServerCertificate", "true")
	}

	timeoutSeconds := int(math.Ceil(opts.Timeout.Seconds()))
	if timeoutSeconds > 0 {
		query.Set("dial timeout", fmt.Sprintf("%d", timeoutSeconds))
		query.Set("connection timeout", fmt.Sprintf("%d", timeoutSeconds))
	}

	return (&url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(cred.Username, cred.Password),
		Host:     fmt.Sprintf("%s:%d", candidate.ResolvedIP, candidate.Port),
		RawQuery: query.Encode(),
	}).String()
}

func shouldContinueDSNAttempts(reason core.FailureReason) bool {
	switch reason {
	case core.FailureReasonConnection, core.FailureReasonInsufficientConfirmation:
		return true
	default:
		return false
	}
}

func mssqlEvidence(ctx context.Context, db mssqlDB, opts core.CredentialProbeOptions) string {
	queryCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	var version string
	if err := db.QueryRowContext(queryCtx, "SELECT @@VERSION").Scan(&version); err == nil && version != "" {
		return fmt.Sprintf("MSSQL authentication succeeded (%s)", compactWhitespace(version))
	}
	return "MSSQL authentication succeeded"
}

func classifyMSSQLFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "login failed"),
		strings.Contains(text, "authentication"),
		strings.Contains(text, "password"),
		strings.Contains(text, "credential"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"),
		strings.Contains(text, "connect"),
		strings.Contains(text, "connection"),
		strings.Contains(text, "refused"),
		strings.Contains(text, "reset by peer"),
		strings.Contains(text, "broken pipe"),
		strings.Contains(text, "no route"):
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
	case errors.Is(err, context.DeadlineExceeded),
		strings.Contains(text, "deadline exceeded"),
		strings.Contains(text, "timeout"),
		strings.Contains(text, "timed out"):
		return core.FailureReasonTimeout
	default:
		return ""
	}
}

func isTerminalContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func compactWhitespace(text string) string {
	return strings.Join(strings.Fields(text), " ")
}
