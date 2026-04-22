package postgresql

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"net/url"

	_ "github.com/lib/pq"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "postgresql" }

func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }

func (prober) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "postgresql"
}

func (prober) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, creds []core.Credential) core.SecurityResult {
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		FindingType: core.FindingTypeCredentialValid,
	}
	successResult := result
	successFound := false

	connectTimeout := int(math.Ceil(opts.Timeout.Seconds()))
	if connectTimeout < 1 {
		connectTimeout = 1
	}

	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			if successFound {
				return successResult
			}
			result.Error = err.Error()
			return result
		}

		query := url.Values{
			"dbname":          []string{"postgres"},
			"sslmode":         []string{"disable"},
			"connect_timeout": []string{fmt.Sprintf("%d", connectTimeout)},
		}
		dsn := fmt.Sprintf(
			"postgres://%s@%s:%d?%s",
			url.UserPassword(cred.Username, cred.Password).String(),
			candidate.ResolvedIP,
			candidate.Port,
			query.Encode(),
		)

		db, err := sql.Open("postgres", dsn)
		if err != nil {
			result.Error = err.Error()
			return result
		}

		pingCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
		err = db.PingContext(pingCtx)
		cancel()
		_ = db.Close()
		if err == nil {
			successResult.Success = true
			successResult.Username = cred.Username
			successResult.Password = cred.Password
			successResult.Evidence = "PostgreSQL authentication succeeded"
			successResult.Error = ""
			successFound = true
			if opts.StopOnSuccess {
				return successResult
			}
			continue
		}

		result.Error = err.Error()
	}

	if successFound {
		return successResult
	}
	return result
}
