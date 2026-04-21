package postgresql

import (
	"context"
	"database/sql"
	"fmt"
	"math"

	_ "github.com/lib/pq"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "postgresql" }

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

	connectTimeout := int(math.Ceil(opts.Timeout.Seconds()))
	if connectTimeout < 1 {
		connectTimeout = 1
	}

	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			result.Error = err.Error()
			return result
		}

		dsn := fmt.Sprintf(
			"host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable connect_timeout=%d",
			candidate.ResolvedIP,
			candidate.Port,
			cred.Username,
			cred.Password,
			connectTimeout,
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
			result.Success = true
			result.Username = cred.Username
			result.Password = cred.Password
			result.Evidence = "PostgreSQL authentication succeeded"
			result.Error = ""
			return result
		}

		result.Error = err.Error()
	}

	return result
}
