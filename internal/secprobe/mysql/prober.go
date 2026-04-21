package mysql

import (
	"context"
	"database/sql"
	"net"
	"strconv"

	gmysql "github.com/go-sql-driver/mysql"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "mysql" }

func (prober) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "mysql"
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

	addr := net.JoinHostPort(candidate.ResolvedIP, strconv.Itoa(candidate.Port))
	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			if successFound {
				return successResult
			}
			result.Error = err.Error()
			return result
		}

		cfg := gmysql.Config{
			User:                 cred.Username,
			Passwd:               cred.Password,
			Net:                  "tcp",
			Addr:                 addr,
			Timeout:              opts.Timeout,
			ReadTimeout:          opts.Timeout,
			WriteTimeout:         opts.Timeout,
			AllowNativePasswords: true,
		}

		db, err := sql.Open("mysql", cfg.FormatDSN())
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
			successResult.Evidence = "MySQL authentication succeeded"
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
