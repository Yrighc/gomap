package ftp

import (
	"context"
	"net"
	"strconv"

	jftp "github.com/jlaffaye/ftp"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "ftp" }

func (prober) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "ftp"
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

		conn, err := jftp.Dial(addr, jftp.DialWithTimeout(opts.Timeout))
		if err != nil {
			result.Error = err.Error()
			return result
		}

		err = conn.Login(cred.Username, cred.Password)
		_ = conn.Quit()
		if err == nil {
			successResult.Success = true
			successResult.Username = cred.Username
			successResult.Password = cred.Password
			successResult.Evidence = "FTP authentication succeeded"
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
