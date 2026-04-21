package ssh

import (
	"context"
	"errors"
	"net"
	"strconv"

	"github.com/yrighc/gomap/internal/secprobe/core"
	gssh "golang.org/x/crypto/ssh"
)

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "ssh" }

func (prober) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "ssh"
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

		config := &gssh.ClientConfig{
			User:            cred.Username,
			Auth:            []gssh.AuthMethod{gssh.Password(cred.Password)},
			HostKeyCallback: gssh.InsecureIgnoreHostKey(),
			Timeout:         opts.Timeout,
		}
		client, err := gssh.Dial("tcp", addr, config)
		if err == nil {
			_ = client.Close()
			successResult.Success = true
			successResult.Username = cred.Username
			successResult.Password = cred.Password
			successResult.Evidence = "SSH authentication succeeded"
			successResult.Error = ""
			successFound = true
			if opts.StopOnSuccess {
				return successResult
			}
			continue
		}

		result.Error = err.Error()
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			if successFound {
				return successResult
			}
			return result
		}
	}

	if successFound {
		return successResult
	}
	return result
}
