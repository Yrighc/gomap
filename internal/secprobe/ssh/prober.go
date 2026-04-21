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

	addr := net.JoinHostPort(candidate.ResolvedIP, strconv.Itoa(candidate.Port))
	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
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
			result.Success = true
			result.Username = cred.Username
			result.Password = cred.Password
			result.Evidence = "SSH authentication succeeded"
			return result
		}

		result.Error = err.Error()
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return result
		}
	}

	return result
}
