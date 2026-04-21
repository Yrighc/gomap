package secprobe

import (
	"context"

	ftpprobe "github.com/yrighc/gomap/internal/secprobe/ftp"
	sshprobe "github.com/yrighc/gomap/internal/secprobe/ssh"
	telnetprobe "github.com/yrighc/gomap/internal/secprobe/telnet"
)

func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(sshprobe.New())
	r.Register(ftpprobe.New())
	r.Register(telnetprobe.New())
	return r
}

func RunWithRegistry(ctx context.Context, registry *Registry, candidates []SecurityCandidate, opts CredentialProbeOptions) RunResult {
	_ = opts

	result := RunResult{}
	result.Meta.Candidates = len(candidates)

	for _, candidate := range candidates {
		if ctx.Err() != nil {
			break
		}

		if _, ok := registry.Lookup(candidate); !ok {
			result.Meta.Skipped++
		}
	}

	return result
}
