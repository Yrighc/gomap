package secprobe

import "context"

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
