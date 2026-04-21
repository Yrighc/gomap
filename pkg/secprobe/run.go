package secprobe

import "context"

func RunWithRegistry(ctx context.Context, registry *Registry, candidates []SecurityCandidate, opts CredentialProbeOptions) RunResult {
	result := RunResult{}
	result.Meta.Candidates = len(candidates)

	for _, candidate := range candidates {
		if ctx.Err() != nil {
			break
		}

		prober, ok := registry.Lookup(candidate)
		if !ok {
			result.Meta.Skipped++
			result.Results = append(result.Results, SecurityResult{
				Target:      candidate.Target,
				ResolvedIP:  candidate.ResolvedIP,
				Port:        candidate.Port,
				Service:     candidate.Service,
				FindingType: FindingTypeCredentialValid,
				Error:       "unsupported protocol",
			})
			continue
		}

		creds, err := CredentialsFor(candidate.Service, opts)
		if err != nil {
			result.Meta.Failed++
			result.Results = append(result.Results, SecurityResult{
				Target:      candidate.Target,
				ResolvedIP:  candidate.ResolvedIP,
				Port:        candidate.Port,
				Service:     candidate.Service,
				FindingType: FindingTypeCredentialValid,
				Error:       err.Error(),
			})
			continue
		}

		result.Meta.Attempted++
		item := prober.Probe(ctx, candidate, opts, creds)
		if item.Success {
			result.Meta.Succeeded++
		} else {
			result.Meta.Failed++
		}
		result.Results = append(result.Results, item)
	}

	return result
}
