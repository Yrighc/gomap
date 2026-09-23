package assetprobe

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/yrighc/gomap/internal/hostdiscovery"
)

const (
	defaultDiscoverHostsConcurrency = 32
	defaultDiscoverHostsMaxTargets  = 65536
)

type hostDiscoveryJob struct {
	index      int
	resolvedIP string
}

// DiscoverHosts runs only host discovery for IP and CIDR targets. It does not
// initialize scan assets, scan ports, identify services, fetch pages, or emit
// scan events. Normal no-signal results are returned as Matched=false with an
// empty Method and Error; they do not prove that a host is offline.
func (s *Scanner) DiscoverHosts(
	ctx context.Context,
	targets []string,
	opts DiscoverHostsOptions,
) (*BatchHostDiscoveryResult, error) {
	if s == nil {
		return nil, errors.New("scanner is nil")
	}
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	maxTargets := opts.MaxTargets
	if maxTargets <= 0 {
		maxTargets = defaultDiscoverHostsMaxTargets
	}
	normalized, err := normalizeDiscoveryTargets(ctx, targets, maxTargets)
	if err != nil {
		return nil, err
	}
	if len(normalized) == 0 {
		return nil, errors.New("targets is required")
	}

	probeOptions := s.discoverHostsOptions(opts.HostDiscovery)
	if err := hostdiscovery.ValidateOptions(toInternalHostDiscoveryOptions(probeOptions)); err != nil {
		return nil, err
	}

	results := make([]TargetHostDiscoveryResult, len(normalized))
	jobs := make([]hostDiscoveryJob, 0, len(normalized))
	for i, target := range normalized {
		results[i].Target = target
		ip := net.ParseIP(target)
		if ip == nil {
			results[i].Error = "target is not an IP address"
			continue
		}
		resolvedIP := ip.String()
		results[i].ResolvedIP = resolvedIP
		jobs = append(jobs, hostDiscoveryJob{index: i, resolvedIP: resolvedIP})
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = defaultDiscoverHostsConcurrency
	}
	if concurrency > len(jobs) {
		concurrency = len(jobs)
	}
	completed := make([]bool, len(results))
	jobCh := make(chan hostDiscoveryJob)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case job, ok := <-jobCh:
					if !ok {
						return
					}
					// The receive-side guard is also the final check before the
					// probe handoff.
					if ctx.Err() != nil {
						return
					}
					result, runErr := runHostDiscovery(ctx, job.resolvedIP, probeOptions)
					if ctx.Err() != nil {
						return
					}

					targetResult := &results[job.index]
					if runErr != nil {
						targetResult.Error = runErr.Error()
					} else if result.Matched {
						targetResult.Matched = true
						targetResult.Method = result.Method
					}
					completed[job.index] = true
				}
			}
		}()
	}

	dispatchCanceled := false
	for _, job := range jobs {
		if ctx.Err() != nil {
			dispatchCanceled = true
			break
		}
		select {
		case <-ctx.Done():
			dispatchCanceled = true
		case jobCh <- job:
		}
		if dispatchCanceled {
			break
		}
	}
	close(jobCh)
	wg.Wait()

	if err := ctx.Err(); err != nil {
		for i := range results {
			if !completed[i] && results[i].Error == "" {
				results[i].Matched = false
				results[i].Method = ""
				results[i].Error = err.Error()
			}
		}
		return &BatchHostDiscoveryResult{Results: results}, err
	}
	return &BatchHostDiscoveryResult{Results: results}, nil
}

func (s *Scanner) discoverHostsOptions(override HostDiscoveryOptions) HostDiscoveryOptions {
	base := s.opts
	applyDefaults(&base)
	merged := mergeHostDiscoveryOptions(base.HostDiscovery, override)
	// Disabled controls only the Scan and ScanTargets pre-discovery stage. An
	// explicit standalone call must always attempt discovery.
	merged.Disabled = false
	return merged
}
