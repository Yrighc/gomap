package assetprobe

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/hostdiscovery"
)

func testDiscoverHostsOptions() DiscoverHostsOptions {
	return DiscoverHostsOptions{
		HostDiscovery: HostDiscoveryOptions{
			Modes: []HostDiscoveryMode{HostDiscoveryTCPConnect},
			Ports: []int{80},
		},
	}
}

func replaceRunHostDiscovery(t *testing.T, fn func(context.Context, string, HostDiscoveryOptions) (hostdiscovery.Result, error)) {
	t.Helper()
	original := runHostDiscovery
	runHostDiscovery = fn
	t.Cleanup(func() { runHostDiscovery = original })
}

func TestDiscoverHostsZeroValueScannerAndDisabledStillRun(t *testing.T) {
	var calls atomic.Int32
	var events atomic.Int32
	scanner := &Scanner{opts: Options{
		OnEvent: func(ScanEvent) { events.Add(1) },
		HostDiscovery: HostDiscoveryOptions{
			Disabled: true,
		},
	}}

	replaceRunHostDiscovery(t, func(_ context.Context, ip string, opts HostDiscoveryOptions) (hostdiscovery.Result, error) {
		calls.Add(1)
		if opts.Disabled {
			t.Fatal("DiscoverHosts must ignore HostDiscovery.Disabled")
		}
		if opts.Modes != nil {
			t.Fatalf("expected automatic discovery defaults, got explicit modes: %#v", opts.Modes)
		}
		wantPorts := []int{80, 443, 22, 445, 3389, 8080, 3306, 6379}
		if !reflect.DeepEqual(opts.Ports, wantPorts) {
			t.Fatalf("expected default TCP discovery ports %v, got %v", wantPorts, opts.Ports)
		}
		return hostdiscovery.Result{Matched: true, Method: "tcp-connect"}, nil
	})

	result, err := scanner.DiscoverHosts(context.Background(), []string{"127.0.0.1"}, DiscoverHostsOptions{
		HostDiscovery: HostDiscoveryOptions{Disabled: true},
	})
	if err != nil {
		t.Fatalf("DiscoverHosts returned error: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one discovery call, got %d", calls.Load())
	}
	if events.Load() != 0 {
		t.Fatalf("DiscoverHosts emitted %d scan events", events.Load())
	}
	if got := result.Results; len(got) != 1 || !got[0].Matched || got[0].Method != "tcp-connect" || got[0].Error != "" {
		t.Fatalf("unexpected discovery result: %#v", got)
	}
}

func TestDiscoverHostsReturnsOrderedTargetOutcomes(t *testing.T) {
	var calls atomic.Int32
	replaceRunHostDiscovery(t, func(_ context.Context, ip string, _ HostDiscoveryOptions) (hostdiscovery.Result, error) {
		calls.Add(1)
		switch ip {
		case "127.0.0.0":
			return hostdiscovery.Result{Matched: true, Method: "icmp-echo"}, nil
		case "127.0.0.2":
			return hostdiscovery.Result{}, errors.New("probe failed")
		default:
			return hostdiscovery.Result{}, nil
		}
	})

	var scanner Scanner
	result, err := scanner.DiscoverHosts(context.Background(), []string{
		" 127.0.0.0/30 ",
		"127.0.0.2",
		"not-an-ip",
		"10.0.0.1/99",
	}, testDiscoverHostsOptions())
	if err != nil {
		t.Fatalf("DiscoverHosts returned error: %v", err)
	}

	wantTargets := []string{
		"127.0.0.0", "127.0.0.1", "127.0.0.2", "127.0.0.3", "not-an-ip", "10.0.0.1/99",
	}
	if len(result.Results) != len(wantTargets) {
		t.Fatalf("expected %d results, got %#v", len(wantTargets), result.Results)
	}
	for i, target := range wantTargets {
		if result.Results[i].Target != target {
			t.Fatalf("result %d target: want %q, got %#v", i, target, result.Results[i])
		}
	}
	if !result.Results[0].Matched || result.Results[0].Method != "icmp-echo" || result.Results[0].ResolvedIP != "127.0.0.0" {
		t.Fatalf("expected first target match, got %#v", result.Results[0])
	}
	if result.Results[1].Matched || result.Results[1].Method != "" || result.Results[1].Error != "" {
		t.Fatalf("expected normal no-signal result, got %#v", result.Results[1])
	}
	if result.Results[2].Error != "probe failed" || result.Results[2].ResolvedIP != "127.0.0.2" {
		t.Fatalf("expected probe failure, got %#v", result.Results[2])
	}
	for _, index := range []int{4, 5} {
		if result.Results[index].ResolvedIP != "" || result.Results[index].Error == "" {
			t.Fatalf("expected invalid target error, got %#v", result.Results[index])
		}
	}
	if calls.Load() != 4 {
		t.Fatalf("expected four valid IP calls, got %d", calls.Load())
	}
}

func TestDiscoverHostsMatchesScanPreDiscoveryNoSignal(t *testing.T) {
	var received []HostDiscoveryOptions
	replaceRunHostDiscovery(t, func(_ context.Context, _ string, opts HostDiscoveryOptions) (hostdiscovery.Result, error) {
		wantPorts := []int{80, 443, 22, 445, 3389, 8080, 3306, 6379}
		if !reflect.DeepEqual(opts.Ports, wantPorts) {
			t.Fatalf("expected shared default TCP discovery ports %v, got %v", wantPorts, opts.Ports)
		}
		received = append(received, opts)
		return hostdiscovery.Result{}, nil
	})

	scanner, err := NewScanner(Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := scanner.DiscoverHosts(context.Background(), []string{"127.0.0.1"}, DiscoverHostsOptions{})
	if err != nil {
		t.Fatalf("DiscoverHosts returned error: %v", err)
	}
	if len(discovery.Results) != 1 || discovery.Results[0].Matched || discovery.Results[0].Error != "" {
		t.Fatalf("unexpected standalone no-signal result: %#v", discovery)
	}

	single, err := scanner.Scan(context.Background(), ScanRequest{
		Target: "127.0.0.1", Ports: []int{1}, Protocol: ProtocolTCP,
	})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(single.Ports) != 0 {
		t.Fatalf("Scan did not preserve pre-discovery no-signal behavior: %#v", single)
	}

	batch, err := scanner.ScanTargets(context.Background(), []string{"127.0.0.1"}, ScanCommonOptions{
		Ports: []int{1}, Protocol: ProtocolTCP,
	})
	if err != nil {
		t.Fatalf("ScanTargets returned error: %v", err)
	}
	if len(batch.Results) != 1 || batch.Results[0].Result == nil || len(batch.Results[0].Result.Ports) != 0 || batch.Results[0].Error != "" {
		t.Fatalf("ScanTargets did not preserve pre-discovery no-signal behavior: %#v", batch)
	}
	if len(received) != 3 {
		t.Fatalf("expected standalone, Scan, and ScanTargets calls, got %d", len(received))
	}
	for i := 1; i < len(received); i++ {
		if !reflect.DeepEqual(received[0], received[i]) {
			t.Fatalf("discovery configuration differs at call %d:\nstandalone=%#v\ngot=%#v", i, received[0], received[i])
		}
	}
}

func TestDiscoverHostsCIDRExpansionAndLimits(t *testing.T) {
	var calls atomic.Int32
	replaceRunHostDiscovery(t, func(context.Context, string, HostDiscoveryOptions) (hostdiscovery.Result, error) {
		calls.Add(1)
		return hostdiscovery.Result{}, nil
	})

	if defaultDiscoverHostsMaxTargets != 65536 {
		t.Fatalf("unexpected default MaxTargets: %d", defaultDiscoverHostsMaxTargets)
	}
	if !cidrAddressCountExceeds(63, defaultDiscoverHostsMaxTargets) {
		t.Fatal("large CIDR size must not wrap before the MaxTargets check")
	}
	var scanner Scanner
	opts := testDiscoverHostsOptions()
	opts.MaxTargets = 4

	result, err := scanner.DiscoverHosts(context.Background(), []string{
		"127.0.0.0/30", "127.0.0.2/31",
	}, opts)
	if err != nil {
		t.Fatalf("overlapping CIDRs at the limit returned error: %v", err)
	}
	if got := len(result.Results); got != 4 {
		t.Fatalf("expected 4 de-duplicated IPv4 results, got %d", got)
	}
	if got := calls.Load(); got != 4 {
		t.Fatalf("expected 4 probe calls, got %d", got)
	}

	calls.Store(0)
	_, err = scanner.DiscoverHosts(context.Background(), []string{"10.0.0.0/8"}, DiscoverHostsOptions{
		HostDiscovery: opts.HostDiscovery,
		MaxTargets:    4,
	})
	if err == nil {
		t.Fatal("expected oversized CIDR to be rejected")
	}
	if calls.Load() != 0 {
		t.Fatalf("oversized CIDR started %d probes", calls.Load())
	}

	_, err = scanner.DiscoverHosts(context.Background(), []string{"not-an-ip", "127.0.0.1"}, DiscoverHostsOptions{
		HostDiscovery: opts.HostDiscovery,
		MaxTargets:    1,
	})
	if err == nil {
		t.Fatal("expected invalid target to count toward MaxTargets")
	}

	calls.Store(0)
	result, err = scanner.DiscoverHosts(context.Background(), []string{
		"2001:db8::1/127", "2001:db8::1/128",
	}, DiscoverHostsOptions{HostDiscovery: opts.HostDiscovery, MaxTargets: 2})
	if err != nil {
		t.Fatalf("IPv6 CIDR expansion returned error: %v", err)
	}
	gotTargets := []string{result.Results[0].Target, result.Results[1].Target}
	if want := []string{"2001:db8::", "2001:db8::1"}; !reflect.DeepEqual(gotTargets, want) {
		t.Fatalf("unexpected IPv6 targets: want %#v, got %#v", want, gotTargets)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected two IPv6 probe calls, got %d", calls.Load())
	}
}

func TestNormalizeDiscoveryTargetsCIDRBoundaries(t *testing.T) {
	got, err := normalizeDiscoveryTargets(context.Background(), []string{
		"127.0.0.1/31",
		"127.0.0.1/32",
		"2001:db8::3/126",
		"2001:db8::3/128",
	}, 8)
	if err != nil {
		t.Fatalf("normalizeDiscoveryTargets returned error: %v", err)
	}
	want := []string{
		"127.0.0.0", "127.0.0.1",
		"2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected CIDR boundaries:\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestDiscoverHostsCopiesConfigurationSlices(t *testing.T) {
	baseModes := []HostDiscoveryMode{HostDiscoveryICMPEcho}
	basePorts := []int{7}
	requestModes := []HostDiscoveryMode{HostDiscoveryTCPConnect}
	requestPorts := []int{80}
	scanner := &Scanner{opts: Options{HostDiscovery: HostDiscoveryOptions{
		Modes: baseModes,
		Ports: basePorts,
	}}}
	replaceRunHostDiscovery(t, func(_ context.Context, _ string, opts HostDiscoveryOptions) (hostdiscovery.Result, error) {
		opts.Modes[0] = HostDiscoveryARP
		opts.Ports[0] = 1
		return hostdiscovery.Result{}, nil
	})

	_, err := scanner.DiscoverHosts(context.Background(), []string{"127.0.0.1"}, DiscoverHostsOptions{
		HostDiscovery: HostDiscoveryOptions{Modes: requestModes, Ports: requestPorts},
	})
	if err != nil {
		t.Fatalf("DiscoverHosts returned error: %v", err)
	}
	if !reflect.DeepEqual(baseModes, []HostDiscoveryMode{HostDiscoveryICMPEcho}) || !reflect.DeepEqual(basePorts, []int{7}) {
		t.Fatalf("Scanner configuration was mutated: modes=%#v ports=%#v", baseModes, basePorts)
	}
	if !reflect.DeepEqual(requestModes, []HostDiscoveryMode{HostDiscoveryTCPConnect}) || !reflect.DeepEqual(requestPorts, []int{80}) {
		t.Fatalf("request configuration was mutated: modes=%#v ports=%#v", requestModes, requestPorts)
	}
}

func TestDiscoverHostsValidatesSharedOptionsBeforeDispatch(t *testing.T) {
	var calls atomic.Int32
	replaceRunHostDiscovery(t, func(context.Context, string, HostDiscoveryOptions) (hostdiscovery.Result, error) {
		calls.Add(1)
		return hostdiscovery.Result{}, nil
	})

	var scanner Scanner
	_, err := scanner.DiscoverHosts(context.Background(), []string{"127.0.0.1"}, DiscoverHostsOptions{
		HostDiscovery: HostDiscoveryOptions{
			Modes: []HostDiscoveryMode{HostDiscoveryTCPConnect},
			Ports: []int{0},
		},
	})
	if !errors.Is(err, hostdiscovery.ErrInvalidOptions) {
		t.Fatalf("expected shared configuration validation error, got %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid configuration started %d probes", calls.Load())
	}
}

func TestDiscoverHostsConcurrencyBound(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	started := make(chan string, 2)
	release := make(chan struct{})
	replaceRunHostDiscovery(t, func(ctx context.Context, ip string, _ HostDiscoveryOptions) (hostdiscovery.Result, error) {
		current := active.Add(1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		defer active.Add(-1)
		started <- ip
		select {
		case <-release:
			return hostdiscovery.Result{Matched: true, Method: "tcp-connect"}, nil
		case <-ctx.Done():
			return hostdiscovery.Result{}, ctx.Err()
		}
	})

	var scanner Scanner
	done := make(chan struct {
		result *BatchHostDiscoveryResult
		err    error
	}, 1)
	go func() {
		result, err := scanner.DiscoverHosts(context.Background(), []string{
			"127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4",
		}, DiscoverHostsOptions{
			HostDiscovery: testDiscoverHostsOptions().HostDiscovery,
			Concurrency:   2,
		})
		done <- struct {
			result *BatchHostDiscoveryResult
			err    error
		}{result, err}
	}()

	for i := range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for worker %d", i)
		}
	}
	if got := maximum.Load(); got != 2 {
		t.Fatalf("expected exactly two concurrent discovery calls, got %d", got)
	}
	close(release)
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("DiscoverHosts returned error: %v", got.err)
		}
		if len(got.result.Results) != 4 {
			t.Fatalf("unexpected results: %#v", got.result)
		}
	case <-time.After(time.Second):
		t.Fatal("DiscoverHosts did not wait for all workers")
	}
	if got := maximum.Load(); got > 2 {
		t.Fatalf("concurrency limit exceeded: %d", got)
	}
}

func TestDiscoverHostsUsesDefaultConcurrencyLimit(t *testing.T) {
	const wantDefaultConcurrency = 32
	var active atomic.Int32
	var maximum atomic.Int32
	started := make(chan struct{}, wantDefaultConcurrency+1)
	release := make(chan struct{})
	replaceRunHostDiscovery(t, func(ctx context.Context, _ string, _ HostDiscoveryOptions) (hostdiscovery.Result, error) {
		current := active.Add(1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		defer active.Add(-1)
		started <- struct{}{}
		select {
		case <-release:
			return hostdiscovery.Result{}, nil
		case <-ctx.Done():
			return hostdiscovery.Result{}, ctx.Err()
		}
	})

	targets := make([]string, wantDefaultConcurrency+1)
	for i := range targets {
		targets[i] = "127.0.1." + strconv.Itoa(i+1)
	}
	var scanner Scanner
	done := make(chan error, 1)
	go func() {
		_, err := scanner.DiscoverHosts(context.Background(), targets, DiscoverHostsOptions{
			HostDiscovery: testDiscoverHostsOptions().HostDiscovery,
		})
		done <- err
	}()

	for i := 0; i < wantDefaultConcurrency; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for default worker %d", i)
		}
	}
	select {
	case <-started:
		t.Fatal("default DiscoverHosts concurrency exceeded 32")
	case <-time.After(100 * time.Millisecond):
	}
	if got := maximum.Load(); got != wantDefaultConcurrency {
		t.Fatalf("expected default discovery concurrency %d, got %d", wantDefaultConcurrency, got)
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("DiscoverHosts returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DiscoverHosts did not finish default worker cleanup")
	}
}

func TestScanTargetsBoundsPreDiscoveryConcurrencyIndependently(t *testing.T) {
	const wantDefaultConcurrency = 32
	var active atomic.Int32
	var maximum atomic.Int32
	started := make(chan struct{}, wantDefaultConcurrency+1)
	release := make(chan struct{})
	replaceRunHostDiscovery(t, func(ctx context.Context, _ string, _ HostDiscoveryOptions) (hostdiscovery.Result, error) {
		current := active.Add(1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		defer active.Add(-1)
		started <- struct{}{}
		select {
		case <-release:
			return hostdiscovery.Result{}, nil
		case <-ctx.Done():
			return hostdiscovery.Result{}, ctx.Err()
		}
	})

	targets := make([]string, wantDefaultConcurrency+1)
	for i := range targets {
		targets[i] = "127.0.0." + strconv.Itoa(i+1)
	}
	var scanner Scanner
	done := make(chan error, 1)
	go func() {
		_, err := scanner.ScanTargets(context.Background(), targets, ScanCommonOptions{
			Ports:           []int{1},
			Protocol:        ProtocolTCP,
			PortConcurrency: len(targets) * 2,
			HostDiscovery: HostDiscoveryOptions{
				Modes: []HostDiscoveryMode{HostDiscoveryTCPConnect},
				Ports: []int{80},
			},
		})
		done <- err
	}()

	for i := 0; i < wantDefaultConcurrency; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for discovery %d", i)
		}
	}
	select {
	case <-started:
		t.Fatal("pre-discovery exceeded its 32-target limit")
	case <-time.After(100 * time.Millisecond):
	}
	if got := maximum.Load(); got != wantDefaultConcurrency {
		t.Fatalf("expected %d concurrent discoveries, got %d", wantDefaultConcurrency, got)
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ScanTargets returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ScanTargets did not complete discovery cleanup")
	}
	if got := maximum.Load(); got > wantDefaultConcurrency {
		t.Fatalf("pre-discovery concurrency limit exceeded: %d", got)
	}
}

func TestDiscoverHostsCancellationPreservesPartialResults(t *testing.T) {
	startedSecond := make(chan struct{})
	replaceRunHostDiscovery(t, func(ctx context.Context, ip string, _ HostDiscoveryOptions) (hostdiscovery.Result, error) {
		if ip == "127.0.0.1" {
			return hostdiscovery.Result{Matched: true, Method: "tcp-connect"}, nil
		}
		if ip == "127.0.0.2" {
			close(startedSecond)
			<-ctx.Done()
			return hostdiscovery.Result{}, ctx.Err()
		}
		t.Fatalf("unexpected discovery call for %q after cancellation", ip)
		return hostdiscovery.Result{}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var scanner Scanner
	done := make(chan struct {
		result *BatchHostDiscoveryResult
		err    error
	}, 1)
	go func() {
		result, err := scanner.DiscoverHosts(ctx, []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}, DiscoverHostsOptions{
			HostDiscovery: testDiscoverHostsOptions().HostDiscovery,
			Concurrency:   1,
		})
		done <- struct {
			result *BatchHostDiscoveryResult
			err    error
		}{result, err}
	}()

	select {
	case <-startedSecond:
	case <-time.After(time.Second):
		t.Fatal("second discovery did not start")
	}
	cancel()

	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", got.err)
		}
		if got.result == nil || len(got.result.Results) != 3 {
			t.Fatalf("expected complete partial result list, got %#v", got.result)
		}
		if first := got.result.Results[0]; !first.Matched || first.Method != "tcp-connect" || first.Error != "" {
			t.Fatalf("completed result was not retained: %#v", first)
		}
		for i := 1; i < 3; i++ {
			result := got.result.Results[i]
			if result.Matched || result.Method != "" || result.Error != context.Canceled.Error() {
				t.Fatalf("result %d should be cancellation-marked, got %#v", i, result)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("DiscoverHosts did not finish cancellation cleanup")
	}
}

func TestDiscoverHostsReturnsCancellationBeforeExpansionWithoutProbes(t *testing.T) {
	var calls atomic.Int32
	replaceRunHostDiscovery(t, func(context.Context, string, HostDiscoveryOptions) (hostdiscovery.Result, error) {
		calls.Add(1)
		return hostdiscovery.Result{}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var scanner Scanner
	result, err := scanner.DiscoverHosts(ctx, []string{"127.0.0.0/30"}, testDiscoverHostsOptions())
	if !errors.Is(err, context.Canceled) || result != nil {
		t.Fatalf("expected expansion cancellation with no result, got result=%#v err=%v", result, err)
	}
	if calls.Load() != 0 {
		t.Fatalf("canceled expansion started %d probes", calls.Load())
	}
}
