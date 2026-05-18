# AssetProbe HostDiscovery Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix HostDiscovery review issues so ICMP timeout does not block TCP fallback, ping is cancelable, and batch scans avoid serial host-discovery delays.

**Architecture:** Keep the public CLI/API unchanged and improve the internal HostDiscovery pipeline. ICMP becomes context-aware, TCP connect host discovery races common ports with bounded internal concurrency, and `ScanTargets` prepares target contexts concurrently before the existing batch port scan stages.

**Tech Stack:** Go, standard library `context`, `os/exec`, `net`, `sync`, `atomic`, existing `assetprobe` scanner package, existing `internal/hostdiscovery` package.

---

## File Structure

- Modify `internal/hostdiscovery/icmp_echo.go`: replace goroutine-wrapped `achieve.PingHost` with a context-aware ping command runner.
- Create `internal/hostdiscovery/icmp_echo_test.go`: cover ICMP timeout/no-signal and parent context cancellation using a test hook.
- Modify `internal/hostdiscovery/runner_test.go`: add fallback regression coverage where first mode returns no-signal and second mode matches.
- Modify `internal/hostdiscovery/tcp_connect.go`: add bounded concurrent TCP connect racing with cancellation after first match.
- Modify `internal/hostdiscovery/tcp_connect_test.go`: add deterministic tests for first-match return and parent context cancellation using a test hook.
- Modify `pkg/assetprobe/scanner.go`: extract per-target preparation and run it concurrently in `ScanTargets`.
- Modify `pkg/assetprobe/scanner_test.go`: add batch HostDiscovery concurrency and ordering tests using a package-level test hook for `runHostDiscovery`.

## Task 1: Fix ICMP Error Semantics And Cancellation

**Files:**
- Modify: `internal/hostdiscovery/icmp_echo.go`
- Create: `internal/hostdiscovery/icmp_echo_test.go`
- Modify: `internal/hostdiscovery/runner_test.go`

- [ ] **Step 1: Add failing ICMP tests**

Create `internal/hostdiscovery/icmp_echo_test.go` with this content:

```go
package hostdiscovery

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

func TestICMPEchoTimeoutReturnsNoSignal(t *testing.T) {
	origCommand := pingCommandContext
	t.Cleanup(func() { pingCommandContext = origCommand })

	pingCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sleep", "1")
	}

	result, err := newICMPEchoRunner(Options{
		Timeout: 10 * time.Millisecond,
	}).Run(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("expected timeout to be treated as no-signal, got error: %v", err)
	}
	if result.Matched {
		t.Fatalf("expected no matched result, got %+v", result)
	}
}

func TestICMPEchoParentContextCancelReturnsError(t *testing.T) {
	origCommand := pingCommandContext
	t.Cleanup(func() { pingCommandContext = origCommand })

	pingCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sleep", "1")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := newICMPEchoRunner(Options{
		Timeout: time.Second,
	}).Run(ctx, "127.0.0.1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
```

Append this test to `internal/hostdiscovery/runner_test.go`:

```go
func TestRunContinuesAfterNoSignalMode(t *testing.T) {
	orig := modeFactories
	t.Cleanup(func() { modeFactories = orig })

	modeFactories = map[string]func(Options) Runner{
		"icmp-echo": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				return Result{}, nil
			})
		},
		"tcp-connect": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				return Result{Matched: true, Method: "tcp-connect"}, nil
			})
		},
	}

	result, err := Run(context.Background(), "127.0.0.1", Options{
		Modes: []string{"icmp-echo", "tcp-connect"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Matched || result.Method != "tcp-connect" {
		t.Fatalf("unexpected result: %+v", result)
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/hostdiscovery -run 'TestICMPEchoTimeoutReturnsNoSignal|TestICMPEchoParentContextCancelReturnsError|TestRunContinuesAfterNoSignalMode' -v
```

Expected: FAIL because `pingCommandContext` is not defined and current ICMP timeout returns `context deadline exceeded`.

- [ ] **Step 3: Implement context-aware ICMP runner**

Replace `internal/hostdiscovery/icmp_echo.go` with:

```go
package hostdiscovery

import (
	"context"
	"net"
	"os/exec"
	"time"
)

var pingCommandContext = exec.CommandContext

func newICMPEchoRunner(opts Options) Runner {
	return RunnerFunc(func(ctx context.Context, ip string) (Result, error) {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = time.Second
		}
		pingCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		err := runPingCommand(pingCtx, ip)
		if err == nil {
			return Result{Matched: true, Method: "icmp-echo"}, nil
		}
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		return Result{}, nil
	})
}

func runPingCommand(ctx context.Context, host string) error {
	args := []string{"-c", "1", "-W", "3", host}
	name := "ping"
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		if _, err := exec.LookPath("ping6"); err == nil {
			name = "ping6"
			args = []string{"-c", "1", "-w", "3", host}
		} else {
			args = []string{"-6", "-c", "1", "-W", "3", host}
		}
	}
	return pingCommandContext(ctx, name, args...).Run()
}
```

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
go test ./internal/hostdiscovery -run 'TestICMPEchoTimeoutReturnsNoSignal|TestICMPEchoParentContextCancelReturnsError|TestRunContinuesAfterNoSignalMode' -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/hostdiscovery/icmp_echo.go internal/hostdiscovery/icmp_echo_test.go internal/hostdiscovery/runner_test.go
git commit -m "fix(assetprobe): 修复 icmp 存活探测超时语义"
```

## Task 2: Race TCP Connect Discovery Ports With Bounded Concurrency

**Files:**
- Modify: `internal/hostdiscovery/tcp_connect.go`
- Modify: `internal/hostdiscovery/tcp_connect_test.go`

- [ ] **Step 1: Add failing TCP connect concurrency tests**

Append these tests to `internal/hostdiscovery/tcp_connect_test.go`:

```go
func TestTCPConnectReturnsAfterFirstMatchedPort(t *testing.T) {
	origDial := tcpConnectDialContext
	t.Cleanup(func() { tcpConnectDialContext = origDial })

	hit := make(chan int, 8)
	tcpConnectDialContext = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
		_, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			return nil, err
		}
		hit <- port
		if port == 443 {
			server, client := net.Pipe()
			_ = server.Close()
			return client, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}

	result, err := newTCPConnectRunner(Options{
		Timeout: time.Second,
		Ports:   []int{80, 443, 22, 445, 3389},
	}).Run(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Matched || result.Method != "tcp-connect" {
		t.Fatalf("unexpected result: %+v", result)
	}

	seen443 := false
	for len(hit) > 0 {
		if <-hit == 443 {
			seen443 = true
		}
	}
	if !seen443 {
		t.Fatal("expected port 443 to be attempted")
	}
}

func TestTCPConnectParentContextCancelReturnsError(t *testing.T) {
	origDial := tcpConnectDialContext
	t.Cleanup(func() { tcpConnectDialContext = origDial })

	tcpConnectDialContext = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := newTCPConnectRunner(Options{
		Timeout: time.Second,
		Ports:   []int{80, 443},
	}).Run(ctx, "127.0.0.1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
```

Update the import block in `internal/hostdiscovery/tcp_connect_test.go` to include:

```go
import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"
)
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/hostdiscovery -run 'TestTCPConnectReturnsAfterFirstMatchedPort|TestTCPConnectParentContextCancelReturnsError' -v
```

Expected: FAIL because `tcpConnectDialContext` is not defined and the current implementation does not expose a deterministic dial hook.

- [ ] **Step 3: Implement bounded TCP connect racing**

Replace `internal/hostdiscovery/tcp_connect.go` with:

```go
package hostdiscovery

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"
)

const maxTCPConnectDiscoveryConcurrency = 8

var tcpConnectDialContext = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, network, address)
}

func newTCPConnectRunner(opts Options) Runner {
	return RunnerFunc(func(ctx context.Context, ip string) (Result, error) {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = time.Second
		}
		retries := opts.Retries
		if retries <= 0 {
			retries = 1
		}
		for attempt := 0; attempt < retries; attempt++ {
			result, err := raceTCPConnectPorts(ctx, ip, opts.Ports, timeout)
			if err != nil {
				return Result{}, err
			}
			if result.Matched {
				return result, nil
			}
		}
		return Result{}, nil
	})
}

func raceTCPConnectPorts(ctx context.Context, ip string, ports []int, timeout time.Duration) (Result, error) {
	if len(ports) == 0 {
		return Result{}, nil
	}
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	concurrency := len(ports)
	if concurrency > maxTCPConnectDiscoveryConcurrency {
		concurrency = maxTCPConnectDiscoveryConcurrency
	}
	jobs := make(chan int, len(ports))
	matched := make(chan struct{}, 1)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				select {
				case <-raceCtx.Done():
					return
				default:
				}
				address := net.JoinHostPort(ip, strconv.Itoa(port))
				conn, err := tcpConnectDialContext(raceCtx, "tcp", address, timeout)
				if err != nil {
					continue
				}
				_ = conn.Close()
				select {
				case matched <- struct{}{}:
					cancel()
				default:
				}
				return
			}
		}()
	}

	for _, port := range ports {
		jobs <- port
	}
	close(jobs)
	wg.Wait()

	select {
	case <-matched:
		return Result{Matched: true, Method: "tcp-connect"}, nil
	default:
	}
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	return Result{}, nil
}
```

- [ ] **Step 4: Run TCP connect tests**

Run:

```bash
go test ./internal/hostdiscovery -run 'TestTCPConnect' -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/hostdiscovery/tcp_connect.go internal/hostdiscovery/tcp_connect_test.go
git commit -m "feat(assetprobe): 并发探测 tcp 存活端口"
```

## Task 3: Run Batch HostDiscovery Concurrently In ScanTargets

**Files:**
- Modify: `pkg/assetprobe/scanner.go`
- Modify: `pkg/assetprobe/scanner_test.go`

- [ ] **Step 1: Add failing batch concurrency test**

Append this test to `pkg/assetprobe/scanner_test.go`:

```go
func TestScanTargetsRunsHostDiscoveryConcurrentlyAndKeepsOrder(t *testing.T) {
	origRunHostDiscovery := runHostDiscovery
	t.Cleanup(func() { runHostDiscovery = origRunHostDiscovery })

	started := make(chan string, 2)
	release := make(chan struct{})
	runHostDiscovery = func(ctx context.Context, ip string, opts HostDiscoveryOptions) (hostdiscovery.Result, error) {
		started <- ip
		<-release
		return hostdiscovery.Result{}, nil
	}

	scanner, err := NewScanner(Options{
		Timeout:         50 * time.Millisecond,
		PortConcurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan *BatchScanResult, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := scanner.ScanTargets(context.Background(), []string{"127.0.0.1", "127.0.0.2"}, ScanCommonOptions{
			PortSpec:        "65001",
			Protocol:        ProtocolTCP,
			PortConcurrency: 2,
		})
		if err != nil {
			errCh <- err
			return
		}
		done <- result
	}()

	first := <-started
	second := <-started
	if first == second {
		t.Fatalf("expected two distinct targets to start discovery, got %q and %q", first, second)
	}
	close(release)

	select {
	case err := <-errCh:
		t.Fatalf("unexpected error: %v", err)
	case result := <-done:
		if len(result.Results) != 2 {
			t.Fatalf("expected 2 results, got %d", len(result.Results))
		}
		if result.Results[0].Target != "127.0.0.1" || result.Results[1].Target != "127.0.0.2" {
			t.Fatalf("unexpected result order: %#v", result.Results)
		}
		if result.Results[0].Result == nil || result.Results[1].Result == nil {
			t.Fatalf("expected skipped targets to have empty results: %#v", result.Results)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ScanTargets")
	}
}
```

Update the import block in `pkg/assetprobe/scanner_test.go` to include:

```go
import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/hostdiscovery"
)
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
go test ./pkg/assetprobe -run 'TestScanTargetsRunsHostDiscoveryConcurrentlyAndKeepsOrder' -v
```

Expected: FAIL by timeout because current `ScanTargets` runs HostDiscovery serially and the second target cannot start before the first one is released.

- [ ] **Step 3: Make `runHostDiscovery` replaceable in tests**

In `pkg/assetprobe/scanner.go`, change:

```go
func runHostDiscovery(ctx context.Context, resolvedIP string, opts HostDiscoveryOptions) (hostdiscovery.Result, error) {
	return hostdiscovery.Run(ctx, resolvedIP, toInternalHostDiscoveryOptions(opts))
}
```

to:

```go
var runHostDiscovery = func(ctx context.Context, resolvedIP string, opts HostDiscoveryOptions) (hostdiscovery.Result, error) {
	return hostdiscovery.Run(ctx, resolvedIP, toInternalHostDiscoveryOptions(opts))
}
```

- [ ] **Step 4: Add concurrent target preparation helper**

In `pkg/assetprobe/scanner.go`, add this helper near the existing batch helper functions:

```go
func prepareBatchTargetContexts(
	ctx context.Context,
	targets []string,
	protocol Protocol,
	hostDiscovery HostDiscoveryOptions,
	timeout time.Duration,
	totalPorts int,
	concurrency int,
	results []TargetScanResult,
) []*batchTargetContext {
	contexts := make([]*batchTargetContext, len(targets))
	if len(targets) == 0 {
		return contexts
	}
	if concurrency <= 0 {
		concurrency = 1
	}
	if concurrency > len(targets) {
		concurrency = len(targets)
	}

	jobs := make(chan int, len(targets))
	for i := range targets {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				target := targets[idx]
				results[idx].Target = target
				resolvedIP, resolveErr := resolveTarget(target)
				if resolveErr != nil {
					results[idx].Error = resolveErr.Error()
					continue
				}
				if protocol == ProtocolTCP && !hostDiscovery.Disabled {
					discoveryResult, err := runHostDiscovery(ctx, resolvedIP, hostDiscovery)
					if err != nil {
						results[idx].Error = err.Error()
						continue
					}
					if !discoveryResult.Matched {
						results[idx].Result = emptyScanResult(target, resolvedIP, protocol)
						continue
					}
				}
				contexts[idx] = &batchTargetContext{
					index:      idx,
					target:     target,
					resolvedIP: resolvedIP,
					protocol:   protocol,
					timeout:    timeout,
					totalPorts: totalPorts,
				}
			}
		}()
	}
	wg.Wait()
	return contexts
}
```

- [ ] **Step 5: Use helper in `ScanTargets`**

In `pkg/assetprobe/scanner.go`, replace the serial block that initializes `results` and `contexts`:

```go
results := make([]TargetScanResult, len(normalized))
contexts := make([]*batchTargetContext, len(normalized))
for i, target := range normalized {
	results[i].Target = target
	resolvedIP, resolveErr := resolveTarget(target)
	if resolveErr != nil {
		results[i].Error = resolveErr.Error()
		continue
	}
	if opts.Protocol == ProtocolTCP && !hostDiscovery.Disabled {
		discoveryResult, err := runHostDiscovery(ctx, resolvedIP, hostDiscovery)
		if err != nil {
			results[i].Error = err.Error()
			continue
		}
		if !discoveryResult.Matched {
			results[i].Result = emptyScanResult(target, resolvedIP, opts.Protocol)
			continue
		}
	}

	contexts[i] = &batchTargetContext{
		index:      i,
		target:     target,
		resolvedIP: resolvedIP,
		protocol:   opts.Protocol,
		timeout:    timeout,
		totalPorts: len(ports),
	}
}
```

with:

```go
results := make([]TargetScanResult, len(normalized))
contexts := prepareBatchTargetContexts(
	ctx,
	normalized,
	opts.Protocol,
	hostDiscovery,
	timeout,
	len(ports),
	portConcurrency,
	results,
)
```

- [ ] **Step 6: Run batch scanner tests**

Run:

```bash
go test ./pkg/assetprobe -run 'TestScanTargetsRunsHostDiscoveryConcurrentlyAndKeepsOrder|TestScanTargetsSkipsPortScanWhenHostDiscoveryReturnsNoSignal|TestScanTargetsKeepsOrderAndPerTargetErrors|TestScanTargetsReturnsResultsInInputOrder' -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/assetprobe/scanner.go pkg/assetprobe/scanner_test.go
git commit -m "feat(assetprobe): 并发执行批量主机存活探测"
```

## Task 4: Final Verification And Documentation Check

**Files:**
- Modify only if verification reveals stale docs or broken tests.

- [ ] **Step 1: Run focused package tests**

Run:

```bash
go test ./internal/hostdiscovery -v
```

Expected: PASS.

- [ ] **Step 2: Run scanner and CLI tests**

Run:

```bash
go test ./cmd ./pkg/assetprobe -v
```

Expected: PASS.

- [ ] **Step 3: Run combined verification**

Run:

```bash
go test ./cmd ./pkg/assetprobe ./internal/hostdiscovery -v
```

Expected: PASS.

- [ ] **Step 4: Check worktree and diff**

Run:

```bash
git status --short
git diff --check
```

Expected: `git diff --check` has no output. `git status --short` only shows intentional files if any verification follow-up changed docs or tests.

- [ ] **Step 5: Commit any verification follow-up**

If no files changed, skip this step. If docs or tests were updated during final verification, commit them:

```bash
git add <changed-files>
git commit -m "test(assetprobe): 完善主机存活探测验证"
```

## Self-Review

- Spec coverage: Task 1 covers ICMP timeout/no-signal and cancelable ping. Task 2 covers bounded concurrent TCP connect racing. Task 3 covers concurrent batch HostDiscovery and ordered results. Task 4 covers final verification.
- Placeholder scan: no unfinished placeholder markers are present.
- Type consistency: all referenced package types already exist except test hooks introduced in the relevant implementation tasks: `pingCommandContext`, `tcpConnectDialContext`, and replaceable `runHostDiscovery`.
- Scope check: plan does not add CLI/API fields, does not change `ScanResult`, does not rewrite `tcp-syn`/`tcp-ack`/`arp`, and leaves UDP unchanged.
