# Assetprobe Host Discovery And Scan Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add default-on host discovery with `-Pn` compatibility and refactor TCP scanning into a discovery stage plus fingerprint stage without changing `ScanResult` or JSON output shape.

**Architecture:** Introduce a dedicated `internal/hostdiscovery` package that decides whether a target should proceed to port scanning, then rework `pkg/assetprobe.Scanner` so TCP scanning first discovers open ports and only then fingerprints them. Keep public result models unchanged and expose the new behavior through CLI flags plus request/common options.

**Tech Stack:** Go 1.24, `flag`, `net`, existing `pkg/assetprobe`, existing `internal/achieve`, shell-outs for host discovery compatibility modes, Go test

---

## File Structure

**Create:**

- `internal/hostdiscovery/runner.go`
- `internal/hostdiscovery/modes.go`
- `internal/hostdiscovery/tcp_connect.go`
- `internal/hostdiscovery/icmp_echo.go`
- `internal/hostdiscovery/command_modes.go`
- `internal/hostdiscovery/errors.go`
- `internal/hostdiscovery/runner_test.go`
- `internal/hostdiscovery/tcp_connect_test.go`
- `internal/hostdiscovery/command_modes_test.go`
- `docs/superpowers/plans/2026-05-18-assetprobe-host-discovery-and-scan-pipeline.md`

**Modify:**

- `pkg/assetprobe/types.go`
- `pkg/assetprobe/scanner.go`
- `pkg/assetprobe/scanner_test.go`
- `cmd/main.go`
- `cmd/main_test.go`
- `README.md`
- `pkg/assetprobe/README.md`

**Responsibilities:**

- `internal/hostdiscovery/*`: all host discovery mode execution, mode ordering, environment availability checks, and short-circuit semantics
- `pkg/assetprobe/types.go`: request/common/options config surface for host discovery, without touching result types
- `pkg/assetprobe/scanner.go`: integrate host discovery into `Scan`/`ScanTargets` and split TCP work into discovery/fingerprint phases
- `cmd/main.go`: default-on host discovery flags, `-Pn` compatibility, forwarding to scanner options
- `*_test.go`: lock behavior before implementation and prevent JSON/result regressions

### Task 1: Add Host Discovery Config Surface And CLI Flags

**Files:**

- Modify: `/Users/yrighc/work/hzyz/project/GoMap/pkg/assetprobe/types.go`
- Modify: `/Users/yrighc/work/hzyz/project/GoMap/cmd/main.go`
- Modify: `/Users/yrighc/work/hzyz/project/GoMap/cmd/main_test.go`

- [ ] **Step 1: Write the failing CLI forwarding tests**

Add these tests to `/Users/yrighc/work/hzyz/project/GoMap/cmd/main_test.go`:

```go
func TestRunPortDefaultsToHostDiscovery(t *testing.T) {
	scanner := &stubPortScanner{
		batch: &assetprobe.BatchScanResult{
			Results: []assetprobe.TargetScanResult{{
				Target: "demo",
				Result: &assetprobe.ScanResult{Target: "demo", Protocol: assetprobe.ProtocolTCP},
			}},
		},
	}
	restore := stubPortScannerFactory(scanner)
	defer restore()

	stdout, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{"-target", "demo", "-ports", "80"})
	})
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%s stdout=%s", exitCode, stderr, stdout)
	}
	if scanner.gotOpts.HostDiscovery.Disabled {
		t.Fatal("expected host discovery enabled by default")
	}
	if len(scanner.gotOpts.HostDiscovery.Modes) == 0 {
		t.Fatal("expected default host discovery modes to be forwarded")
	}
}

func TestRunPortPnDisablesHostDiscovery(t *testing.T) {
	scanner := &stubPortScanner{
		batch: &assetprobe.BatchScanResult{
			Results: []assetprobe.TargetScanResult{{
				Target: "demo",
				Result: &assetprobe.ScanResult{Target: "demo", Protocol: assetprobe.ProtocolTCP},
			}},
		},
	}
	restore := stubPortScannerFactory(scanner)
	defer restore()

	_, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{"-target", "demo", "-ports", "80", "-Pn"})
	})
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%s", exitCode, stderr)
	}
	if !scanner.gotOpts.HostDiscovery.Disabled {
		t.Fatal("expected -Pn to disable host discovery")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
go test ./cmd -run 'TestRunPortDefaultsToHostDiscovery|TestRunPortPnDisablesHostDiscovery' -v
```

Expected: FAIL because `ScanCommonOptions.HostDiscovery` and `-Pn` do not exist yet.

- [ ] **Step 3: Add host discovery config types to assetprobe**

Update `/Users/yrighc/work/hzyz/project/GoMap/pkg/assetprobe/types.go` with these additions:

```go
type HostDiscoveryMode string

const (
	HostDiscoveryICMPEcho   HostDiscoveryMode = "icmp-echo"
	HostDiscoveryTCPSYN     HostDiscoveryMode = "tcp-syn"
	HostDiscoveryTCPACK     HostDiscoveryMode = "tcp-ack"
	HostDiscoveryARP        HostDiscoveryMode = "arp"
	HostDiscoveryTCPConnect HostDiscoveryMode = "tcp-connect"
)

type HostDiscoveryOptions struct {
	Disabled bool
	Modes    []HostDiscoveryMode
	Timeout  time.Duration
	Retries  int
	Ports    []int
}
```

Thread the same field through scanner inputs:

```go
type Options struct {
	// ...
	HostDiscovery HostDiscoveryOptions
}

type ScanRequest struct {
	// ...
	HostDiscovery HostDiscoveryOptions
}

type ScanCommonOptions struct {
	// ...
	HostDiscovery HostDiscoveryOptions
}
```

- [ ] **Step 4: Add `-Pn` and host discovery CLI flags**

Update `/Users/yrighc/work/hzyz/project/GoMap/cmd/main.go` in `runPort(...)`:

```go
	disableHostDiscovery := fs.Bool("Pn", false, "[可选] 跳过主机存活验证，直接扫描端口")
	hostDiscoveryModes := fs.String("host-discovery-mode", "icmp-echo,tcp-connect", "[可选] 主机存活验证模式，逗号分隔")
	hostDiscoveryTimeout := fs.Int("host-discovery-timeout", 1, "[可选] 主机存活验证超时秒数")
	hostDiscoveryRetries := fs.Int("host-discovery-retries", 1, "[可选] 主机存活验证重试次数")
	hostDiscoveryPorts := fs.String("host-discovery-ports", "80,443,22,445,3389", "[可选] TCP 类主机存活验证端口")
```

Add a helper near the bottom of the file:

```go
func buildHostDiscoveryOptions(disabled bool, modes string, timeoutSeconds int, retries int, ports string) (assetprobe.HostDiscoveryOptions, error) {
	parsedPorts, err := parsePortSpec(ports)
	if err != nil {
		return assetprobe.HostDiscoveryOptions{}, err
	}
	modeValues := splitComma(modes)
	parsedModes := make([]assetprobe.HostDiscoveryMode, 0, len(modeValues))
	for _, mode := range modeValues {
		parsedModes = append(parsedModes, assetprobe.HostDiscoveryMode(mode))
	}
	return assetprobe.HostDiscoveryOptions{
		Disabled: disabled,
		Modes:    parsedModes,
		Timeout:  time.Duration(timeoutSeconds) * time.Second,
		Retries:  retries,
		Ports:    parsedPorts,
	}, nil
}
```

Forward the built value into `assetprobe.Options` and `assetprobe.ScanCommonOptions`:

```go
	hostDiscovery, err := buildHostDiscoveryOptions(*disableHostDiscovery, *hostDiscoveryModes, *hostDiscoveryTimeout, *hostDiscoveryRetries, *hostDiscoveryPorts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitPort(1)
	}

	scanner, err := newPortTargetScanner(assetprobe.Options{
		PortConcurrency: finalPortConcurrency,
		PortRateLimit:   finalPortRateLimit,
		Timeout:         time.Duration(*timeout) * time.Second,
		ConsoleLog:      *verbose,
		HostDiscovery:   hostDiscovery,
	})
```

And:

```go
	batchRes, err := scanner.ScanTargets(context.Background(), targets, assetprobe.ScanCommonOptions{
		PortSpec:              *ports,
		Protocol:              protocol,
		PortConcurrency:       finalPortConcurrency,
		PortRateLimit:         finalPortRateLimit,
		Timeout:               time.Duration(*timeout) * time.Second,
		MaxFingerprintPorts:   finalMaxFingerprintPorts,
		HoneypotOpenThreshold: *honeypotOpenThreshold,
		HoneypotOpenRatio:     *honeypotOpenRatio,
		HostDiscovery:         hostDiscovery,
	})
```

- [ ] **Step 5: Run the CLI tests to verify they pass**

Run:

```bash
go test ./cmd -run 'TestRunPortDefaultsToHostDiscovery|TestRunPortPnDisablesHostDiscovery' -v
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add /Users/yrighc/work/hzyz/project/GoMap/pkg/assetprobe/types.go /Users/yrighc/work/hzyz/project/GoMap/cmd/main.go /Users/yrighc/work/hzyz/project/GoMap/cmd/main_test.go
git commit -m "feat(assetprobe): add host discovery config surface"
```

### Task 2: Implement Host Discovery Core Runner

**Files:**

- Create: `/Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/errors.go`
- Create: `/Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/modes.go`
- Create: `/Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/runner.go`
- Create: `/Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/runner_test.go`

- [ ] **Step 1: Write failing runner tests**

Create `/Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/runner_test.go`:

```go
package hostdiscovery

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunStopsOnFirstMatchedMode(t *testing.T) {
	orig := modeFactories
	t.Cleanup(func() { modeFactories = orig })

	modeFactories = map[string]func(Options) Runner{
		"first": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				return Result{}, nil
			})
		},
		"second": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				return Result{Matched: true, Method: "second"}, nil
			})
		},
	}

	result, err := Run(context.Background(), "127.0.0.1", Options{
		Modes:   []string{"first", "second"},
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Matched || result.Method != "second" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestRunReturnsErrorWhenAllModesUnavailable(t *testing.T) {
	orig := modeFactories
	t.Cleanup(func() { modeFactories = orig })

	modeFactories = map[string]func(Options) Runner{
		"icmp-echo": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				return Result{}, ErrModeUnavailable
			})
		},
	}

	_, err := Run(context.Background(), "127.0.0.1", Options{
		Modes:   []string{"icmp-echo"},
		Timeout: time.Second,
	})
	if !errors.Is(err, ErrNoUsableModes) {
		t.Fatalf("expected ErrNoUsableModes, got %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
go test ./internal/hostdiscovery -run 'TestRunStopsOnFirstMatchedMode|TestRunReturnsErrorWhenAllModesUnavailable' -v
```

Expected: FAIL because the package does not exist yet.

- [ ] **Step 3: Add the runner core**

Create `/Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/errors.go`:

```go
package hostdiscovery

import "errors"

var (
	ErrModeUnavailable = errors.New("host discovery mode unavailable")
	ErrNoUsableModes   = errors.New("no usable host discovery modes")
)
```

Create `/Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/modes.go`:

```go
package hostdiscovery

import (
	"context"
	"time"
)

type Options struct {
	Modes   []string
	Timeout time.Duration
	Retries int
	Ports   []int
}

type Result struct {
	Matched bool
	Method  string
}

type Runner interface {
	Run(ctx context.Context, ip string) (Result, error)
}

type RunnerFunc func(ctx context.Context, ip string) (Result, error)

func (f RunnerFunc) Run(ctx context.Context, ip string) (Result, error) {
	return f(ctx, ip)
}
```

Create `/Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/runner.go`:

```go
package hostdiscovery

import (
	"context"
	"errors"
)

var modeFactories = map[string]func(Options) Runner{
	"tcp-connect": newTCPConnectRunner,
	"icmp-echo":   newICMPEchoRunner,
	"tcp-syn":     newTCPSYNRunner,
	"tcp-ack":     newTCPACKRunner,
	"arp":         newARPRunner,
}

func Run(ctx context.Context, ip string, opts Options) (Result, error) {
	usable := 0
	for _, mode := range opts.Modes {
		factory, ok := modeFactories[mode]
		if !ok {
			continue
		}
		result, err := factory(opts).Run(ctx, ip)
		if err != nil {
			if errors.Is(err, ErrModeUnavailable) {
				continue
			}
			return Result{}, err
		}
		usable++
		if result.Matched {
			return result, nil
		}
	}
	if usable == 0 {
		return Result{}, ErrNoUsableModes
	}
	return Result{}, nil
}
```

- [ ] **Step 4: Run the host discovery core tests**

Run:

```bash
go test ./internal/hostdiscovery -run 'TestRunStopsOnFirstMatchedMode|TestRunReturnsErrorWhenAllModesUnavailable' -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/errors.go /Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/modes.go /Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/runner.go /Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/runner_test.go
git commit -m "feat(assetprobe): add host discovery runner core"
```

### Task 3: Implement TCP Connect And ICMP Echo Discovery Modes

**Files:**

- Create: `/Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/tcp_connect.go`
- Create: `/Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/icmp_echo.go`
- Create: `/Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/tcp_connect_test.go`

- [ ] **Step 1: Write the failing TCP connect mode tests**

Create `/Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/tcp_connect_test.go`:

```go
package hostdiscovery

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTCPConnectMatchesOnSuccessfulConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	runner := newTCPConnectRunner(Options{
		Timeout: time.Second,
		Ports:   []int{port},
	})

	result, err := runner.Run(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected matched result, got %+v", result)
	}
}

func TestTCPConnectReturnsNoMatchWhenAllPortsTimeout(t *testing.T) {
	runner := newTCPConnectRunner(Options{
		Timeout: 50 * time.Millisecond,
		Ports:   []int{65001},
	})

	result, err := runner.Run(context.Background(), "203.0.113.254")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Matched {
		t.Fatalf("expected no match, got %+v", result)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
go test ./internal/hostdiscovery -run 'TestTCPConnectMatchesOnSuccessfulConnect|TestTCPConnectReturnsNoMatchWhenAllPortsTimeout' -v
```

Expected: FAIL because `newTCPConnectRunner` does not exist yet.

- [ ] **Step 3: Implement TCP connect mode**

Create `/Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/tcp_connect.go`:

```go
package hostdiscovery

import (
	"context"
	"net"
	"strconv"
	"time"
)

func newTCPConnectRunner(opts Options) Runner {
	return RunnerFunc(func(ctx context.Context, ip string) (Result, error) {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = time.Second
		}
		for _, port := range opts.Ports {
			address := net.JoinHostPort(ip, strconv.Itoa(port))
			dialer := net.Dialer{Timeout: timeout}
			conn, err := dialer.DialContext(ctx, "tcp", address)
			if err == nil {
				conn.Close()
				return Result{Matched: true, Method: "tcp-connect"}, nil
			}
		}
		return Result{}, nil
	})
}
```

Create `/Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/icmp_echo.go`:

```go
package hostdiscovery

import (
	"context"

	"github.com/yrighc/gomap/internal/achieve"
)

func newICMPEchoRunner(_ Options) Runner {
	return RunnerFunc(func(ctx context.Context, ip string) (Result, error) {
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		default:
		}
		if achieve.PingHost(ip) {
			return Result{Matched: true, Method: "icmp-echo"}, nil
		}
		return Result{}, nil
	})
}
```

- [ ] **Step 4: Run the TCP connect tests**

Run:

```bash
go test ./internal/hostdiscovery -run 'TestTCPConnectMatchesOnSuccessfulConnect|TestTCPConnectReturnsNoMatchWhenAllPortsTimeout' -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/tcp_connect.go /Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/icmp_echo.go /Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/tcp_connect_test.go
git commit -m "feat(assetprobe): add tcp connect and icmp discovery modes"
```

### Task 4: Add Command-Based SYN ACK And ARP Discovery Modes

**Files:**

- Create: `/Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/command_modes.go`
- Create: `/Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/command_modes_test.go`

- [ ] **Step 1: Write failing tests for unavailable command modes**

Create `/Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/command_modes_test.go`:

```go
package hostdiscovery

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

func TestTCPSYNModeReturnsUnavailableWhenNpingMissing(t *testing.T) {
	origLookPath := execLookPath
	t.Cleanup(func() { execLookPath = origLookPath })
	execLookPath = func(string) (string, error) { return "", exec.ErrNotFound }

	_, err := newTCPSYNRunner(Options{
		Timeout: time.Second,
		Ports:   []int{80},
	}).Run(context.Background(), "127.0.0.1")
	if !errors.Is(err, ErrModeUnavailable) {
		t.Fatalf("expected ErrModeUnavailable, got %v", err)
	}
}

func TestARPModeReturnsUnavailableWhenArpingMissing(t *testing.T) {
	origLookPath := execLookPath
	t.Cleanup(func() { execLookPath = origLookPath })
	execLookPath = func(string) (string, error) { return "", exec.ErrNotFound }

	_, err := newARPRunner(Options{Timeout: time.Second}).Run(context.Background(), "127.0.0.1")
	if !errors.Is(err, ErrModeUnavailable) {
		t.Fatalf("expected ErrModeUnavailable, got %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
go test ./internal/hostdiscovery -run 'TestTCPSYNModeReturnsUnavailableWhenNpingMissing|TestARPModeReturnsUnavailableWhenArpingMissing' -v
```

Expected: FAIL because the command runners and hooks do not exist yet.

- [ ] **Step 3: Implement command-based compatibility runners**

Create `/Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/command_modes.go`:

```go
package hostdiscovery

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
)

var execLookPath = exec.LookPath
var execCommandContext = exec.CommandContext

func newTCPSYNRunner(opts Options) Runner {
	return newNpingRunner("tcp-syn", []string{"--tcp", "-flags", "syn"}, opts)
}

func newTCPACKRunner(opts Options) Runner {
	return newNpingRunner("tcp-ack", []string{"--tcp", "-flags", "ack"}, opts)
}

func newNpingRunner(method string, baseArgs []string, opts Options) Runner {
	return RunnerFunc(func(ctx context.Context, ip string) (Result, error) {
		if _, err := execLookPath("nping"); err != nil {
			return Result{}, ErrModeUnavailable
		}
		for _, port := range opts.Ports {
			args := append([]string{}, baseArgs...)
			args = append(args, "-c", "1", "-p", strconv.Itoa(port), ip)
			out, err := execCommandContext(ctx, "nping", args...).CombinedOutput()
			if err == nil && strings.Contains(string(out), "RCVD") {
				return Result{Matched: true, Method: method}, nil
			}
		}
		return Result{}, nil
	})
}

func newARPRunner(_ Options) Runner {
	return RunnerFunc(func(ctx context.Context, ip string) (Result, error) {
		if _, err := execLookPath("arping"); err != nil {
			return Result{}, ErrModeUnavailable
		}
		out, err := execCommandContext(ctx, "arping", "-c", "1", ip).CombinedOutput()
		if err != nil {
			return Result{}, nil
		}
		if strings.Contains(string(out), "reply from") || strings.Contains(string(out), "bytes from") {
			return Result{Matched: true, Method: "arp"}, nil
		}
		return Result{}, nil
	})
}
```

- [ ] **Step 4: Run the command-mode tests**

Run:

```bash
go test ./internal/hostdiscovery -run 'TestTCPSYNModeReturnsUnavailableWhenNpingMissing|TestARPModeReturnsUnavailableWhenArpingMissing' -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/command_modes.go /Users/yrighc/work/hzyz/project/GoMap/internal/hostdiscovery/command_modes_test.go
git commit -m "feat(assetprobe): add command-based discovery mode compatibility"
```

### Task 5: Integrate Host Discovery Into Scanner

**Files:**

- Modify: `/Users/yrighc/work/hzyz/project/GoMap/pkg/assetprobe/scanner.go`
- Modify: `/Users/yrighc/work/hzyz/project/GoMap/pkg/assetprobe/scanner_test.go`

- [ ] **Step 1: Write failing scanner tests for host discovery short-circuit**

Add to `/Users/yrighc/work/hzyz/project/GoMap/pkg/assetprobe/scanner_test.go`:

```go
func TestScanSkipsPortScanWhenHostDiscoveryReturnsNoSignal(t *testing.T) {
	scanner, err := NewScanner(Options{
		Timeout: 100 * time.Millisecond,
		HostDiscovery: HostDiscoveryOptions{
			Modes: []HostDiscoveryMode{HostDiscoveryTCPConnect},
			Ports: []int{65001},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := scanner.Scan(context.Background(), ScanRequest{
		Target:   "203.0.113.254",
		PortSpec: "80,443",
		Protocol: ProtocolTCP,
		HostDiscovery: HostDiscoveryOptions{
			Modes:   []HostDiscoveryMode{HostDiscoveryTCPConnect},
			Timeout: 20 * time.Millisecond,
			Ports:   []int{65001},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Ports) != 0 {
		t.Fatalf("expected no ports after host discovery skip, got %+v", result.Ports)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
go test ./pkg/assetprobe -run 'TestScanSkipsPortScanWhenHostDiscoveryReturnsNoSignal' -v
```

Expected: FAIL because scanner does not know about host discovery yet.

- [ ] **Step 3: Wire host discovery into `Scan` and `ScanTargets`**

Add an adapter near the top of `/Users/yrighc/work/hzyz/project/GoMap/pkg/assetprobe/scanner.go`:

```go
var runHostDiscovery = func(ctx context.Context, ip string, opts HostDiscoveryOptions) (bool, error) {
	modeNames := make([]string, 0, len(opts.Modes))
	for _, mode := range opts.Modes {
		modeNames = append(modeNames, string(mode))
	}
	result, err := hostdiscovery.Run(ctx, ip, hostdiscovery.Options{
		Modes:   modeNames,
		Timeout: opts.Timeout,
		Retries: opts.Retries,
		Ports:   opts.Ports,
	})
	if err != nil {
		return false, err
	}
	return result.Matched, nil
}
```

Inside `Scan(...)`, after `resolvedIP` and merged request options:

```go
	hostDiscovery := mergeHostDiscoveryOptions(s.opts.HostDiscovery, req.HostDiscovery)
	if req.Protocol == ProtocolTCP && !hostDiscovery.Disabled {
		matched, err := runHostDiscovery(ctx, resolvedIP, hostDiscovery)
		if err != nil {
			return nil, err
		}
		if !matched {
			return &ScanResult{
				Target:     targetHost,
				ResolvedIP: resolvedIP,
				Protocol:   req.Protocol,
				Meta:       ScanMeta{},
				Ports:      nil,
			}, nil
		}
	}
```

Use the same rule in `ScanTargets(...)` before expanding target jobs:

```go
	hostDiscovery := mergeHostDiscoveryOptions(s.opts.HostDiscovery, opts.HostDiscovery)
	// for each target:
	if opts.Protocol == ProtocolTCP && !hostDiscovery.Disabled {
		matched, err := runHostDiscovery(ctx, resolvedIP, hostDiscovery)
		if err != nil {
			results[i].Error = err.Error()
			continue
		}
		if !matched {
			results[i].Result = &ScanResult{
				Target:     target,
				ResolvedIP: resolvedIP,
				Protocol:   opts.Protocol,
				Meta:       ScanMeta{},
				Ports:      nil,
			}
			continue
		}
	}
```

Also add:

```go
func mergeHostDiscoveryOptions(base HostDiscoveryOptions, override HostDiscoveryOptions) HostDiscoveryOptions {
	out := base
	if override.Disabled {
		out.Disabled = true
	}
	if len(override.Modes) > 0 {
		out.Modes = append([]HostDiscoveryMode(nil), override.Modes...)
	}
	if override.Timeout > 0 {
		out.Timeout = override.Timeout
	}
	if override.Retries > 0 {
		out.Retries = override.Retries
	}
	if len(override.Ports) > 0 {
		out.Ports = append([]int(nil), override.Ports...)
	}
	return out
}
```

- [ ] **Step 4: Run the scanner host discovery test**

Run:

```bash
go test ./pkg/assetprobe -run 'TestScanSkipsPortScanWhenHostDiscoveryReturnsNoSignal' -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/yrighc/work/hzyz/project/GoMap/pkg/assetprobe/scanner.go /Users/yrighc/work/hzyz/project/GoMap/pkg/assetprobe/scanner_test.go
git commit -m "feat(assetprobe): short-circuit scans with host discovery"
```

### Task 6: Split TCP Scanning Into Discovery And Fingerprint Stages

**Files:**

- Modify: `/Users/yrighc/work/hzyz/project/GoMap/pkg/assetprobe/scanner.go`
- Modify: `/Users/yrighc/work/hzyz/project/GoMap/pkg/assetprobe/scanner_test.go`

- [ ] **Step 1: Write the failing pipeline test**

Add to `/Users/yrighc/work/hzyz/project/GoMap/pkg/assetprobe/scanner_test.go`:

```go
func TestDiscoverTCPPortReturnsTrueForListeningPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	if !discoverTCPPort("127.0.0.1", port, time.Second) {
		t.Fatal("expected discoverTCPPort to detect listening socket")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
go test ./pkg/assetprobe -run 'TestDiscoverTCPPortReturnsTrueForListeningPort' -v
```

Expected: FAIL because `discoverTCPPort` does not exist yet.

- [ ] **Step 3: Extract the discovery and fingerprint helpers**

In `/Users/yrighc/work/hzyz/project/GoMap/pkg/assetprobe/scanner.go`, add:

```go
func discoverTCPPort(resolvedIP string, port int, timeout time.Duration) bool {
	address := net.JoinHostPort(resolvedIP, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (s *Scanner) fingerprintTCPPort(targetHost string, resolvedIP string, port int, timeout time.Duration) PortResult {
	result := PortResult{Port: port, Open: true}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(resolvedIP, strconv.Itoa(port)), timeout)
	if err != nil {
		result.Service = "open"
		return result
	}
	defer conn.Close()

	banner, subject, dns, serviceName, version, _ := detectTCPServiceWithBudget(
		resolvedIP,
		targetHost,
		port,
		conn,
		s.opts.DisableWeakPassword,
		timeout,
	)
	result.Service = strings.TrimSuffix(serviceName, "?")
	if result.Service == "" {
		result.Service = "unknown"
	}
	result.Version = achieve.SanitizeUTF8(version)
	result.Banner = achieve.SanitizeUTF8(banner)
	result.Subject = achieve.SanitizeUTF8(subject)
	if dns != "" {
		result.DNSNames = splitAndCleanDNS(dns)
	}
	return result
}
```

Refactor `Scan(...)` TCP branch into:

```go
	openPorts := make([]int, 0, len(ports))
	for _, p := range ports {
		if discoverTCPPort(resolvedIP, p, timeout) {
			openPorts = append(openPorts, p)
		}
	}

	final := make([]PortResult, 0, len(openPorts))
	for idx, port := range openPorts {
		if maxFingerprintPorts > 0 && idx >= maxFingerprintPorts {
			final = append(final, PortResult{Port: port, Open: true, Service: "open"})
			continue
		}
		final = append(final, s.fingerprintTCPPort(targetHost, resolvedIP, port, timeout))
	}
```

Preserve meta calculation from the original implementation using `len(openPorts)` and the number fingerprinted.

- [ ] **Step 4: Run the pipeline test and targeted scanner regression tests**

Run:

```bash
go test ./pkg/assetprobe -run 'TestDiscoverTCPPortReturnsTrueForListeningPort|TestScanTargetsKeepsOrderAndPerTargetErrors|TestScanTargetsReturnsResultsInInputOrder' -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/yrighc/work/hzyz/project/GoMap/pkg/assetprobe/scanner.go /Users/yrighc/work/hzyz/project/GoMap/pkg/assetprobe/scanner_test.go
git commit -m "refactor(assetprobe): split tcp discovery from fingerprinting"
```

### Task 7: Update CLI Help And README Documentation

**Files:**

- Modify: `/Users/yrighc/work/hzyz/project/GoMap/cmd/main.go`
- Modify: `/Users/yrighc/work/hzyz/project/GoMap/README.md`
- Modify: `/Users/yrighc/work/hzyz/project/GoMap/pkg/assetprobe/README.md`

- [ ] **Step 1: Write the documentation updates**

Add to `/Users/yrighc/work/hzyz/project/GoMap/cmd/main.go` help text:

```go
	fmt.Println("  gomap port -target example.com -ports 1-1024")
	fmt.Println("  gomap port -target example.com -ports 1-65535 -Pn")
```

Update `/Users/yrighc/work/hzyz/project/GoMap/README.md` in the port scan section:

```md
- 默认会先执行主机存活验证（HostDiscovery），验证命中后再进入正式 TCP 端口扫描
- `-Pn` 用于跳过主机存活验证，直接执行端口扫描，语义与 Nmap `-Pn` 对齐
- `--host-discovery-mode` 支持 `icmp-echo,tcp-connect,tcp-syn,tcp-ack,arp`
- 当主机存活验证未命中时，该目标会被直接跳过，不再继续端口扫描
```

Update `/Users/yrighc/work/hzyz/project/GoMap/pkg/assetprobe/README.md`:

```md
scanner, err := assetprobe.NewScanner(assetprobe.Options{
    Timeout: 2 * time.Second,
    HostDiscovery: assetprobe.HostDiscoveryOptions{
        Modes:   []assetprobe.HostDiscoveryMode{assetprobe.HostDiscoveryICMPEcho, assetprobe.HostDiscoveryTCPConnect},
        Timeout: time.Second,
        Ports:   []int{80, 443, 22, 445, 3389},
    },
})
```

- [ ] **Step 2: Run the full focused regression suite**

Run:

```bash
go test ./cmd ./pkg/assetprobe ./internal/hostdiscovery -v
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add /Users/yrighc/work/hzyz/project/GoMap/cmd/main.go /Users/yrighc/work/hzyz/project/GoMap/README.md /Users/yrighc/work/hzyz/project/GoMap/pkg/assetprobe/README.md
git commit -m "docs(assetprobe): document host discovery and -Pn behavior"
```

## Self-Review

### Spec coverage

- Default-on host discovery: covered by Task 1 and Task 5
- `-Pn` compatibility: covered by Task 1 and Task 7
- Independent `HostDiscovery` module: covered by Task 2, Task 3, Task 4
- Multi-mode support: covered by Task 3 and Task 4
- No `ScanResult` shape changes: preserved throughout Task 5 and validated by Task 7 regression tests
- Two-stage TCP pipeline: covered by Task 6
- `ScanTargets` order/error semantics: covered by Task 5 and Task 6 regression tests

### Placeholder scan

- No `TODO`, `TBD`, or “implement later” placeholders remain.

### Type consistency

- `assetprobe.HostDiscoveryOptions` is the single config carrier used across CLI wiring and scanner integration.
- `internal/hostdiscovery.Options` is the internal execution shape used only by the host discovery package.
- `-Pn` is consistently modeled as `HostDiscovery.Disabled = true`.
