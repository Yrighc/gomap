package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yrighc/gomap/pkg/assetprobe"
)

// Keep the CLI entry self-contained: users also run cmd/main.go directly.
func TestMainFileSupportsHostCLI(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"root help", []string{"-h"}, "host   主机存活探测"},
		{"host help", []string{"host", "-h"}, "用法: gomap host"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			args := append([]string{"run", "./cmd/main.go"}, tt.args...)
			cmd := exec.CommandContext(ctx, "go", args...)
			cmd.Dir = ".."
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("go %s failed: %v\n%s", strings.Join(args, " "), err, out)
			}
			if !strings.Contains(string(out), tt.want) {
				t.Fatalf("expected %q in single-file CLI output, got %s", tt.want, out)
			}
		})
	}
}

type stubHostDiscoverer struct {
	batch      *assetprobe.BatchHostDiscoveryResult
	err        error
	calls      int
	gotTargets []string
	gotOpts    assetprobe.DiscoverHostsOptions
	gotContext context.Context
}

func (s *stubHostDiscoverer) DiscoverHosts(ctx context.Context, targets []string, opts assetprobe.DiscoverHostsOptions) (*assetprobe.BatchHostDiscoveryResult, error) {
	s.calls++
	s.gotContext = ctx
	s.gotTargets = append([]string(nil), targets...)
	s.gotOpts = opts
	return s.batch, s.err
}

func stubHostDiscovererFactory(t *testing.T, discoverer hostDiscoverer) {
	t.Helper()
	oldFactory := newHostDiscoverer
	newHostDiscoverer = func() hostDiscoverer { return discoverer }
	t.Cleanup(func() { newHostDiscoverer = oldFactory })
}

// Reuse the existing CLI output/exit capture rather than duplicating pipe handling.
func captureHostRun(t *testing.T, fn func()) (string, string, int) {
	t.Helper()
	oldExit := exitHost
	defer func() { exitHost = oldExit }()
	return capturePortRun(t, func() {
		exitHost = exitPort
		fn()
	})
}

func hostTestResults() []assetprobe.TargetHostDiscoveryResult {
	return []assetprobe.TargetHostDiscoveryResult{
		{Target: "192.0.2.1", ResolvedIP: "192.0.2.1", Matched: true, Method: "arp"},
		{Target: "192.0.2.2", ResolvedIP: "192.0.2.2"},
		{Target: "2001:db8::1", ResolvedIP: "2001:db8::1", Matched: true, Method: "tcp-connect"},
	}
}

func TestRunHostDefaultsToAliveIPsOnly(t *testing.T) {
	discoverer := &stubHostDiscoverer{batch: &assetprobe.BatchHostDiscoveryResult{Results: hostTestResults()}}
	stubHostDiscovererFactory(t, discoverer)

	stdout, stderr, code := captureHostRun(t, func() {
		runHost([]string{"-ips", "192.0.2.0/30,2001:db8::1"})
	})
	if code != 0 || stderr != "" || stdout != "192.0.2.1\n2001:db8::1\n" {
		t.Fatalf("unexpected output: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if discoverer.calls != 1 || !reflect.DeepEqual(discoverer.gotTargets, []string{"192.0.2.0/30", "2001:db8::1"}) {
		t.Fatalf("expected one SDK discovery call with IP/CIDR targets, got %+v", discoverer)
	}
	wantOpts := assetprobe.DiscoverHostsOptions{
		Concurrency:   32,
		MaxTargets:    65536,
		HostDiscovery: assetprobe.HostDiscoveryOptions{Timeout: time.Second},
	}
	if !reflect.DeepEqual(discoverer.gotOpts, wantOpts) {
		t.Fatalf("expected automatic-policy SDK options %+v, got %+v", wantOpts, discoverer.gotOpts)
	}
	if discoverer.gotContext == nil || discoverer.gotContext.Err() != context.Canceled {
		t.Fatal("expected the command to release its signal context after discovery")
	}
}

func TestRunHostForwardsOptionsAndDeduplicatesInput(t *testing.T) {
	for _, concurrencyFlags := range [][]string{
		{"-c", "7"},
		{"-concurrency", "7"},
		{"-c", "3", "-concurrency", "7"},
		{"-concurrency", "3", "-c", "7"},
	} {
		t.Run(strings.Join(concurrencyFlags, " "), func(t *testing.T) {
			discoverer := &stubHostDiscoverer{batch: &assetprobe.BatchHostDiscoveryResult{}}
			stubHostDiscovererFactory(t, discoverer)
			args := append([]string{"-target", " 192.0.2.1 ", "-ips", "192.0.2.1, 192.0.2.0/30,,", "-timeout", "3", "-max-targets", "100"}, concurrencyFlags...)
			_, stderr, code := captureHostRun(t, func() { runHost(args) })
			if code != 0 || stderr != "" {
				t.Fatalf("unexpected output: code=%d stderr=%q", code, stderr)
			}
			if !reflect.DeepEqual(discoverer.gotTargets, []string{"192.0.2.1", "192.0.2.0/30"}) {
				t.Fatalf("unexpected targets: %v", discoverer.gotTargets)
			}
			if discoverer.gotOpts.Concurrency != 7 || discoverer.gotOpts.MaxTargets != 100 || discoverer.gotOpts.HostDiscovery.Timeout != 3*time.Second {
				t.Fatalf("unexpected options: %+v", discoverer.gotOpts)
			}
		})
	}
}

func TestRunHostJLIncludesEveryOutcome(t *testing.T) {
	results := append(hostTestResults(), assetprobe.TargetHostDiscoveryResult{Target: "example.com", Error: "target is not an IP address"})
	discoverer := &stubHostDiscoverer{batch: &assetprobe.BatchHostDiscoveryResult{Results: results}}
	stubHostDiscovererFactory(t, discoverer)

	stdout, stderr, code := captureHostRun(t, func() {
		runHost([]string{"-ips", "192.0.2.0/30,2001:db8::1,example.com", "-jl", "-v"})
	})
	if code != 1 {
		t.Fatalf("expected nonzero exit for a failed target, got %d", code)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != len(results) {
		t.Fatalf("expected one JSON line per result, got %q", stdout)
	}
	for i, line := range lines {
		var got assetprobe.TargetHostDiscoveryResult
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("invalid JSON line %d: %v", i, err)
		}
		if !reflect.DeepEqual(got, results[i]) {
			t.Fatalf("result %d: want %+v, got %+v", i, results[i], got)
		}
	}
	if !strings.Contains(stderr, "target=example.com: target is not an IP address") || !strings.Contains(stderr, "总数=4，已确认存活=2，未确认存活=1，失败=1") {
		t.Fatalf("expected separate error and summary diagnostics, got %q", stderr)
	}
}

func TestRunHostNoSignalIsSuccessfulAndNotOffline(t *testing.T) {
	discoverer := &stubHostDiscoverer{batch: &assetprobe.BatchHostDiscoveryResult{Results: []assetprobe.TargetHostDiscoveryResult{
		{Target: "192.0.2.1", ResolvedIP: "192.0.2.1"},
	}}}
	stubHostDiscovererFactory(t, discoverer)

	stdout, stderr, code := captureHostRun(t, func() { runHost([]string{"-target", "192.0.2.1", "-v"}) })
	if code != 0 || stdout != "" || !strings.Contains(stderr, "总数=1，已确认存活=0，未确认存活=1，失败=0") || strings.Contains(stderr, "离线") {
		t.Fatalf("unexpected no-signal outcome: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestRunHostPreservesPartialResultsOnFailure(t *testing.T) {
	for _, batchErr := range []error{nil, context.Canceled, errors.New("batch failed")} {
		name := "target error only"
		if batchErr != nil {
			name = batchErr.Error()
		}
		t.Run(name, func(t *testing.T) {
			discoverer := &stubHostDiscoverer{
				batch: &assetprobe.BatchHostDiscoveryResult{Results: []assetprobe.TargetHostDiscoveryResult{
					{Target: "192.0.2.1", ResolvedIP: "192.0.2.1", Matched: true, Method: "tcp-connect"},
					{Target: "192.0.2.2", ResolvedIP: "192.0.2.2", Error: "probe failed"},
				}},
				err: batchErr,
			}
			stubHostDiscovererFactory(t, discoverer)
			stdout, stderr, code := captureHostRun(t, func() { runHost([]string{"-ips", "192.0.2.1,192.0.2.2"}) })
			if code != 1 || stdout != "192.0.2.1\n" || !strings.Contains(stderr, "target=192.0.2.2: probe failed") {
				t.Fatalf("expected partial alive results with failure: code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			if batchErr != nil && !strings.Contains(stderr, batchErr.Error()) {
				t.Fatalf("expected batch error %q, got %q", batchErr, stderr)
			}
		})
	}
}

func TestRunHostRejectsInvalidArgumentsBeforeDiscovery(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		message string
		code    int
	}{
		{"missing target", nil, "target 参数缺失", 1},
		{"blank target", []string{"-ips", " , "}, "target 参数缺失", 1},
		{"timeout", []string{"-target", "192.0.2.1", "-timeout", "0"}, "timeout 参数无效", 1},
		{"negative timeout", []string{"-target", "192.0.2.1", "-timeout", "-1"}, "timeout 参数无效", 1},
		{"concurrency", []string{"-target", "192.0.2.1", "-c", "0"}, "concurrency 参数无效", 1},
		{"negative concurrency", []string{"-target", "192.0.2.1", "-concurrency", "-1"}, "concurrency 参数无效", 1},
		{"max targets", []string{"-target", "192.0.2.1", "-max-targets", "0"}, "max-targets 参数无效", 1},
		{"positional", []string{"-target", "192.0.2.1", "192.0.2.2"}, "不接受位置参数", 1},
		{"unknown flag", []string{"-target", "192.0.2.1", "-ports", "80"}, "flag provided but not defined", 2},
		{"unknown flag with JSONL", []string{"-target", "192.0.2.1", "-jl", "-ports", "80"}, "flag provided but not defined", 2},
		{"missing flag value", []string{"-target"}, "flag needs an argument", 2},
		{"non-integer timeout", []string{"-target", "192.0.2.1", "-timeout", "invalid"}, "invalid value", 2},
	}
	if strconv.IntSize == 64 {
		tests = append(tests, struct {
			name    string
			args    []string
			message string
			code    int
		}{"timeout overflow", []string{"-target", "192.0.2.1", "-timeout", "10000000000"}, "timeout 参数无效", 1})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			discoverer := &stubHostDiscoverer{}
			stubHostDiscovererFactory(t, discoverer)
			stdout, stderr, code := captureHostRun(t, func() { runHost(tt.args) })
			if code != tt.code || stdout != "" || !strings.Contains(stderr, tt.message) || discoverer.calls != 0 {
				t.Fatalf("expected pre-discovery failure %q/code %d with empty stdout, got code=%d stdout=%q stderr=%q calls=%d", tt.message, tt.code, code, stdout, stderr, discoverer.calls)
			}
			if tt.code == 2 && !strings.Contains(stderr, "用法: gomap host") {
				t.Fatalf("expected parse-error usage on stderr, got %q", stderr)
			}
		})
	}
}

func TestRunHostHandlesMissingBatch(t *testing.T) {
	for _, batchErr := range []error{nil, errors.New("discovery unavailable")} {
		name := "nil batch without error"
		if batchErr != nil {
			name = batchErr.Error()
		}
		t.Run(name, func(t *testing.T) {
			discoverer := &stubHostDiscoverer{err: batchErr}
			stubHostDiscovererFactory(t, discoverer)
			stdout, stderr, code := captureHostRun(t, func() { runHost([]string{"-target", "192.0.2.1"}) })
			if code != 1 || stdout != "" || stderr == "" {
				t.Fatalf("expected a reported error: code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestRunHostHelpDoesNotDiscover(t *testing.T) {
	discoverer := &stubHostDiscoverer{}
	stubHostDiscovererFactory(t, discoverer)
	stdout, stderr, code := captureHostRun(t, func() { runHost([]string{"-h"}) })
	if code != 0 || stderr != "" || !strings.Contains(stdout, "用法: gomap host") || discoverer.calls != 0 {
		t.Fatalf("unexpected help result: code=%d stdout=%q stderr=%q calls=%d", code, stdout, stderr, discoverer.calls)
	}
}

func TestRunHostSDKRejectsDomainWithoutProbing(t *testing.T) {
	stdout, stderr, code := captureHostRun(t, func() { runHost([]string{"-target", "example.com"}) })
	if code != 1 || stdout != "" || !strings.Contains(stderr, "target=example.com: target is not an IP address") {
		t.Fatalf("unexpected domain outcome: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestRunHostSDKRejectsExpandedTargetsBeforeProbing(t *testing.T) {
	stdout, stderr, code := captureHostRun(t, func() { runHost([]string{"-ips", "192.0.2.0/30", "-max-targets", "1"}) })
	if code != 1 || stdout != "" || !strings.Contains(stderr, "exceeds limit 1") {
		t.Fatalf("unexpected target-limit outcome: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestMainDispatchesHost(t *testing.T) {
	discoverer := &stubHostDiscoverer{batch: &assetprobe.BatchHostDiscoveryResult{Results: hostTestResults()[:1]}}
	stubHostDiscovererFactory(t, discoverer)
	oldArgs := os.Args
	os.Args = []string{"gomap", "host", "-target", "192.0.2.1"}
	defer func() { os.Args = oldArgs }()

	stdout, stderr, code := captureHostRun(t, main)
	if code != 0 || stdout != "192.0.2.1\n" || stderr != "" || discoverer.calls != 1 {
		t.Fatalf("unexpected dispatch: code=%d stdout=%q stderr=%q calls=%d", code, stdout, stderr, discoverer.calls)
	}
}

func TestRootUsageIncludesHost(t *testing.T) {
	stdout, stderr, code := captureHostRun(t, printRootUsage)
	if code != 0 || stderr != "" || !strings.Contains(stdout, "host   主机存活探测") || !strings.Contains(stdout, "gomap host -ips 192.168.1.0/24") {
		t.Fatalf("unexpected root usage: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
