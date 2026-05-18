# Port CLI Verbose Hit Logging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add clear verbose stderr hit logs to `gomap port` when open ports or service fingerprint matches are found, while preserving the stdout JSON contract.

**Architecture:** Keep the change inside the CLI layer by formatting per-port hit lines from the already-produced `assetprobe.ScanResult`. This avoids coupling to scanner internals and guarantees that stdout JSON, CSV, and batch semantics stay unchanged.

**Tech Stack:** Go, standard library `fmt`/`strings`, existing CLI tests in `cmd/main_test.go`

---

### Task 1: Lock verbose hit logging behavior with a failing CLI test

**Files:**
- Modify: `cmd/main_test.go`
- Test: `cmd/main_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestRunPortVerboseLogsOpenPortsAndMatchedServicesToStderr(t *testing.T) {
	scanner := &stubPortScanner{
		batch: &assetprobe.BatchScanResult{
			Results: []assetprobe.TargetScanResult{{
				Target: "demo",
				Result: &assetprobe.ScanResult{
					Target:     "demo",
					ResolvedIP: "127.0.0.1",
					Protocol:   assetprobe.ProtocolTCP,
					Ports: []assetprobe.PortResult{
						{Port: 80, Open: true, Service: "http", Version: "nginx"},
						{Port: 443, Open: true},
					},
				},
			}},
		},
	}
	restoreScanner := stubPortScannerFactory(scanner)
	defer restoreScanner()

	stdout, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{"-target", "demo", "-ports", "80,443", "-v"})
	})

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, `"Target": "demo"`) {
		t.Fatalf("expected stdout json result, got %s", stdout)
	}
	if !strings.Contains(stderr, "port hit target=demo resolved_ip=127.0.0.1 protocol=tcp port=80 open=true service=http version=nginx") {
		t.Fatalf("expected service hit log, got %s", stderr)
	}
	if !strings.Contains(stderr, "port hit target=demo resolved_ip=127.0.0.1 protocol=tcp port=443 open=true") {
		t.Fatalf("expected open port hit log, got %s", stderr)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd -run TestRunPortVerboseLogsOpenPortsAndMatchedServicesToStderr -count=1`
Expected: FAIL because `runPort` does not currently print per-port verbose hit lines to stderr.

- [ ] **Step 3: Commit**

```bash
git add cmd/main_test.go docs/superpowers/specs/2026-05-18-port-cli-verbose-hit-logging-design.md docs/superpowers/plans/2026-05-18-port-cli-verbose-hit-logging.md
git commit -m "test: cover port cli verbose hit logging"
```

### Task 2: Implement minimal CLI stderr hit logging

**Files:**
- Modify: `cmd/main.go`
- Test: `cmd/main_test.go`

- [ ] **Step 1: Write minimal implementation**

```go
func printVerbosePortHits(stderr io.Writer, res *assetprobe.ScanResult) {
	if res == nil {
		return
	}
	for _, p := range res.Ports {
		if !p.Open {
			continue
		}
		line := fmt.Sprintf(
			"port hit target=%s resolved_ip=%s protocol=%s port=%d open=true",
			res.Target,
			res.ResolvedIP,
			res.Protocol,
			p.Port,
		)
		if p.Service != "" {
			line += fmt.Sprintf(" service=%s", p.Service)
		}
		if p.Version != "" {
			line += fmt.Sprintf(" version=%s", p.Version)
		}
		fmt.Fprintln(stderr, line)
	}
}
```

- [ ] **Step 2: Call it only for `-v`**

```go
if *verbose {
	printVerbosePortHits(os.Stderr, res)
}
```

- [ ] **Step 3: Run focused test to verify it passes**

Run: `go test ./cmd -run TestRunPortVerboseLogsOpenPortsAndMatchedServicesToStderr -count=1`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add cmd/main.go cmd/main_test.go
git commit -m "feat(cli): log verbose port hits on match"
```

### Task 3: Verify no regression in nearby CLI behavior

**Files:**
- Modify: none
- Test: `cmd/main_test.go`

- [ ] **Step 1: Run the focused nearby tests**

Run: `go test ./cmd -run 'TestRunPort(VerboseLogsOpenPortsAndMatchedServicesToStderr|CSVWritesRowWhenNoOpenPorts|RejectsWeakOnUDP|RejectsInvalidPortRangeWithoutPanic|DefaultsToHostDiscovery|PnDisablesHostDiscovery)' -count=1`
Expected: PASS

- [ ] **Step 2: Run the whole cmd package**

Run: `go test ./cmd -count=1`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add .
git commit -m "test: verify port cli verbose logging behavior"
```
