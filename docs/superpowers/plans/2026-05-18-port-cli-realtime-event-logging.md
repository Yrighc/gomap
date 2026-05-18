# Port CLI Realtime Event Logging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move verbose CLI hit logs from post-scan aggregation to realtime scan events emitted during execution, while preserving stdout JSON behavior.

**Architecture:** Introduce a tiny optional event callback in `pkg/assetprobe` and fire it from the TCP/UDP detection pipeline when concrete milestones happen. The CLI layer subscribes to these events and prints localized stderr lines immediately, so scan timing comes from the engine rather than from post-processing.

**Tech Stack:** Go, `pkg/assetprobe`, CLI tests in `cmd/main_test.go`, scanner tests in `pkg/assetprobe/scanner_test.go`

---

### Task 1: Lock realtime event emission with a failing scanner test

**Files:**
- Modify: `pkg/assetprobe/scanner_test.go`
- Test: `pkg/assetprobe/scanner_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestScanEmitsOpenPortEventBeforeReturning(t *testing.T) {
	ln, addr := startTestTCPServer(t)
	defer ln.Close()

	events := make(chan ScanEvent, 1)
	scanner, err := NewScanner(Options{
		Timeout: 2 * time.Second,
		OnEvent: func(evt ScanEvent) {
			events <- evt
		},
	})
	if err != nil {
		t.Fatalf("new scanner: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = scanner.Scan(context.Background(), ScanRequest{
			Target:   hostFromAddr(addr),
			Ports:    []int{portFromAddr(addr)},
			Protocol: ProtocolTCP,
		})
	}()

	select {
	case evt := <-events:
		if evt.Kind != ScanEventOpenPort {
			t.Fatalf("expected open port event, got %#v", evt)
		}
	case <-time.After(time.Second):
		t.Fatal("expected open port event before scan completion")
	}

	<-done
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/assetprobe -run TestScanEmitsOpenPortEventBeforeReturning -count=1`
Expected: FAIL because `assetprobe` does not yet emit realtime scan events.

### Task 2: Implement minimal event callback plumbing

**Files:**
- Modify: `pkg/assetprobe/types.go`
- Modify: `pkg/assetprobe/scanner.go`
- Test: `pkg/assetprobe/scanner_test.go`

- [ ] **Step 1: Add event types and callback option**
- [ ] **Step 2: Emit `open_port` during TCP discovery and UDP recognition**
- [ ] **Step 3: Emit `service_match` during fingerprint completion**
- [ ] **Step 4: Run focused scanner test**

Run: `go test ./pkg/assetprobe -run TestScanEmitsOpenPortEventBeforeReturning -count=1`
Expected: PASS

### Task 3: Reconnect CLI verbose output to realtime events

**Files:**
- Modify: `cmd/main.go`
- Modify: `cmd/main_test.go`

- [ ] **Step 1: Update CLI wiring so `-v` registers the event callback**
- [ ] **Step 2: Keep Chinese stderr wording in the callback printer**
- [ ] **Step 3: Run focused CLI tests**

Run: `go test ./cmd -run 'TestRunPortVerboseLogsOpenPortsAndMatchedServicesToStderr|TestRunWeakVerboseLogsMatchedFindingsToStderr' -count=1`
Expected: PASS
