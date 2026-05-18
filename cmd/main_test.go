package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yrighc/gomap/pkg/assetprobe"
	"github.com/yrighc/gomap/pkg/secprobe"
)

type stubPortScanner struct {
	batch      *assetprobe.BatchScanResult
	err        error
	gotTargets []string
	gotOpts    assetprobe.ScanCommonOptions
}

type portExitCode int
type weakExitCode int
type webExitCode int
type dirExitCode int

func (s *stubPortScanner) ScanTargets(_ context.Context, targets []string, opts assetprobe.ScanCommonOptions) (*assetprobe.BatchScanResult, error) {
	s.gotTargets = append([]string(nil), targets...)
	s.gotOpts = opts
	return s.batch, s.err
}

func TestCollectCredentialsParsesInlinePairs(t *testing.T) {
	got, err := collectCredentials("admin : admin,root : root", "")
	if err != nil {
		t.Fatalf("collect credentials: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(got))
	}
}

func TestCollectCredentialsRejectsInvalidInlinePair(t *testing.T) {
	if _, err := collectCredentials("admin", ""); err == nil {
		t.Fatal("expected invalid inline credential to fail")
	}
}

func TestCollectCredentialsParsesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.txt")
	if err := os.WriteFile(path, []byte("admin : admin\nroot : root\n"), 0o600); err != nil {
		t.Fatalf("write creds file: %v", err)
	}

	got, err := collectCredentials("", path)
	if err != nil {
		t.Fatalf("collect credentials from file: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(got))
	}
}

func TestPortWithWeakWrapsAssetAndSecurityResults(t *testing.T) {
	scanner := &stubPortScanner{
		batch: &assetprobe.BatchScanResult{
			Results: []assetprobe.TargetScanResult{{
				Target: "demo",
				Result: &assetprobe.ScanResult{
					Target:   "demo",
					Protocol: assetprobe.ProtocolTCP,
					Ports:    []assetprobe.PortResult{{Port: 5432, Open: true}},
				},
			}},
		},
	}
	security := &secprobe.RunResult{
		Meta: secprobe.SecurityMeta{Candidates: 1, Attempted: 1, Succeeded: 1},
		Results: []secprobe.SecurityResult{{
			Target:      "demo",
			Service:     "postgresql",
			FindingType: secprobe.FindingTypeCredentialValid,
			Success:     true,
			Username:    "root",
			Password:    "root",
		}},
	}
	restoreScanner := stubPortScannerFactory(scanner)
	defer restoreScanner()
	oldWeakRunner := runPortWeakProbe
	var gotWeakOpts secprobe.CredentialProbeOptions
	runPortWeakProbe = func(_ context.Context, _ *assetprobe.ScanResult, opts secprobe.CredentialProbeOptions) *secprobe.RunResult {
		gotWeakOpts = opts
		return security
	}
	defer func() {
		runPortWeakProbe = oldWeakRunner
	}()

	stdout, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{
			"-target", "demo",
			"-ports", "5432",
			"-weak",
			"-weak-protocols", "postgresql",
			"-weak-concurrency", "7",
			"-weak-stop-on-success=false",
			"-weak-enable-unauth",
			"-weak-enable-enrichment",
		})
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %s", exitCode, stderr)
	}
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %s", stderr)
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout)
	}
	if _, ok := payload["asset"]; !ok {
		t.Fatalf("expected asset envelope, got %s", stdout)
	}
	if _, ok := payload["security"]; !ok {
		t.Fatalf("expected security envelope, got %s", stdout)
	}
	if len(scanner.gotTargets) != 1 || scanner.gotTargets[0] != "demo" {
		t.Fatalf("expected target demo, got %v", scanner.gotTargets)
	}
	if scanner.gotOpts.Protocol != assetprobe.ProtocolTCP {
		t.Fatalf("expected tcp scan protocol, got %s", scanner.gotOpts.Protocol)
	}
	if len(gotWeakOpts.Protocols) != 1 || gotWeakOpts.Protocols[0] != "postgresql" {
		t.Fatalf("expected forwarded protocols, got %v", gotWeakOpts.Protocols)
	}
	if gotWeakOpts.Concurrency != 7 {
		t.Fatalf("expected weak concurrency 7, got %d", gotWeakOpts.Concurrency)
	}
	if gotWeakOpts.Timeout != 2*time.Second {
		t.Fatalf("expected timeout 2s, got %s", gotWeakOpts.Timeout)
	}
	if gotWeakOpts.StopOnSuccess {
		t.Fatal("expected stop-on-success false")
	}
	if !gotWeakOpts.EnableUnauthorized {
		t.Fatal("expected unauthorized probing enabled")
	}
	if !gotWeakOpts.EnableEnrichment {
		t.Fatal("expected enrichment enabled")
	}
}

func TestPortWithWeakOutputOmitsInternalStateFields(t *testing.T) {
	security := &secprobe.RunResult{
		Meta: secprobe.SecurityMeta{Candidates: 1, Attempted: 1, Succeeded: 1},
		Results: []secprobe.SecurityResult{{
			Target:      "demo",
			Service:     "redis",
			ProbeKind:   secprobe.ProbeKindUnauthorized,
			FindingType: secprobe.FindingTypeUnauthorizedAccess,
			Success:     true,
			Evidence:    "INFO returned redis_version without authentication",
		}},
	}

	raw, err := security.ToJSON(false)
	if err != nil {
		t.Fatalf("marshal security result: %v", err)
	}

	for _, field := range []string{`"Stage"`, `"FailureReason"`, `"Capabilities"`} {
		if bytes.Contains(raw, []byte(field)) {
			t.Fatalf("expected %s to stay internal, got %s", field, string(raw))
		}
	}
}

func TestBuildPortWeakProbeOptions(t *testing.T) {
	opts := buildPortWeakProbeOptions("ssh, redis", 7, 3*time.Second, false, false, false)

	if got, want := opts.Protocols, []string{"ssh", "redis"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected protocols %v, got %v", want, got)
	}
	if opts.Concurrency != 7 {
		t.Fatalf("expected concurrency 7, got %d", opts.Concurrency)
	}
	if opts.Timeout != 3*time.Second {
		t.Fatalf("expected timeout 3s, got %s", opts.Timeout)
	}
	if opts.StopOnSuccess {
		t.Fatal("expected stop-on-success false")
	}
}

func TestBuildPortWeakProbeOptionsForwardsUnauthorizedAndEnrichment(t *testing.T) {
	opts := buildPortWeakProbeOptions("mongodb", 5, 4*time.Second, true, true, true)

	if !opts.EnableUnauthorized {
		t.Fatal("expected unauthorized probing enabled")
	}
	if !opts.EnableEnrichment {
		t.Fatal("expected enrichment enabled")
	}
}

func TestMarshalPortOutputWithoutWeakKeepsAssetShape(t *testing.T) {
	scanner := &stubPortScanner{
		batch: &assetprobe.BatchScanResult{
			Results: []assetprobe.TargetScanResult{{
				Target: "demo",
				Result: &assetprobe.ScanResult{
					Target:   "demo",
					Protocol: assetprobe.ProtocolTCP,
					Ports:    []assetprobe.PortResult{{Port: 80, Open: true}},
				},
			}},
		},
	}
	restoreScanner := stubPortScannerFactory(scanner)
	defer restoreScanner()
	oldWeakRunner := runPortWeakProbe
	runPortWeakProbe = func(context.Context, *assetprobe.ScanResult, secprobe.CredentialProbeOptions) *secprobe.RunResult {
		t.Fatal("runPortWeakProbe should not be called")
		return nil
	}
	defer func() {
		runPortWeakProbe = oldWeakRunner
	}()

	stdout, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{"-target", "demo", "-ports", "80"})
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %s", exitCode, stderr)
	}
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %s", stderr)
	}

	if bytes.Contains([]byte(stdout), []byte(`"asset"`)) || bytes.Contains([]byte(stdout), []byte(`"security"`)) {
		t.Fatalf("expected raw asset output, got %s", stdout)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"Target": "demo"`)) {
		t.Fatalf("expected asset target in output, got %s", stdout)
	}
}

func TestRunPortJLPrintsSingleLineJSON(t *testing.T) {
	scanner := &stubPortScanner{
		batch: &assetprobe.BatchScanResult{
			Results: []assetprobe.TargetScanResult{{
				Target: "demo",
				Result: &assetprobe.ScanResult{
					Target:   "demo",
					Protocol: assetprobe.ProtocolTCP,
					Ports:    []assetprobe.PortResult{{Port: 80, Open: true}},
				},
			}},
		},
	}
	restoreScanner := stubPortScannerFactory(scanner)
	defer restoreScanner()

	stdout, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{"-target", "demo", "-ports", "80", "-jl"})
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %s", exitCode, stderr)
	}
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %s", stderr)
	}
	if strings.Contains(stdout, "\n  ") {
		t.Fatalf("expected jsonl single-line output, got %q", stdout)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly one jsonl line, got %d in %q", len(lines), stdout)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &payload); err != nil {
		t.Fatalf("expected valid single-line json, got %v in %q", err, stdout)
	}
}

func TestRunPortDefaultsToHostDiscovery(t *testing.T) {
	scanner := &stubPortScanner{
		batch: &assetprobe.BatchScanResult{
			Results: []assetprobe.TargetScanResult{{
				Target: "demo",
				Result: &assetprobe.ScanResult{
					Target:   "demo",
					Protocol: assetprobe.ProtocolTCP,
				},
			}},
		},
	}
	restoreScanner := stubPortScannerFactory(scanner)
	defer restoreScanner()

	stdout, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{"-target", "demo", "-ports", "80"})
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %s and stdout %s", exitCode, stderr, stdout)
	}
	if scanner.gotOpts.HostDiscovery.Disabled {
		t.Fatal("expected host discovery enabled by default")
	}
	if len(scanner.gotOpts.HostDiscovery.Modes) != 0 {
		t.Fatalf("expected CLI to rely on scanner defaults for host discovery modes, got %v", scanner.gotOpts.HostDiscovery.Modes)
	}
}

func TestRunPortPnDisablesHostDiscovery(t *testing.T) {
	scanner := &stubPortScanner{
		batch: &assetprobe.BatchScanResult{
			Results: []assetprobe.TargetScanResult{{
				Target: "demo",
				Result: &assetprobe.ScanResult{
					Target:   "demo",
					Protocol: assetprobe.ProtocolTCP,
				},
			}},
		},
	}
	restoreScanner := stubPortScannerFactory(scanner)
	defer restoreScanner()

	_, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{"-target", "demo", "-ports", "80", "-Pn"})
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %s", exitCode, stderr)
	}
	if !scanner.gotOpts.HostDiscovery.Disabled {
		t.Fatal("expected -Pn to disable host discovery")
	}
}

func TestRunPortRejectsLegacyHostDiscoveryFlags(t *testing.T) {
	_, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{"-target", "demo", "-ports", "80", "-host-discovery-timeout", "2"})
	})
	if exitCode != 2 {
		t.Fatalf("expected exit code 2 for unknown flag, got %d with stderr %s", exitCode, stderr)
	}
	if !strings.Contains(stderr, "flag provided but not defined") {
		t.Fatalf("expected unknown flag error, got %s", stderr)
	}
	if !strings.Contains(stderr, "host-discovery-timeout") {
		t.Fatalf("expected stderr to mention removed host-discovery flag, got %s", stderr)
	}
}

func TestRunPortCSVWritesRowWhenNoOpenPorts(t *testing.T) {
	scanner := &stubPortScanner{
		batch: &assetprobe.BatchScanResult{
			Results: []assetprobe.TargetScanResult{{
				Target: "192.108.0.1",
				Result: &assetprobe.ScanResult{
					Target:     "192.108.0.1",
					ResolvedIP: "192.108.0.1",
					Protocol:   assetprobe.ProtocolTCP,
					Meta: assetprobe.ScanMeta{
						OpenPorts: 0,
					},
					Ports: nil,
				},
			}},
		},
	}
	restoreScanner := stubPortScannerFactory(scanner)
	defer restoreScanner()

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldWD)
	}()

	stdout, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{"-target", "192.108.0.1", "-ports", "443", "-csv", "-csv-mode", "overwrite"})
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %s", exitCode, stderr)
	}
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %s", stderr)
	}
	if !strings.Contains(stdout, `"Target": "192.108.0.1"`) {
		t.Fatalf("expected stdout to include target result, got %s", stdout)
	}

	data, err := os.ReadFile(filepath.Join(tmp, "logs", "port.csv"))
	if err != nil {
		t.Fatalf("read port.csv: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected header plus one data row, got %d lines:\n%s", len(lines), string(data))
	}
	if !strings.Contains(lines[1], "192.108.0.1") {
		t.Fatalf("expected csv row to contain target, got %s", lines[1])
	}
	if !strings.Contains(lines[1], ",0,0,0,false,") {
		t.Fatalf("expected csv row to record zero-open-port meta, got %s", lines[1])
	}
}

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
		t.Fatalf("expected stdout to include json result, got %s", stdout)
	}
	if !strings.Contains(stderr, "发现开放端口 target=demo resolved_ip=127.0.0.1 protocol=tcp port=80 service=http version=nginx") {
		t.Fatalf("expected stderr to include localized service hit log, got %s", stderr)
	}
	if !strings.Contains(stderr, "发现开放端口 target=demo resolved_ip=127.0.0.1 protocol=tcp port=443") {
		t.Fatalf("expected stderr to include localized open port hit log, got %s", stderr)
	}
}

func TestRunPortVerboseEmitsRealtimeOpenPortLog(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	oldStdout := os.Stdout
	oldStderr := os.Stderr
	oldExit := exitPort

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	os.Stdout = stdoutW
	os.Stderr = stderrW
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		exitPort = oldExit
	}()

	done := make(chan int, 1)
	go func() {
		exitCode := 0
		defer func() {
			if r := recover(); r != nil {
				code, ok := r.(portExitCode)
				if !ok {
					panic(r)
				}
				exitCode = int(code)
			}
			done <- exitCode
		}()
		exitPort = func(code int) {
			panic(portExitCode(code))
		}
		runPort([]string{
			"-target", "127.0.0.1",
			"-ports", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port),
			"-timeout", "1",
			"-Pn",
			"-v",
		})
	}()

	stderrReady := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := stderrR.Read(buf)
		stderrReady <- string(buf[:n])
	}()

	select {
	case firstChunk := <-stderrReady:
		if !strings.Contains(firstChunk, "发现开放端口 target=127.0.0.1") {
			t.Fatalf("expected realtime open port log, got %s", firstChunk)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expected realtime stderr log before command completion")
	}

	exitCode := <-done
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if err := stdoutW.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	if err := stderrW.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	stdout, err := io.ReadAll(stdoutR)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if !strings.Contains(string(stdout), `"Target": "127.0.0.1"`) {
		t.Fatalf("expected stdout json result, got %s", string(stdout))
	}
	<-accepted
}

func TestRunPortVerbosePrintsHostDiscoverySummaryForMultipleTargets(t *testing.T) {
	oldFactory := newPortTargetScanner
	defer func() { newPortTargetScanner = oldFactory }()

	newPortTargetScanner = func(opts assetprobe.Options) (portTargetScanner, error) {
		if opts.OnEvent != nil {
			opts.OnEvent(assetprobe.ScanEvent{
				Kind:       assetprobe.ScanEventHostDiscoveryMatched,
				Target:     "127.0.0.1",
				ResolvedIP: "127.0.0.1",
				Method:     "tcp-connect",
			})
			opts.OnEvent(assetprobe.ScanEvent{
				Kind:       assetprobe.ScanEventOpenPort,
				Target:     "127.0.0.1",
				ResolvedIP: "127.0.0.1",
				Protocol:   assetprobe.ProtocolTCP,
				Port:       80,
			})
			opts.OnEvent(assetprobe.ScanEvent{
				Kind: assetprobe.ScanEventHostDiscoverySummary,
				Summary: &assetprobe.HostDiscoverySummary{
					Total: 2,
					Alive: []assetprobe.HostDiscoveryTarget{{
						Target:     "127.0.0.1",
						ResolvedIP: "127.0.0.1",
						Method:     "tcp-connect",
					}},
					Skipped: []assetprobe.HostDiscoveryTarget{{
						Target:     "127.0.0.2",
						ResolvedIP: "127.0.0.2",
					}},
				},
			})
		}
		return &stubPortScanner{
			batch: &assetprobe.BatchScanResult{
				Results: []assetprobe.TargetScanResult{
					{
						Target: "127.0.0.1",
						Result: &assetprobe.ScanResult{
							Target:     "127.0.0.1",
							ResolvedIP: "127.0.0.1",
							Protocol:   assetprobe.ProtocolTCP,
						},
					},
					{
						Target: "127.0.0.2",
						Result: &assetprobe.ScanResult{
							Target:     "127.0.0.2",
							ResolvedIP: "127.0.0.2",
							Protocol:   assetprobe.ProtocolTCP,
						},
					},
				},
			},
		}, nil
	}

	stdout, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{
			"-ips", "127.0.0.1,127.0.0.2",
			"-ports", "1",
			"-timeout", "1",
			"-v",
		})
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %s", exitCode, stderr)
	}
	if !strings.Contains(stderr, "主机存活校验完成：总数=2，存活=1，未存活=1") {
		t.Fatalf("expected host discovery summary, got %s", stderr)
	}
	if strings.Contains(stderr, "发现主机存活") || strings.Contains(stderr, "未发现主机存活信号") {
		t.Fatalf("expected multi-target verbose mode to suppress host discovery process logs, got %s", stderr)
	}
	if !strings.Contains(stderr, "发现开放端口 target=127.0.0.1 resolved_ip=127.0.0.1 protocol=tcp port=80") {
		t.Fatalf("expected open port logs to remain visible in multi-target mode, got %s", stderr)
	}
	if strings.Contains(stderr, "存活目标:") || strings.Contains(stderr, "未存活目标:") {
		t.Fatalf("expected summary-only output without target detail lines, got %s", stderr)
	}
	if !strings.Contains(stdout, `"Target": "127.0.0.1"`) {
		t.Fatalf("expected stdout json result, got %s", stdout)
	}
}

func TestRunPortVerboseTreatsCIDRInputAsSummaryOnlyMode(t *testing.T) {
	oldFactory := newPortTargetScanner
	defer func() { newPortTargetScanner = oldFactory }()

	newPortTargetScanner = func(opts assetprobe.Options) (portTargetScanner, error) {
		if opts.OnEvent != nil {
			opts.OnEvent(assetprobe.ScanEvent{
				Kind:       assetprobe.ScanEventHostDiscoveryNotMatched,
				Target:     "192.168.0.250",
				ResolvedIP: "192.168.0.250",
			})
			opts.OnEvent(assetprobe.ScanEvent{
				Kind: assetprobe.ScanEventHostDiscoverySummary,
				Summary: &assetprobe.HostDiscoverySummary{
					Total: 256,
					Alive: []assetprobe.HostDiscoveryTarget{{
						Target:     "192.168.0.182",
						ResolvedIP: "192.168.0.182",
						Method:     "tcp-connect",
					}},
					Skipped: []assetprobe.HostDiscoveryTarget{{
						Target:     "192.168.0.250",
						ResolvedIP: "192.168.0.250",
					}},
				},
			})
		}
		return &stubPortScanner{
			batch: &assetprobe.BatchScanResult{
				Results: []assetprobe.TargetScanResult{{
					Target: "192.168.0.0/24",
					Result: &assetprobe.ScanResult{
						Target:     "192.168.0.0/24",
						ResolvedIP: "192.168.0.182",
						Protocol:   assetprobe.ProtocolTCP,
					},
				}},
			},
		}, nil
	}

	_, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{
			"-target", "192.168.0.0/24",
			"-ports", "1",
			"-timeout", "1",
			"-v",
		})
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %s", exitCode, stderr)
	}
	if strings.Contains(stderr, "未发现主机存活信号 target=192.168.0.250") {
		t.Fatalf("expected CIDR input to suppress per-target process logs, got %s", stderr)
	}
	if !strings.Contains(stderr, "主机存活校验完成：总数=256，存活=1，未存活=1") {
		t.Fatalf("expected CIDR summary log, got %s", stderr)
	}
	if strings.Contains(stderr, "存活目标:") || strings.Contains(stderr, "未存活目标:") {
		t.Fatalf("expected CIDR summary-only output without target detail lines, got %s", stderr)
	}
}

func TestResolvePortProtocolRejectsWeakOnUDP(t *testing.T) {
	_, err := resolvePortProtocol("udp", true)
	if err == nil {
		t.Fatal("expected weak+udp to fail")
	}
}

func TestRunPortRejectsWeakOnUDP(t *testing.T) {
	stdout, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{"-target", "demo", "-ports", "53", "-proto", "udp", "-weak"})
	})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d with stderr %s", exitCode, stderr)
	}
	if stdout != "" {
		t.Fatalf("expected empty stdout, got %s", stdout)
	}
	if !bytes.Contains([]byte(stderr), []byte("weak 仅支持 tcp 扫描")) {
		t.Fatalf("expected udp rejection message, got %s", stderr)
	}
}

func TestRunPortRejectsInvalidPortRangeWithoutPanic(t *testing.T) {
	stdout, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{"-target", "demo", "-ports", "1--65535"})
	})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d with stderr %s", exitCode, stderr)
	}
	if stdout != "" {
		t.Fatalf("expected empty stdout, got %s", stdout)
	}
	if !strings.Contains(stderr, "ports 参数无效") {
		t.Fatalf("expected friendly validation message, got %s", stderr)
	}
	if !strings.Contains(stderr, "端口范围格式错误") {
		t.Fatalf("expected localized validation reason, got %s", stderr)
	}
	if !strings.Contains(stderr, "1--65535") {
		t.Fatalf("expected stderr to include invalid input, got %s", stderr)
	}
	if !strings.Contains(stderr, "示例: 80,443,1-1024") {
		t.Fatalf("expected stderr to include valid example, got %s", stderr)
	}
}

func TestRunPortRejectsOutOfRangePortInChinese(t *testing.T) {
	stdout, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{"-target", "demo", "-ports", "70000"})
	})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d with stderr %s", exitCode, stderr)
	}
	if stdout != "" {
		t.Fatalf("expected empty stdout, got %s", stdout)
	}
	if !strings.Contains(stderr, "端口超出范围") {
		t.Fatalf("expected localized out-of-range message, got %s", stderr)
	}
	if !strings.Contains(stderr, "70000") {
		t.Fatalf("expected stderr to include invalid input, got %s", stderr)
	}
}

func TestRunPortRejectsMissingTargetWithUnifiedMessage(t *testing.T) {
	stdout, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{"-ports", "80"})
	})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d with stderr %s", exitCode, stderr)
	}
	if stdout != "" {
		t.Fatalf("expected empty stdout, got %s", stdout)
	}
	if !strings.Contains(stderr, "target 参数缺失") {
		t.Fatalf("expected unified missing-target message, got %s", stderr)
	}
	if !strings.Contains(stderr, "gomap port -target example.com") {
		t.Fatalf("expected target example, got %s", stderr)
	}
}

func TestRunPortRejectsInvalidTimeoutWithUnifiedMessage(t *testing.T) {
	stdout, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{"-target", "demo", "-timeout", "0"})
	})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d with stderr %s", exitCode, stderr)
	}
	if stdout != "" {
		t.Fatalf("expected empty stdout, got %s", stdout)
	}
	if !strings.Contains(stderr, "timeout 参数无效") {
		t.Fatalf("expected unified timeout message, got %s", stderr)
	}
	if !strings.Contains(stderr, "必须大于 0") {
		t.Fatalf("expected timeout reason, got %s", stderr)
	}
	if !strings.Contains(stderr, "示例: -timeout 2") {
		t.Fatalf("expected timeout example, got %s", stderr)
	}
}

func TestRunPortRejectsInvalidCSVModeWithUnifiedMessage(t *testing.T) {
	stdout, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{"-target", "demo", "-csv", "-csv-mode", "bad"})
	})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d with stderr %s", exitCode, stderr)
	}
	if stdout != "" {
		t.Fatalf("expected empty stdout, got %s", stdout)
	}
	if !strings.Contains(stderr, "csv-mode 参数无效") {
		t.Fatalf("expected unified csv-mode message, got %s", stderr)
	}
	if !strings.Contains(stderr, "append|overwrite") {
		t.Fatalf("expected allowed values, got %s", stderr)
	}
}

func TestRunPortRejectsInvalidProtoWithUnifiedMessage(t *testing.T) {
	stdout, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{"-target", "demo", "-proto", "bad"})
	})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d with stderr %s", exitCode, stderr)
	}
	if stdout != "" {
		t.Fatalf("expected empty stdout, got %s", stdout)
	}
	if !strings.Contains(stderr, "proto 参数无效") {
		t.Fatalf("expected unified proto message, got %s", stderr)
	}
	if !strings.Contains(stderr, "tcp|udp") {
		t.Fatalf("expected allowed proto values, got %s", stderr)
	}
}

func TestRunPortRejectsInvalidHoneypotRatioWithUnifiedMessage(t *testing.T) {
	stdout, stderr, exitCode := capturePortRun(t, func() {
		runPort([]string{"-target", "demo", "-honeypot-open-ratio", "2"})
	})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d with stderr %s", exitCode, stderr)
	}
	if stdout != "" {
		t.Fatalf("expected empty stdout, got %s", stdout)
	}
	if !strings.Contains(stderr, "honeypot-open-ratio 参数无效") {
		t.Fatalf("expected unified ratio message, got %s", stderr)
	}
	if !strings.Contains(stderr, "(0,1]") {
		t.Fatalf("expected valid range hint, got %s", stderr)
	}
}

func TestRunWeakDefaultsToCredentialOnly(t *testing.T) {
	scanner := &stubWeakScanner{
		batch: &assetprobe.BatchScanResult{
			Results: []assetprobe.TargetScanResult{{
				Target: "demo",
				Result: &assetprobe.ScanResult{
					Target:   "demo",
					Protocol: assetprobe.ProtocolTCP,
					Ports:    []assetprobe.PortResult{{Port: 6379, Open: true, Service: "redis"}},
				},
			}},
		},
	}
	restoreScanner := stubWeakScannerFactory(scanner)
	defer restoreScanner()

	oldWeakRunner := runWeakProbe
	var gotOpts secprobe.CredentialProbeOptions
	runWeakProbe = func(_ context.Context, _ []secprobe.SecurityCandidate, opts secprobe.CredentialProbeOptions) secprobe.RunResult {
		gotOpts = opts
		return secprobe.RunResult{
			Meta: secprobe.SecurityMeta{},
		}
	}
	defer func() {
		runWeakProbe = oldWeakRunner
	}()

	stdout, stderr := captureWeakRun(t, func() {
		runWeak([]string{"-target", "demo", "-ports", "6379"})
	})
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %s", stderr)
	}
	if stdout == "" {
		t.Fatal("expected stdout output")
	}
	if gotOpts.EnableUnauthorized {
		t.Fatal("expected unauthorized probing disabled by default")
	}
	if gotOpts.EnableEnrichment {
		t.Fatal("expected enrichment disabled by default")
	}
}

func TestRunWeakDefaultsTimeoutToOneSecond(t *testing.T) {
	scanner := &stubWeakScanner{
		batch: &assetprobe.BatchScanResult{
			Results: []assetprobe.TargetScanResult{{
				Target: "demo",
				Result: &assetprobe.ScanResult{
					Target:   "demo",
					Protocol: assetprobe.ProtocolTCP,
					Ports:    []assetprobe.PortResult{{Port: 22, Open: true, Service: "ssh"}},
				},
			}},
		},
	}
	restoreScanner := stubWeakScannerFactory(scanner)
	defer restoreScanner()

	oldWeakRunner := runWeakProbe
	var gotOpts secprobe.CredentialProbeOptions
	runWeakProbe = func(_ context.Context, _ []secprobe.SecurityCandidate, opts secprobe.CredentialProbeOptions) secprobe.RunResult {
		gotOpts = opts
		return secprobe.RunResult{Meta: secprobe.SecurityMeta{}}
	}
	defer func() {
		runWeakProbe = oldWeakRunner
	}()

	stdout, stderr := captureWeakRun(t, func() {
		runWeak([]string{"-target", "demo", "-ports", "22"})
	})
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %s", stderr)
	}
	if stdout == "" {
		t.Fatal("expected stdout output")
	}
	if gotOpts.Timeout != time.Second {
		t.Fatalf("expected weak default timeout 1s, got %s", gotOpts.Timeout)
	}
}

func TestRunWeakBuildsCandidateFromExplicitProtocolOnCustomPort(t *testing.T) {
	scanner := &stubWeakScanner{
		batch: &assetprobe.BatchScanResult{
			Results: []assetprobe.TargetScanResult{{
				Target: "demo",
				Result: &assetprobe.ScanResult{
					Target:     "demo",
					ResolvedIP: "192.0.2.10",
					Protocol:   assetprobe.ProtocolTCP,
					Ports:      []assetprobe.PortResult{{Port: 10033, Open: true, Service: ""}},
				},
			}},
		},
	}
	restoreScanner := stubWeakScannerFactory(scanner)
	defer restoreScanner()

	oldWeakRunner := runWeakProbe
	var gotCandidates []secprobe.SecurityCandidate
	runWeakProbe = func(_ context.Context, candidates []secprobe.SecurityCandidate, _ secprobe.CredentialProbeOptions) secprobe.RunResult {
		gotCandidates = append([]secprobe.SecurityCandidate(nil), candidates...)
		return secprobe.RunResult{Meta: secprobe.SecurityMeta{Candidates: len(candidates)}}
	}
	defer func() {
		runWeakProbe = oldWeakRunner
	}()

	stdout, stderr := captureWeakRun(t, func() {
		runWeak([]string{"-target", "demo", "-ports", "10033", "-protocols", "ssh", "-up", "root:secret"})
	})
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %s", stderr)
	}
	if stdout == "" {
		t.Fatal("expected stdout output")
	}
	if len(gotCandidates) != 1 {
		t.Fatalf("expected one ssh candidate from explicit protocol on custom port, got %#v", gotCandidates)
	}
	if gotCandidates[0].Service != "ssh" || gotCandidates[0].Port != 10033 {
		t.Fatalf("expected explicit ssh candidate on port 10033, got %#v", gotCandidates[0])
	}
}

func TestRunWeakForwardsUnauthorizedAndEnrichment(t *testing.T) {
	scanner := &stubWeakScanner{
		batch: &assetprobe.BatchScanResult{
			Results: []assetprobe.TargetScanResult{{
				Target: "demo",
				Result: &assetprobe.ScanResult{
					Target:   "demo",
					Protocol: assetprobe.ProtocolTCP,
					Ports:    []assetprobe.PortResult{{Port: 27017, Open: true, Service: "mongodb"}},
				},
			}},
		},
	}
	restoreScanner := stubWeakScannerFactory(scanner)
	defer restoreScanner()

	oldWeakRunner := runWeakProbe
	var gotOpts secprobe.CredentialProbeOptions
	runWeakProbe = func(_ context.Context, _ []secprobe.SecurityCandidate, opts secprobe.CredentialProbeOptions) secprobe.RunResult {
		gotOpts = opts
		return secprobe.RunResult{Meta: secprobe.SecurityMeta{}}
	}
	defer func() {
		runWeakProbe = oldWeakRunner
	}()

	stdout, stderr := captureWeakRun(t, func() {
		runWeak([]string{"-target", "demo", "-ports", "27017", "-enable-unauth", "-enable-enrichment"})
	})
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %s", stderr)
	}
	if stdout == "" {
		t.Fatal("expected stdout output")
	}
	if !gotOpts.EnableUnauthorized {
		t.Fatal("expected unauthorized probing enabled")
	}
	if !gotOpts.EnableEnrichment {
		t.Fatal("expected enrichment enabled")
	}
}

func TestRunWeakJLPrintsSingleLineJSON(t *testing.T) {
	scanner := &stubWeakScanner{
		batch: &assetprobe.BatchScanResult{
			Results: []assetprobe.TargetScanResult{{
				Target: "demo",
				Result: &assetprobe.ScanResult{
					Target:   "demo",
					Protocol: assetprobe.ProtocolTCP,
					Ports:    []assetprobe.PortResult{{Port: 6379, Open: true, Service: "redis"}},
				},
			}},
		},
	}
	restoreScanner := stubWeakScannerFactory(scanner)
	defer restoreScanner()

	oldWeakRunner := runWeakProbe
	runWeakProbe = func(_ context.Context, _ []secprobe.SecurityCandidate, _ secprobe.CredentialProbeOptions) secprobe.RunResult {
		return secprobe.RunResult{Meta: secprobe.SecurityMeta{Candidates: 1}}
	}
	defer func() {
		runWeakProbe = oldWeakRunner
	}()

	stdout, stderr := captureWeakRun(t, func() {
		runWeak([]string{"-target", "demo", "-ports", "6379", "-jl"})
	})
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %s", stderr)
	}
	if strings.Contains(stdout, "\n  ") {
		t.Fatalf("expected jsonl single-line output, got %q", stdout)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly one jsonl line, got %d in %q", len(lines), stdout)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &payload); err != nil {
		t.Fatalf("expected valid single-line json, got %v in %q", err, stdout)
	}
}

func TestRunWeakVerboseLogsMatchedFindingsToStderr(t *testing.T) {
	scanner := &stubWeakScanner{
		batch: &assetprobe.BatchScanResult{
			Results: []assetprobe.TargetScanResult{{
				Target: "demo",
				Result: &assetprobe.ScanResult{
					Target:     "demo",
					ResolvedIP: "127.0.0.1",
					Protocol:   assetprobe.ProtocolTCP,
					Ports:      []assetprobe.PortResult{{Port: 6379, Open: true, Service: "redis"}},
				},
			}},
		},
	}
	restoreScanner := stubWeakScannerFactory(scanner)
	defer restoreScanner()

	oldWeakRunner := runWeakProbe
	runWeakProbe = func(_ context.Context, _ []secprobe.SecurityCandidate, _ secprobe.CredentialProbeOptions) secprobe.RunResult {
		return secprobe.RunResult{
			Meta: secprobe.SecurityMeta{Candidates: 1, Attempted: 1, Succeeded: 1},
			Results: []secprobe.SecurityResult{{
				Target:      "demo",
				ResolvedIP:  "127.0.0.1",
				Port:        6379,
				Service:     "redis",
				ProbeKind:   secprobe.ProbeKindCredential,
				FindingType: secprobe.FindingTypeCredentialValid,
				Success:     true,
				Username:    "default",
				Password:    "default",
			}},
		}
	}
	defer func() {
		runWeakProbe = oldWeakRunner
	}()

	stdout, stderr := captureWeakRun(t, func() {
		runWeak([]string{"-target", "demo", "-ports", "6379", "-v"})
	})
	if !strings.Contains(stdout, `"Succeeded": 1`) {
		t.Fatalf("expected stdout to include json result, got %s", stdout)
	}
	if !strings.Contains(stderr, "发现弱口令命中 target=demo resolved_ip=127.0.0.1 service=redis port=6379 用户名=default 密码=default") {
		t.Fatalf("expected stderr to include localized weak hit log, got %s", stderr)
	}
}

func TestRunWeakRejectsInvalidPortRangeWithoutPanic(t *testing.T) {
	stdout, stderr := captureWeakRun(t, func() {
		runWeak([]string{"-target", "demo", "-ports", "1--65535"})
	})
	if stdout != "" {
		t.Fatalf("expected empty stdout, got %s", stdout)
	}
	if !strings.Contains(stderr, "ports 参数无效") {
		t.Fatalf("expected friendly validation message, got %s", stderr)
	}
	if !strings.Contains(stderr, "端口范围格式错误") {
		t.Fatalf("expected localized validation reason, got %s", stderr)
	}
	if !strings.Contains(stderr, "1--65535") {
		t.Fatalf("expected stderr to include invalid input, got %s", stderr)
	}
	if !strings.Contains(stderr, "示例: 80,443,1-1024") {
		t.Fatalf("expected stderr to include valid example, got %s", stderr)
	}
}

func TestRunWeakRejectsInvalidTimeoutWithUnifiedMessage(t *testing.T) {
	stdout, stderr := captureWeakRun(t, func() {
		runWeak([]string{"-target", "demo", "-timeout", "0"})
	})
	if stdout != "" {
		t.Fatalf("expected empty stdout, got %s", stdout)
	}
	if !strings.Contains(stderr, "timeout 参数无效") {
		t.Fatalf("expected unified timeout message, got %s", stderr)
	}
	if !strings.Contains(stderr, "必须大于 0") {
		t.Fatalf("expected timeout reason, got %s", stderr)
	}
}

func TestRunWebRejectsMissingURLWithUnifiedMessage(t *testing.T) {
	stdout, stderr, exitCode := captureWebRun(t, func() {
		runWeb([]string{})
	})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d with stderr %s", exitCode, stderr)
	}
	if stdout != "" {
		t.Fatalf("expected empty stdout, got %s", stdout)
	}
	if !strings.Contains(stderr, "url 参数缺失") {
		t.Fatalf("expected unified missing-url message, got %s", stderr)
	}
	if !strings.Contains(stderr, "gomap web -url https://example.com") {
		t.Fatalf("expected URL example, got %s", stderr)
	}
}

func TestRunDirRejectsMissingURLWithUnifiedMessage(t *testing.T) {
	stdout, stderr, exitCode := captureDirRun(t, func() {
		runDir([]string{})
	})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d with stderr %s", exitCode, stderr)
	}
	if stdout != "" {
		t.Fatalf("expected empty stdout, got %s", stdout)
	}
	if !strings.Contains(stderr, "url 参数缺失") {
		t.Fatalf("expected unified missing-url message, got %s", stderr)
	}
	if !strings.Contains(stderr, "gomap dir -url https://example.com") {
		t.Fatalf("expected URL example, got %s", stderr)
	}
}

func TestRunDirRejectsInvalidDictLevelWithUnifiedMessage(t *testing.T) {
	stdout, stderr, exitCode := captureDirRun(t, func() {
		runDir([]string{"-url", "https://example.com", "-dict", "bad"})
	})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d with stderr %s", exitCode, stderr)
	}
	if stdout != "" {
		t.Fatalf("expected empty stdout, got %s", stdout)
	}
	if !strings.Contains(stderr, "dict 参数无效") {
		t.Fatalf("expected unified dict message, got %s", stderr)
	}
	if !strings.Contains(stderr, "simple|normal|diff") {
		t.Fatalf("expected allowed dict values, got %s", stderr)
	}
}

func TestMarshalCLIJSONJLProducesSingleLine(t *testing.T) {
	raw, err := marshalCLIJSON(map[string]any{
		"target": "demo",
		"ports":  []int{80, 443},
	}, false)
	if err != nil {
		t.Fatalf("marshal cli json: %v", err)
	}
	if strings.Contains(string(raw), "\n") {
		t.Fatalf("expected single-line json output, got %q", string(raw))
	}
}

func TestRunWebJLPrintsSingleLineJSON(t *testing.T) {
	page := &assetprobe.HomepageResult{
		URL:   "https://example.com",
		Title: "Example",
		Response: assetprobe.HomepageResponse{
			Header: assetprobe.HomepageResponseHeader{
				StatusCode: 200,
			},
		},
	}
	raw, err := marshalCLIJSON(page, false)
	if err != nil {
		t.Fatalf("marshal homepage json: %v", err)
	}
	if strings.Contains(string(raw), "\n") {
		t.Fatalf("expected single-line homepage json, got %q", string(raw))
	}
}

func TestRunDirJLPrintsSingleLineJSON(t *testing.T) {
	res := &assetprobe.DirResult{
		Target:     "example.com",
		ResolvedIP: "93.184.216.34",
		Port:       443,
		Paths: []assetprobe.PathResult{{
			URL:        "https://example.com/admin",
			StatusCode: 200,
		}},
	}
	raw, err := marshalCLIJSON(res, false)
	if err != nil {
		t.Fatalf("marshal dir json: %v", err)
	}
	if strings.Contains(string(raw), "\n") {
		t.Fatalf("expected single-line dir json, got %q", string(raw))
	}
}

func capturePortRun(t *testing.T, fn func()) (string, string, int) {
	t.Helper()

	oldStdout := os.Stdout
	oldStderr := os.Stderr
	oldExit := exitPort

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	os.Stdout = stdoutW
	os.Stderr = stderrW
	exitCode := 0
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		exitPort = oldExit
	}()

	func() {
		defer func() {
			if r := recover(); r != nil {
				code, ok := r.(portExitCode)
				if !ok {
					panic(r)
				}
				exitCode = int(code)
			}
		}()
		exitPort = func(code int) {
			panic(portExitCode(code))
		}
		fn()
	}()

	if err := stdoutW.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	if err := stderrW.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	stdout, err := io.ReadAll(stdoutR)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	stderr, err := io.ReadAll(stderrR)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(stdout), string(stderr), exitCode
}

func stubPortScannerFactory(scanner portTargetScanner) func() {
	oldScannerFactory := newPortTargetScanner

	newPortTargetScanner = func(assetprobe.Options) (portTargetScanner, error) {
		return scanner, nil
	}

	return func() {
		newPortTargetScanner = oldScannerFactory
	}
}

type stubWeakScanner struct {
	batch      *assetprobe.BatchScanResult
	err        error
	gotTargets []string
	gotOpts    assetprobe.ScanCommonOptions
}

func (s *stubWeakScanner) ScanTargets(_ context.Context, targets []string, opts assetprobe.ScanCommonOptions) (*assetprobe.BatchScanResult, error) {
	s.gotTargets = append([]string(nil), targets...)
	s.gotOpts = opts
	return s.batch, s.err
}

func captureWeakRun(t *testing.T, fn func()) (string, string) {
	t.Helper()

	oldStdout := os.Stdout
	oldStderr := os.Stderr
	oldExit := exitWeak

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	os.Stdout = stdoutW
	os.Stderr = stderrW
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		exitWeak = oldExit
	}()

	func() {
		defer func() {
			if r := recover(); r != nil {
				_, ok := r.(weakExitCode)
				if !ok {
					panic(r)
				}
			}
		}()
		exitWeak = func(code int) {
			panic(weakExitCode(code))
		}
		fn()
	}()

	if err := stdoutW.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	if err := stderrW.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	stdout, err := io.ReadAll(stdoutR)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	stderr, err := io.ReadAll(stderrR)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(stdout), string(stderr)
}

func captureWebRun(t *testing.T, fn func()) (string, string, int) {
	t.Helper()

	oldStdout := os.Stdout
	oldStderr := os.Stderr
	oldExit := exitWeb

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	os.Stdout = stdoutW
	os.Stderr = stderrW
	exitCode := 0
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		exitWeb = oldExit
	}()

	func() {
		defer func() {
			if r := recover(); r != nil {
				code, ok := r.(webExitCode)
				if !ok {
					panic(r)
				}
				exitCode = int(code)
			}
		}()
		exitWeb = func(code int) {
			panic(webExitCode(code))
		}
		fn()
	}()

	if err := stdoutW.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	if err := stderrW.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	stdout, err := io.ReadAll(stdoutR)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	stderr, err := io.ReadAll(stderrR)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(stdout), string(stderr), exitCode
}

func captureDirRun(t *testing.T, fn func()) (string, string, int) {
	t.Helper()

	oldStdout := os.Stdout
	oldStderr := os.Stderr
	oldExit := exitDir

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	os.Stdout = stdoutW
	os.Stderr = stderrW
	exitCode := 0
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		exitDir = oldExit
	}()

	func() {
		defer func() {
			if r := recover(); r != nil {
				code, ok := r.(dirExitCode)
				if !ok {
					panic(r)
				}
				exitCode = int(code)
			}
		}()
		exitDir = func(code int) {
			panic(dirExitCode(code))
		}
		fn()
	}()

	if err := stdoutW.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	if err := stderrW.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	stdout, err := io.ReadAll(stdoutR)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	stderr, err := io.ReadAll(stderrR)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(stdout), string(stderr), exitCode
}

func stubWeakScannerFactory(scanner weakTargetScanner) func() {
	oldScannerFactory := newWeakTargetScanner

	newWeakTargetScanner = func(assetprobe.Options) (weakTargetScanner, error) {
		return scanner, nil
	}

	return func() {
		newWeakTargetScanner = oldScannerFactory
	}
}
