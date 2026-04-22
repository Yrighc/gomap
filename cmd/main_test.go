package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
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
			"-weak-dict-dir", "  ./dicts  ",
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
	if gotWeakOpts.DictDir != "./dicts" {
		t.Fatalf("expected trimmed dict dir, got %q", gotWeakOpts.DictDir)
	}
	if !gotWeakOpts.EnableUnauthorized {
		t.Fatal("expected unauthorized probing enabled")
	}
	if !gotWeakOpts.EnableEnrichment {
		t.Fatal("expected enrichment enabled")
	}
}

func TestBuildPortWeakProbeOptions(t *testing.T) {
	opts := buildPortWeakProbeOptions("ssh, redis", 7, 3*time.Second, false, "  ./dicts  ", false, false)

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
	if opts.DictDir != "./dicts" {
		t.Fatalf("expected trimmed dict dir, got %q", opts.DictDir)
	}
}

func TestBuildPortWeakProbeOptionsForwardsUnauthorizedAndEnrichment(t *testing.T) {
	opts := buildPortWeakProbeOptions("mongodb", 5, 4*time.Second, true, " ./dicts ", true, true)

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
	}()

	fn()

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

func stubWeakScannerFactory(scanner weakTargetScanner) func() {
	oldScannerFactory := newWeakTargetScanner

	newWeakTargetScanner = func(assetprobe.Options) (weakTargetScanner, error) {
		return scanner, nil
	}

	return func() {
		newWeakTargetScanner = oldScannerFactory
	}
}
