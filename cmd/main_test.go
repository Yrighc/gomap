package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yrighc/gomap/pkg/assetprobe"
	"github.com/yrighc/gomap/pkg/secprobe"
)

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
	payload := portWithWeakOutput{
		Asset: &assetprobe.ScanResult{Target: "demo"},
		Security: &secprobe.RunResult{
			Meta: secprobe.SecurityMeta{Candidates: 1, Attempted: 1, Succeeded: 1},
			Results: []secprobe.SecurityResult{{
				Target:      "demo",
				Service:     "ssh",
				FindingType: secprobe.FindingTypeCredentialValid,
				Success:     true,
				Username:    "root",
				Password:    "root",
			}},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if !bytes.Contains(data, []byte(`"asset"`)) || !bytes.Contains(data, []byte(`"security"`)) {
		t.Fatalf("unexpected payload: %s", string(data))
	}
}

func TestBuildPortWeakProbeOptions(t *testing.T) {
	opts := buildPortWeakProbeOptions("ssh, redis", 7, 3*time.Second, false, "  ./dicts  ")

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

func TestMarshalPortOutputWithoutWeakKeepsAssetShape(t *testing.T) {
	data, err := marshalPortOutput(&assetprobe.ScanResult{Target: "demo"}, nil, false)
	if err != nil {
		t.Fatalf("marshal asset output: %v", err)
	}
	if bytes.Contains(data, []byte(`"asset"`)) || bytes.Contains(data, []byte(`"security"`)) {
		t.Fatalf("expected raw asset output, got %s", string(data))
	}
	if !bytes.Contains(data, []byte(`"Target":"demo"`)) {
		t.Fatalf("expected asset target in output, got %s", string(data))
	}
}
