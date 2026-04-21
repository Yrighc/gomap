package secprobe

import (
	"strings"
	"testing"
)

func TestBuiltinCredentialsLoadByProtocol(t *testing.T) {
	tests := []string{"ssh", "ftp", "mysql", "postgresql", "redis", "telnet"}
	for _, protocol := range tests {
		creds, err := BuiltinCredentials(protocol)
		if err != nil {
			t.Fatalf("load %s builtin credentials: %v", protocol, err)
		}
		if len(creds) == 0 {
			t.Fatalf("expected builtin credentials for %s", protocol)
		}
	}
}

func TestSecurityResultToJSON(t *testing.T) {
	res := SecurityResult{
		Target:      "example.com",
		ResolvedIP:  "127.0.0.1",
		Port:        22,
		Service:     "ssh",
		FindingType: FindingTypeCredentialValid,
		Success:     true,
		Username:    "root",
		Password:    "root",
		Evidence:    "SSH authentication succeeded",
	}
	data, err := res.ToJSON(true)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	if len(data) == 0 || data[0] != '{' {
		t.Fatalf("expected json object, got %q", string(data))
	}
}

func TestParseCredentialLinesRejectsMalformedLine(t *testing.T) {
	_, err := parseCredentialLines("root : root\nbroken-line")
	if err == nil {
		t.Fatal("expected malformed credential line error")
	}
	if !strings.Contains(err.Error(), "invalid credential line") {
		t.Fatalf("expected invalid line error, got %v", err)
	}
}

func TestParseCredentialLinesRejectsEmptyResult(t *testing.T) {
	_, err := parseCredentialLines("# comment only\n\n")
	if err == nil {
		t.Fatal("expected empty credential result error")
	}
	if !strings.Contains(err.Error(), "no valid credentials found") {
		t.Fatalf("expected empty result error, got %v", err)
	}
}
