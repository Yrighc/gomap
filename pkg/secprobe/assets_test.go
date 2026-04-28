package secprobe

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestBuiltinCredentialsLoadByProtocol(t *testing.T) {
	tests := []string{"ssh", "ftp", "mysql", "postgresql", "redis", "telnet", "mssql", "rdp", "smb", "vnc"}
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

func TestBuiltinCredentialsLoadByProtocolAlias(t *testing.T) {
	creds, err := BuiltinCredentials("cifs")
	if err != nil {
		t.Fatalf("load cifs builtin credentials: %v", err)
	}
	if len(creds) == 0 {
		t.Fatal("expected builtin credentials for cifs alias")
	}
	if creds[0].Username != "administrator" || creds[0].Password != "administrator" {
		t.Fatalf("expected smb credentials via cifs alias, got %+v", creds[0])
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

func TestSecurityResultPublicShapeDoesNotExposeInternalState(t *testing.T) {
	typ := reflect.TypeOf(SecurityResult{})
	for _, field := range []string{"Stage", "SkipReason", "FailureReason", "Capabilities", "Risk"} {
		if _, ok := typ.FieldByName(field); ok {
			t.Fatalf("expected public SecurityResult to exclude internal field %q", field)
		}
	}
}

func TestSecurityResultJSONDoesNotContainInternalStateFields(t *testing.T) {
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

	data, err := res.ToJSON(false)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}

	for _, field := range []string{"Stage", "SkipReason", "FailureReason", "Capabilities", "Risk"} {
		if _, exists := got[field]; exists {
			t.Fatalf("expected public json to exclude %s: %s", field, string(data))
		}
	}
}

func TestRunResultToJSON(t *testing.T) {
	res := RunResult{
		Meta: SecurityMeta{
			Candidates: 1,
			Attempted:  1,
			Succeeded:  1,
		},
		Results: []SecurityResult{{
			Target:      "example.com",
			ResolvedIP:  "127.0.0.1",
			Port:        22,
			Service:     "ssh",
			FindingType: FindingTypeCredentialValid,
			Success:     true,
			Username:    "root",
			Password:    "root",
		}},
	}

	data, err := res.ToJSON(true)
	if err != nil {
		t.Fatalf("marshal run result json: %v", err)
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

func TestParseCredentialLinesAllowsEmptyUsername(t *testing.T) {
	creds, err := parseCredentialLines(" : 123456\n")
	if err != nil {
		t.Fatalf("expected empty username credential to parse: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].Username != "" || creds[0].Password != "123456" {
		t.Fatalf("unexpected parsed credential: %+v", creds[0])
	}
}
