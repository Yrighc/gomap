package secprobe

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestBuiltinCredentialsUsesSharedPasswordSource(t *testing.T) {
	creds, err := BuiltinCredentials("ssh")
	if err != nil {
		t.Fatalf("load builtin credentials: %v", err)
	}
	if len(creds) == 0 {
		t.Fatal("expected shared password source to generate credentials")
	}
	if creds[0].Username == "" || creds[0].Password == "" {
		t.Fatalf("expected generated credential evidence, got %+v", creds[0])
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

func TestSecurityMetaToJSON(t *testing.T) {
	meta := SecurityMeta{Candidates: 2, Attempted: 2, Succeeded: 1, Failed: 1}
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	if string(data) != `{"Candidates":2,"Attempted":2,"Succeeded":1,"Failed":1,"Skipped":0}` {
		t.Fatalf("unexpected meta json: %s", data)
	}
}
