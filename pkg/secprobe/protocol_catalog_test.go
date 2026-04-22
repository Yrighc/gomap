package secprobe

import "testing"

func TestLookupProtocolSpecSupportsAliasesAndPortFallback(t *testing.T) {
	tests := []struct {
		name    string
		service string
		port    int
		want    string
	}{
		{name: "postgres alias", service: "postgres", want: "postgresql"},
		{name: "pgsql alias", service: "pgsql", want: "postgresql"},
		{name: "mongo alias", service: "mongo", want: "mongodb"},
		{name: "redis tls alias", service: "redis/tls", want: "redis"},
		{name: "mongodb port fallback", port: 27017, want: "mongodb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, ok := LookupProtocolSpec(tt.service, tt.port)
			if !ok {
				t.Fatalf("expected protocol spec for %q/%d", tt.service, tt.port)
			}
			if spec.Name != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, spec.Name)
			}
		})
	}
}

func TestProtocolSupportsKindUsesCatalogDeclaration(t *testing.T) {
	if !ProtocolSupportsKind("redis", ProbeKindCredential) {
		t.Fatal("expected redis to support credential probing")
	}
	if !ProtocolSupportsKind("redis", ProbeKindUnauthorized) {
		t.Fatal("expected redis to support unauthorized probing")
	}
	if ProtocolSupportsKind("mongodb", ProbeKindCredential) {
		t.Fatal("expected mongodb credential probing to stay unsupported")
	}
	if !ProtocolSupportsKind("mongodb", ProbeKindUnauthorized) {
		t.Fatal("expected mongodb unauthorized probing to be declared")
	}
}
