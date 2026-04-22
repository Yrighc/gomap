package secprobe

import (
	"encoding/json"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type ProbeKind = core.ProbeKind

const (
	FindingTypeCredentialValid    = core.FindingTypeCredentialValid
	FindingTypeUnauthorizedAccess = core.FindingTypeUnauthorizedAccess
)

const (
	ProbeKindCredential   = core.ProbeKindCredential
	ProbeKindUnauthorized = core.ProbeKindUnauthorized
)

type SecurityCandidate = core.SecurityCandidate
type Credential = core.Credential
type CredentialProbeOptions = core.CredentialProbeOptions

type SecurityResult struct {
	Target      string
	ResolvedIP  string
	Port        int
	Service     string
	ProbeKind   ProbeKind
	FindingType string
	Success     bool
	Username    string
	Password    string
	Evidence    string
	Enrichment  map[string]any
	Error       string
}

type SecurityMeta struct {
	Candidates int
	Attempted  int
	Succeeded  int
	Failed     int
	Skipped    int
}

type RunResult struct {
	Meta    SecurityMeta
	Results []SecurityResult
}

func marshalJSON(v any, pretty bool) ([]byte, error) {
	if pretty {
		return json.MarshalIndent(v, "", "  ")
	}
	return json.Marshal(v)
}

func (r *SecurityResult) ToJSON(pretty bool) ([]byte, error) { return marshalJSON(r, pretty) }
func (r *RunResult) ToJSON(pretty bool) ([]byte, error)      { return marshalJSON(r, pretty) }

func exportSecurityResult(result core.SecurityResult) SecurityResult {
	return SecurityResult{
		Target:      result.Target,
		ResolvedIP:  result.ResolvedIP,
		Port:        result.Port,
		Service:     result.Service,
		ProbeKind:   result.ProbeKind,
		FindingType: result.FindingType,
		Success:     result.Success,
		Username:    result.Username,
		Password:    result.Password,
		Evidence:    result.Evidence,
		Enrichment:  result.Enrichment,
		Error:       result.Error,
	}
}

func importSecurityResult(result SecurityResult) core.SecurityResult {
	return core.SecurityResult{
		Target:      result.Target,
		ResolvedIP:  result.ResolvedIP,
		Port:        result.Port,
		Service:     result.Service,
		ProbeKind:   core.ProbeKind(result.ProbeKind),
		FindingType: result.FindingType,
		Success:     result.Success,
		Username:    result.Username,
		Password:    result.Password,
		Evidence:    result.Evidence,
		Enrichment:  result.Enrichment,
		Error:       result.Error,
	}
}

func exportSecurityResults(results []core.SecurityResult) []SecurityResult {
	if results == nil {
		return nil
	}
	out := make([]SecurityResult, len(results))
	for i, item := range results {
		out[i] = exportSecurityResult(item)
	}
	return out
}

func exportSecurityMeta(meta core.SecurityMeta) SecurityMeta {
	return SecurityMeta{
		Candidates: meta.Candidates,
		Attempted:  meta.Attempted,
		Succeeded:  meta.Succeeded,
		Failed:     meta.Failed,
		Skipped:    meta.Skipped,
	}
}

func exportRunResult(result core.RunResult) RunResult {
	return RunResult{
		Meta:    exportSecurityMeta(result.Meta),
		Results: exportSecurityResults(result.Results),
	}
}
