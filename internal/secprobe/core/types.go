package core

import "time"

const FindingTypeCredentialValid = "credential-valid"

type SecurityCandidate struct {
	Target     string
	ResolvedIP string
	Port       int
	Service    string
	Version    string
	Banner     string
}

type Credential struct {
	Username string
	Password string
}

type CredentialProbeOptions struct {
	Protocols     []string
	Concurrency   int
	Timeout       time.Duration
	StopOnSuccess bool
	DictDir       string
	Credentials   []Credential
}

type SecurityResult struct {
	Target      string
	ResolvedIP  string
	Port        int
	Service     string
	FindingType string
	Success     bool
	Username    string
	Password    string
	Evidence    string
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
