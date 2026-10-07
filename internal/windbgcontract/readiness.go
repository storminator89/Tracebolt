// Package windbgcontract defines an inactive, local-only WinDbg source candidate.
// It performs no discovery, process execution, MCP connection, file access, dump
// capture, model calls, or data export. Supplied observations are not proof of
// authorization or native support. See docs/windows-windbg-mcp-candidate.md.
package windbgcontract

import (
	"strconv"
	"strings"
)

const (
	MinimumVersion = "1.2610.1001.0"
	CandidateStage = "source-contract-only"
	SourceProfile  = "windows-dump-evidence-v1"
)

// Observation is a future trusted local probe's input, never an HTTP grant or
// model-supplied request. This package does not implement that probe.
type Observation struct {
	Enabled          bool
	OS               string
	Architecture     string
	WindowsBuild     int
	WinDbgVersion    string
	ProxyVerified    bool
	PolicyPermitsMCP bool
	SessionRef       string
	SessionAvailable bool
	TargetKind       string
	SecureMode       string
	XPIAEnabled      bool
	SamplingAllowed  bool
}

type Readiness struct {
	Stage                 string   `json:"stage"`
	Status                string   `json:"status"`
	ClientSupport         string   `json:"clientSupport"`
	PrerequisitesMet      bool     `json:"prerequisitesMet"`
	ConnectionImplemented bool     `json:"connectionImplemented"`
	Ready                 bool     `json:"ready"`
	Blockers              []string `json:"blockers"`
}

// Assess reports fail-closed prerequisite blockers without touching the host.
// Ready and ConnectionImplemented remain false even for a perfect fixture.
// It cannot enable a feature, establish permission, or override administrator policy.
func Assess(o Observation) Readiness {
	r := Readiness{Stage: CandidateStage, Status: "disabled", ClientSupport: "custom-best-effort", Blockers: []string{}}
	if !o.Enabled {
		r.Blockers = append(r.Blockers, "disabled")
		return r
	}
	r.Status = "blocked"
	add := func(condition bool, reason string) {
		if !condition {
			r.Blockers = append(r.Blockers, reason)
		}
	}
	add(o.OS == "windows-client" && o.WindowsBuild >= 14393, "windows-host-unverified-or-unsupported")
	add(o.Architecture == "amd64" || o.Architecture == "arm64", "architecture-unsupported")
	add(supportedVersion(o.WinDbgVersion), "windbg-version-missing-or-unsupported")
	add(o.ProxyVerified, "proxy-identity-unverified")
	add(o.PolicyPermitsMCP, "organization-policy-not-approved")
	add(validID(o.SessionRef) && o.SessionAvailable, "session-unselected-or-unavailable")
	add(validDumpKind(o.TargetKind), "existing-dump-required")
	add(o.SecureMode == "full", "full-secure-mode-required")
	add(o.XPIAEnabled, "prompt-injection-protection-required")
	add(o.SamplingAllowed, "approved-mcp-sampling-required")
	r.PrerequisitesMet = len(r.Blockers) == 0
	if r.PrerequisitesMet {
		r.Status = "native-validation-required"
	}
	r.Blockers = append(r.Blockers, "mcp-transport-not-implemented", "native-smoke-test-required")
	return r
}

func supportedVersion(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 || len(s) > 40 {
		return false
	}
	var v [4]uint64
	for i, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return false
		}
		v[i] = n
	}
	minimum := [4]uint64{1, 2610, 1001, 0}
	for i := range v {
		if v[i] != minimum[i] {
			return v[i] > minimum[i]
		}
	}
	return true
}
