package windbgcontract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"
)

const (
	EvidenceVersion = "tracebolt.windbg-local-evidence.v1"
	MaxRecords      = 16
	MaxOutputBytes  = 8 * 1024
	MaxBundleBytes  = 48 * 1024
)

var ErrInvalidEvidence = errors.New("invalid WinDbg local evidence contract")

// Bundle is a proposed LOCAL evidence format, not the Microsoft MCP wire schema
// and not an analysis.Packet. Output may contain secrets and is always untrusted.
// No code currently reads, stores, renders, or exports a Bundle in production.
// Hashes detect accidental byte mismatches, not forged provenance or permission.
type Bundle struct {
	SchemaVersion string    `json:"schemaVersion"`
	SourceProfile string    `json:"sourceProfile"`
	Synthetic     bool      `json:"synthetic"`
	SessionRef    string    `json:"sessionRef"`
	DumpSHA256    string    `json:"dumpSHA256"`
	DumpKind      string    `json:"dumpKind"`
	CapturedAt    time.Time `json:"capturedAt"`
	ObservedAt    time.Time `json:"observedAt"`
	WinDbgVersion string    `json:"windbgVersion"`
	SymbolStatus  string    `json:"symbolStatus"`
	Records       []Record  `json:"records"`
}

type Record struct {
	ID           string    `json:"id"`
	Command      string    `json:"command"`
	ObservedAt   time.Time `json:"observedAt"`
	Output       string    `json:"output"`
	OutputSHA256 string    `json:"outputSHA256"`
}

// Validation is descriptive, not an export grant, signature, or root-cause
// verdict. Existing analysis export allowlists are deliberately unchanged.
type Validation struct {
	SourceProfile      string   `json:"sourceProfile"`
	EvidenceIDs        []string `json:"evidenceIDs"`
	Gaps               []string `json:"gaps"`
	Synthetic          bool     `json:"synthetic"`
	UntrustedOutput    bool     `json:"untrustedOutput"`
	AIExportAllowed    bool     `json:"aiExportAllowed"`
	RootCauseConfirmed bool     `json:"rootCauseConfirmed"`
}

// Validate checks a typed local candidate in memory, preserving original times,
// content, and synthetic labels. It neither proves causality nor executes Command.
// Errors deliberately contain no dump path, target output, or supplied identifier.
func Validate(b Bundle) (Validation, error) {
	bad := func() (Validation, error) { return Validation{}, ErrInvalidEvidence }
	if b.SchemaVersion != EvidenceVersion || b.SourceProfile != SourceProfile ||
		!validID(b.SessionRef) || !validSHA256(b.DumpSHA256) || !validDumpKind(b.DumpKind) ||
		!supportedVersion(b.WinDbgVersion) || b.ObservedAt.IsZero() ||
		b.CapturedAt.After(b.ObservedAt) || len(b.Records) == 0 || len(b.Records) > MaxRecords {
		return bad()
	}
	switch b.SymbolStatus {
	case "matched", "partial", "missing", "unknown":
	default:
		return bad()
	}
	r := Validation{SourceProfile: SourceProfile, EvidenceIDs: []string{}, Gaps: []string{}, Synthetic: b.Synthetic, UntrustedOutput: true}
	if b.CapturedAt.IsZero() {
		r.Gaps = append(r.Gaps, "dump-capture-time-unknown")
	}
	if b.SymbolStatus != "matched" {
		r.Gaps = append(r.Gaps, "symbols-"+b.SymbolStatus)
	}
	seen := map[string]bool{}
	for _, e := range b.Records {
		if !validID(e.ID) || seen[e.ID] || !candidateReadCommand(e.Command) ||
			e.ObservedAt.IsZero() || e.ObservedAt.After(b.ObservedAt) ||
			(!b.CapturedAt.IsZero() && e.ObservedAt.Before(b.CapturedAt)) ||
			len(e.Output) == 0 || len(e.Output) > MaxOutputBytes || !utf8.ValidString(e.Output) ||
			!validSHA256(e.OutputSHA256) {
			return bad()
		}
		hash := sha256.Sum256([]byte(e.Output))
		if e.OutputSHA256 != hex.EncodeToString(hash[:]) {
			return bad()
		}
		seen[e.ID] = true
		r.EvidenceIDs = append(r.EvidenceIDs, e.ID)
	}
	encoded, err := json.Marshal(b)
	if err != nil || len(encoded) > MaxBundleBytes {
		return bad()
	}
	return r, nil
}

// These exact strings label fixture observations only. This is not a command
// dispatcher or a guarantee that any command/extension is safe on a live target.
// No prefix matching, argument interpolation, compound commands, scripts, file
// writes, process controls, or arbitrary debugger expressions are accepted.
func candidateReadCommand(s string) bool {
	switch s {
	case "!analyze -v", "!analyze -hang", "~* kb", "lm", "kv":
		return true
	default:
		return false
	}
}

func validDumpKind(s string) bool {
	return s == "user-crash-dump" || s == "user-hang-dump" || s == "kernel-crash-dump"
}

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func validID(s string) bool {
	if len(s) == 0 || len(s) > 96 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
