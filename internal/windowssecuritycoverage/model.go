// Package windowssecuritycoverage carries separately consented Windows Security
// Center antivirus registration/status and public TPM presence/version. These
// source reports never establish overall protection or TPM readiness.
package windowssecuritycoverage

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const SchemaVersion = "tracebolt.windows-security-coverage.v1"
const ConsentVersion = "tracebolt.windows-security-coverage-consent.v1"
const Scope = "windows-security-coverage-v1"
const MaxBytes = 8192
const MaxProducts = 16
const MaxProductNameUnits = 128
const CollectionBudget = 5 * time.Second
const ProviderBudget = 2 * time.Second
const Privacy = "Read and send Windows Security Center registered antivirus product names, product state and signature status on supported Windows clients, plus TPM Base Services supported-device presence and TPM version. Independent sources can be denied or unavailable under the unchanged service identity. Product registration/status is not proof of overall protection; TPM presence/version is not readiness, ownership, attestation or BitLocker protection. No BitLocker reads, recovery keys, owner authorization, raw TPM commands/state, remediation paths, product GUIDs, scans, updates, configuration changes, credentials, privilege expansion or AI/provider export. Separate default-off local scope; all earlier grants and receipts remain insufficient."
const TelemetryPrivacy = "AV/TPM: private, no AI export."
const HTTPPrivacy = "WARNING: HTTP-test sends antivirus product names/status and TPM presence/version in plaintext. Network observers can read it; signatures do not encrypt metadata or authenticate manager responses. Production requires HTTPS."

var ErrInvalid = errors.New("windows_security_coverage_invalid")
var ErrDisabled = errors.New("windows_security_coverage_scope_disabled")
var ErrDenied = errors.New("windows_security_coverage_access_denied")
var ErrUnavailable = errors.New("windows_security_coverage_unavailable")
var ErrUnsupported = errors.New("windows_security_coverage_unsupported_platform")
var ErrMetadata = errors.New("windows_security_coverage_invalid_metadata")
var ErrBounds = errors.New("windows_security_coverage_bounds")
var ErrPartial = errors.New("windows_security_coverage_partial_result")
var ErrBudget = errors.New("windows_security_coverage_budget_exhausted")

type Consent struct {
	SchemaVersion string `json:"schemaVersion"`
	Scope         string `json:"scope"`
	SenderBinding string `json:"senderBinding"`
	GrantID       string `json:"grantId"`
	Enabled       bool   `json:"enabled"`
}
type Product struct {
	Index           int     `json:"index"`
	Name            *string `json:"name"`
	State           string  `json:"state"`
	SignatureStatus string  `json:"signatureStatus"`
}
type Antivirus struct {
	Quality       string    `json:"quality"`
	Reason        string    `json:"reason"`
	ReportedCount *uint32   `json:"reportedCount"`
	Rows          []Product `json:"rows"`
	Truncated     bool      `json:"truncated"`
}
type TPM struct {
	Quality  string `json:"quality"`
	Reason   string `json:"reason"`
	Presence string `json:"presence"`
	Version  string `json:"version"`
}
type Snapshot struct {
	SchemaVersion string    `json:"schemaVersion"`
	Scope         string    `json:"scope"`
	GrantID       string    `json:"grantId"`
	GenerationID  string    `json:"generationId"`
	CollectedAt   time.Time `json:"collectedAt"`
	Antivirus     Antivirus `json:"antivirus"`
	TPM           TPM       `json:"tpm"`
}
type Request struct {
	Consent       Consent
	SenderBinding string
	GenerationID  string
	CollectedAt   time.Time
}

func hex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
func validTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1970 && t.Year() <= 9999
}
func canonical(raw []byte, v any, max int) error {
	if len(raw) == 0 || len(raw) > max || !utf8.Valid(raw) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	b, e := json.Marshal(v)
	if e != nil || !bytes.Equal(b, raw) {
		return ErrInvalid
	}
	return nil
}
func DecodeConsent(raw []byte, binding string) (Consent, error) {
	var c Consent
	if canonical(raw, &c, 1024) != nil || c.SchemaVersion != ConsentVersion || c.Scope != Scope || !hex(binding, 64) || c.SenderBinding != binding || !hex(c.GrantID, 32) {
		return Consent{}, ErrInvalid
	}
	return c, nil
}
func EncodeConsent(c Consent, binding string) ([]byte, error) {
	b, e := json.Marshal(c)
	if e != nil {
		return nil, ErrInvalid
	}
	if _, e = DecodeConsent(b, binding); e != nil {
		return nil, e
	}
	return b, nil
}

func validReason(s string) bool {
	switch s {
	case "", ErrDenied.Error(), ErrUnavailable.Error(), ErrUnsupported.Error(), ErrMetadata.Error(), ErrBounds.Error(), ErrPartial.Error(), ErrBudget.Error():
		return true
	}
	return false
}
func validName(s string) bool {
	if s == "" || !utf8.ValidString(s) || len(s) > MaxProductNameUnits*4 {
		return false
	}
	n := 0
	for _, c := range s {
		if unicode.IsControl(c) || c == '\u2028' || c == '\u2029' || c >= '\u202a' && c <= '\u202e' || c >= '\u2066' && c <= '\u2069' {
			return false
		}
		n++
		if c > 0xffff {
			n++
		}
	}
	return n <= MaxProductNameUnits
}
func validAntivirus(a Antivirus) bool {
	if !validReason(a.Reason) || a.Rows == nil || len(a.Rows) > MaxProducts {
		return false
	}
	if a.ReportedCount == nil {
		return len(a.Rows) == 0 && !a.Truncated && (a.Quality == "unavailable" || a.Quality == "denied") && a.Reason != "" && (a.Quality == "denied") == (a.Reason == ErrDenied.Error())
	}
	if *a.ReportedCount > 65535 || uint32(len(a.Rows)) > *a.ReportedCount || a.Truncated != (uint32(len(a.Rows)) < *a.ReportedCount) {
		return false
	}
	complete := !a.Truncated
	for i, p := range a.Rows {
		if p.Index != i || p.Name != nil && !validName(*p.Name) {
			return false
		}
		switch p.State {
		case "on", "off", "snoozed", "expired":
		case "unknown":
			complete = false
		default:
			return false
		}
		switch p.SignatureStatus {
		case "up-to-date", "out-of-date":
		case "unknown":
			complete = false
		default:
			return false
		}
		if p.Name == nil {
			complete = false
		}
	}
	return a.Quality == "observed" && complete && a.Reason == "" || a.Quality == "partial" && a.Reason != ""
}
func validTPM(t TPM) bool {
	if !validReason(t.Reason) {
		return false
	}
	if t.Presence == "unknown" {
		return t.Version == "unknown" && (t.Quality == "denied" || t.Quality == "unavailable") && t.Reason != "" && (t.Quality == "denied") == (t.Reason == ErrDenied.Error())
	}
	if t.Presence == "not-found" {
		return t.Version == "unknown" && t.Quality == "observed" && t.Reason == ""
	}
	if t.Presence != "present" {
		return false
	}
	if t.Version == "unknown" {
		return t.Quality == "partial" && t.Reason != ""
	}
	return (t.Version == "1.2" || t.Version == "2.0") && t.Quality == "observed" && t.Reason == ""
}
func validateShape(s Snapshot) error {
	if s.SchemaVersion != SchemaVersion || s.Scope != Scope || !hex(s.GrantID, 32) || !strings.HasPrefix(s.GenerationID, "sample_") || !hex(strings.TrimPrefix(s.GenerationID, "sample_"), 32) || !validTime(s.CollectedAt) || !validAntivirus(s.Antivirus) || !validTPM(s.TPM) {
		return ErrInvalid
	}
	return nil
}
func Validate(s Snapshot) error {
	if validateShape(s) != nil {
		return ErrInvalid
	}
	b, e := json.Marshal(s)
	if e != nil || len(b) > MaxBytes {
		return ErrInvalid
	}
	return nil
}
func Decode(raw []byte) (Snapshot, error) {
	var s Snapshot
	if canonical(raw, &s, MaxBytes) != nil || Validate(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	return s, nil
}
func Encode(s Snapshot) ([]byte, error) {
	if Validate(s) != nil {
		return nil, ErrInvalid
	}
	return json.Marshal(s)
}
func ValidateBinding(s Snapshot, generation, grant string, at time.Time) error {
	if Validate(s) != nil || s.GenerationID != generation || s.GrantID != grant || !s.CollectedAt.Equal(at) {
		return ErrInvalid
	}
	return nil
}
func EmptyAntivirus(reason string) Antivirus {
	q := "unavailable"
	if reason == ErrDenied.Error() {
		q = "denied"
	}
	return Antivirus{Quality: q, Reason: reason, Rows: []Product{}}
}
func EmptyTPM(reason string) TPM {
	q := "unavailable"
	if reason == ErrDenied.Error() {
		q = "denied"
	}
	return TPM{Quality: q, Reason: reason, Presence: "unknown", Version: "unknown"}
}
func Empty(r Request, reason string) Snapshot {
	return Snapshot{SchemaVersion, Scope, r.Consent.GrantID, r.GenerationID, r.CollectedAt, EmptyAntivirus(reason), EmptyTPM(reason)}
}
func FitBudget(s Snapshot, max int) (Snapshot, error) {
	if validateShape(s) != nil || max <= 0 || max > MaxBytes {
		return Snapshot{}, ErrInvalid
	}
	s.Antivirus.Rows = append([]Product{}, s.Antivirus.Rows...)
	for {
		b, e := json.Marshal(s)
		if e != nil {
			return Snapshot{}, ErrInvalid
		}
		if len(b) <= max {
			return s, nil
		}
		if len(s.Antivirus.Rows) == 0 {
			return Snapshot{}, ErrBounds
		}
		s.Antivirus.Rows = s.Antivirus.Rows[:len(s.Antivirus.Rows)-1]
		s.Antivirus.Truncated = true
		s.Antivirus.Quality = "partial"
		s.Antivirus.Reason = ErrBounds.Error()
	}
}
