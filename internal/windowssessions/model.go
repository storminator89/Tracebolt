// Package windowssessions carries separately consented caller-visible local session and join context.
package windowssessions

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

const SchemaVersion = "tracebolt.windows-session-context.v1"
const ConsentVersion = "tracebolt.windows-session-context-consent.v1"
const Scope = "windows-session-context-v1"
const MaxBytes = 24 * 1024
const MaxRows = 32
const MaxNativeSessions = 4096
const MaxLabelUnits = 64
const MaxJoinUnits = 256
const CollectionBudget = 5 * time.Second
const ProviderBudget = 2 * time.Second
const Privacy = "Read and send caller-visible local Windows session IDs, bounded user and domain labels, session state and Console/RDP protocol, plus this computer's local domain/workgroup join status and name. User, domain and session labels are personal metadata. This is a bounded caller-visible snapshot, not all users or accounts; denied fields remain unknown. No remote server or directory query, client names/IPs, credentials, tokens, SIDs, command lines, logon history, idle/activity monitoring, impersonation, elevation, session actions or account changes. This separate default-off local scope is not granted by existing Windows Setup or earlier receipts. Operator-only; no AI/provider export."
const HTTPPrivacy = "WARNING: HTTP-test sends personal user/domain/session and local join metadata in plaintext. Network observers can read it; signatures do not encrypt metadata or authenticate manager responses. Production requires HTTPS."

var ErrInvalid = errors.New("windows_session_context_invalid")
var ErrDisabled = errors.New("windows_session_context_scope_disabled")
var ErrDenied = errors.New("windows_session_context_access_denied")
var ErrUnavailable = errors.New("windows_session_context_unavailable")
var ErrUnsupported = errors.New("windows_session_context_unsupported_platform")
var ErrMetadata = errors.New("windows_session_context_invalid_metadata")
var ErrBounds = errors.New("windows_session_context_bounds")
var ErrPartial = errors.New("windows_session_context_partial_result")
var ErrBudget = errors.New("windows_session_context_budget_exhausted")

type Consent struct {
	SchemaVersion string `json:"schemaVersion"`
	Scope         string `json:"scope"`
	SenderBinding string `json:"senderBinding"`
	GrantID       string `json:"grantId"`
	Enabled       bool   `json:"enabled"`
}
type Session struct {
	SessionID     uint32  `json:"sessionId"`
	UserName      *string `json:"userName"`
	UserQuality   string  `json:"userQuality"`
	DomainName    *string `json:"domainName"`
	DomainQuality string  `json:"domainQuality"`
	State         string  `json:"state"`
	Protocol      string  `json:"protocol"`
}
type Sessions struct {
	Quality        string    `json:"quality"`
	Reason         string    `json:"reason"`
	ObservedCount  *uint32   `json:"observedCount"`
	RetainedCount  uint32    `json:"retainedCount"`
	TruncatedCount *uint32   `json:"truncatedCount"`
	Rows           []Session `json:"rows"`
}
type Join struct {
	Quality string  `json:"quality"`
	Reason  string  `json:"reason"`
	Status  string  `json:"status"`
	Name    *string `json:"name"`
}
type Snapshot struct {
	SchemaVersion string    `json:"schemaVersion"`
	Scope         string    `json:"scope"`
	GrantID       string    `json:"grantId"`
	GenerationID  string    `json:"generationId"`
	CollectedAt   time.Time `json:"collectedAt"`
	Sessions      Sessions  `json:"sessions"`
	Join          Join      `json:"join"`
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
func validLabel(s string, units int) bool {
	if s == "" || !utf8.ValidString(s) || len(s) > units*4 {
		return false
	}
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) || r == 0xfffd {
			return false
		}
		n++
		if r > 0xffff {
			n++
		}
	}
	return n <= units
}
func validField(value *string, quality string) bool {
	if quality == "observed" {
		return value != nil && validLabel(*value, MaxLabelUnits)
	}
	return value == nil && (quality == "empty" || quality == "denied" || quality == "unavailable")
}
func validState(s string) bool {
	switch s {
	case "active", "connected", "connect-query", "shadow", "disconnected", "idle", "listen", "reset", "down", "init", "unknown":
		return true
	}
	return false
}
func validSessions(s Sessions) bool {
	if !validReason(s.Reason) || s.Rows == nil || len(s.Rows) > MaxRows || s.RetainedCount != uint32(len(s.Rows)) {
		return false
	}
	if s.Quality == "denied" || s.Quality == "unavailable" {
		return len(s.Rows) == 0 && s.ObservedCount == nil && s.TruncatedCount == nil && s.Reason != "" && (s.Quality == "denied") == (s.Reason == ErrDenied.Error())
	}
	if s.Quality != "observed" && s.Quality != "partial" || s.ObservedCount == nil || s.TruncatedCount == nil || *s.ObservedCount > MaxNativeSessions || s.RetainedCount > *s.ObservedCount || *s.TruncatedCount != *s.ObservedCount-s.RetainedCount {
		return false
	}
	partial := *s.TruncatedCount > 0
	for i, r := range s.Rows {
		if !validField(r.UserName, r.UserQuality) || !validField(r.DomainName, r.DomainQuality) || !validState(r.State) || r.Protocol != "console" && r.Protocol != "rdp" && r.Protocol != "unknown" || i > 0 && s.Rows[i-1].SessionID >= r.SessionID {
			return false
		}
		partial = partial || r.UserQuality == "denied" || r.UserQuality == "unavailable" || r.DomainQuality == "denied" || r.DomainQuality == "unavailable" || r.State == "unknown" || r.Protocol == "unknown"
	}
	return s.Quality == "observed" && !partial && s.Reason == "" || s.Quality == "partial" && partial && s.Reason != ""
}
func validJoin(j Join) bool {
	if !validReason(j.Reason) {
		return false
	}
	switch j.Quality {
	case "observed":
		return j.Reason == "" && (j.Status == "unjoined" && j.Name == nil || (j.Status == "domain" || j.Status == "workgroup") && j.Name != nil && validLabel(*j.Name, MaxJoinUnits))
	case "partial":
		return j.Reason != "" && (j.Status == "domain" || j.Status == "workgroup") && j.Name == nil
	case "denied", "unavailable":
		return j.Status == "unknown" && j.Name == nil && j.Reason != "" && (j.Quality == "denied") == (j.Reason == ErrDenied.Error())
	}
	return false
}
func validateStructure(s Snapshot) error {
	if s.SchemaVersion != SchemaVersion || s.Scope != Scope || !hex(s.GrantID, 32) || !strings.HasPrefix(s.GenerationID, "sample_") || !hex(strings.TrimPrefix(s.GenerationID, "sample_"), 32) || !validTime(s.CollectedAt) || !validSessions(s.Sessions) || !validJoin(s.Join) {
		return ErrInvalid
	}
	return nil
}
func Validate(s Snapshot) error {
	if validateStructure(s) != nil {
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
func EmptySessions(reason string) Sessions {
	q := "unavailable"
	if reason == ErrDenied.Error() {
		q = "denied"
	}
	return Sessions{Quality: q, Reason: reason, Rows: []Session{}}
}
func EmptyJoin(reason string) Join {
	q := "unavailable"
	if reason == ErrDenied.Error() {
		q = "denied"
	}
	return Join{Quality: q, Reason: reason, Status: "unknown"}
}
func Empty(r Request, reason string) Snapshot {
	return Snapshot{SchemaVersion, Scope, r.Consent.GrantID, r.GenerationID, r.CollectedAt, EmptySessions(reason), EmptyJoin(reason)}
}
func FitBudget(s Snapshot, budget int) (Snapshot, error) {
	if budget > MaxBytes {
		budget = MaxBytes
	}
	if budget <= 0 {
		return Snapshot{}, ErrBounds
	}
	if validateStructure(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	s.Sessions.Rows = append([]Session{}, s.Sessions.Rows...)
	for {
		b, e := json.Marshal(s)
		if e != nil {
			return Snapshot{}, e
		}
		if len(b) <= budget {
			return s, nil
		}
		if len(s.Sessions.Rows) == 0 {
			return Snapshot{}, ErrBounds
		}
		s.Sessions.Rows = s.Sessions.Rows[:len(s.Sessions.Rows)-1]
		s.Sessions.RetainedCount = uint32(len(s.Sessions.Rows))
		n := *s.Sessions.ObservedCount - s.Sessions.RetainedCount
		s.Sessions.TruncatedCount = &n
		s.Sessions.Quality = "partial"
		s.Sessions.Reason = ErrBounds.Error()
	}
}
