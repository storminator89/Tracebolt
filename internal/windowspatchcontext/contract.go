// Package windowspatchcontext carries separately consented, read-only machine
// patch context. Retained history is never current installation/compliance proof.
package windowspatchcontext

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const SchemaVersion = "tracebolt.windows-patch-context.v1"
const ConsentVersion = "tracebolt.windows-patch-context-consent.v1"
const Scope = "windows-patch-context-v1"
const MaxBytes = 24 << 10
const MaxRows = 64
const MaxTitleBytes = 256
const CollectionBudget = 15 * time.Second
const Privacy = "Read and send fixed machine Windows edition, release, build and revision metadata; the latest 64 locally retained Windows Update installation/uninstallation history events with update identifiers, sanitized titles, UTC times, outcomes and numeric result codes; and machine-wide Windows Update, servicing and pending-file-operation reboot indicators. History may be cleared or incomplete and is not current installed-update or compliance proof. File-operation indicators expose only presence metadata, never paths or values, and do not imply urgent reboot. No update-server search/contact, downloads, installation, reboot, user data, application identities, support URLs, credentials, registry enumeration, arbitrary queries, privilege changes or AI/provider export. This separate default-off local scope is not granted by existing Windows Setup or update-cache consent."
const HTTPPrivacy = "WARNING: HTTP-test sends Windows edition/build, retained update history titles, identifiers, times, outcomes and reboot indicators in plaintext. Network observers can read them; signatures do not encrypt metadata or authenticate manager responses. Production requires HTTPS."

var ErrInvalid = errors.New("windows_patch_context_invalid")
var ErrDisabled = errors.New("windows_patch_context_scope_disabled")
var ErrDenied = errors.New("windows_patch_context_access_denied")
var ErrUnavailable = errors.New("windows_patch_context_unavailable")
var ErrUnsupported = errors.New("windows_patch_context_unsupported_platform")
var ErrMetadata = errors.New("windows_patch_context_invalid_metadata")
var ErrBounds = errors.New("windows_patch_context_bounds")
var ErrOffline = errors.New("windows_patch_context_offline_not_verified")
var ErrPartial = errors.New("windows_patch_context_partial_result")
var ErrBudget = errors.New("windows_patch_context_budget_exhausted")

type Consent struct {
	SchemaVersion string `json:"schemaVersion"`
	Scope         string `json:"scope"`
	SenderBinding string `json:"senderBinding"`
	GrantID       string `json:"grantId"`
	Enabled       bool   `json:"enabled"`
}
type Value struct {
	Value   *string `json:"value"`
	Quality string  `json:"quality"`
}
type OS struct {
	Edition  Value `json:"edition"`
	Release  Value `json:"release"`
	Build    Value `json:"build"`
	Revision Value `json:"revision"`
}
type Reboot struct {
	WindowsUpdate  string `json:"windowsUpdate"`
	Servicing      string `json:"servicing"`
	FileOperations string `json:"fileOperations"`
}
type Entry struct {
	Index             uint32    `json:"index"`
	UpdateID          string    `json:"updateId"`
	Revision          uint32    `json:"revision"`
	Title             string    `json:"title"`
	OccurredAt        time.Time `json:"occurredAt"`
	Operation         string    `json:"operation"`
	Result            string    `json:"result"`
	HResult           string    `json:"hresult"`
	MetadataTruncated bool      `json:"metadataTruncated"`
}
type History struct {
	Quality    string  `json:"quality"`
	Reason     string  `json:"reason"`
	CountExact bool    `json:"countExact"`
	TotalCount uint32  `json:"totalCount"`
	Truncated  bool    `json:"truncated"`
	Rows       []Entry `json:"rows"`
}
type Snapshot struct {
	SchemaVersion string    `json:"schemaVersion"`
	Scope         string    `json:"scope"`
	GrantID       string    `json:"grantId"`
	GenerationID  string    `json:"generationId"`
	CollectedAt   time.Time `json:"collectedAt"`
	OS            OS        `json:"os"`
	Reboot        Reboot    `json:"reboot"`
	History       History   `json:"history"`
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
func validID(s string) bool {
	if len(s) != 36 || s == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i, r := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
		} else if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
func validValue(v Value, max int, numeric bool) bool {
	switch v.Quality {
	case "absent", "denied", "unavailable":
		return v.Value == nil
	case "observed":
	default:
		return false
	}
	if v.Value == nil {
		return false
	}
	s := *v.Value
	if len(s) == 0 || len(s) > max || strings.TrimSpace(s) != s || strings.Contains(s, "  ") {
		return false
	}
	if numeric {
		n, e := strconv.ParseUint(s, 10, 32)
		return e == nil && strconv.FormatUint(n, 10) == s
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == ' ' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
func validState(s string) bool {
	return s == "pending" || s == "clear" || s == "denied" || s == "unavailable"
}
func validTitle(s string) bool {
	if s == "" || len(s) > MaxTitleBytes || !utf8.ValidString(s) || strings.TrimSpace(s) != s || strings.Contains(s, "  ") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) && r != ' ' {
			return false
		}
	}
	return true
}
func validEntry(v Entry, at time.Time) bool {
	if v.Index >= MaxRows || !validID(v.UpdateID) || v.Revision > 1<<31-1 || !validTitle(v.Title) || !validTime(v.OccurredAt) || v.OccurredAt.After(at.Add(2*time.Minute)) || !hex(v.HResult, 8) || (v.Operation != "installation" && v.Operation != "uninstallation") {
		return false
	}
	switch v.Result {
	case "not-started", "in-progress", "succeeded", "succeeded-with-errors", "failed", "aborted":
		return true
	}
	return false
}
func validReason(s string) bool {
	switch s {
	case "", ErrDenied.Error(), ErrUnavailable.Error(), ErrUnsupported.Error(), ErrMetadata.Error(), ErrBounds.Error(), ErrOffline.Error(), ErrPartial.Error(), ErrBudget.Error():
		return true
	}
	return false
}
func validate(s Snapshot, checkBytes bool) error {
	if s.SchemaVersion != SchemaVersion || s.Scope != Scope || !hex(s.GrantID, 32) || !strings.HasPrefix(s.GenerationID, "sample_") || !hex(strings.TrimPrefix(s.GenerationID, "sample_"), 32) || !validTime(s.CollectedAt) || !validValue(s.OS.Edition, 64, false) || !validValue(s.OS.Release, 32, false) || !validValue(s.OS.Build, 10, true) || !validValue(s.OS.Revision, 10, true) || !validState(s.Reboot.WindowsUpdate) || !validState(s.Reboot.Servicing) || !validState(s.Reboot.FileOperations) {
		return ErrInvalid
	}
	h := s.History
	if h.Rows == nil || len(h.Rows) > MaxRows || h.TotalCount > 1<<31-1 || h.TotalCount < uint32(len(h.Rows)) || h.Truncated != (h.TotalCount > uint32(len(h.Rows))) || !validReason(h.Reason) {
		return ErrInvalid
	}
	switch h.Quality {
	case "observed":
		if !h.CountExact || h.Reason != "" {
			return ErrInvalid
		}
	case "partial":
		if h.Reason == "" {
			return ErrInvalid
		}
	case "denied", "unavailable":
		if h.CountExact || h.TotalCount != 0 || len(h.Rows) != 0 || h.Reason == "" || (h.Quality == "denied") != (h.Reason == ErrDenied.Error()) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	for i, r := range h.Rows {
		if !validEntry(r, s.CollectedAt) || r.Index >= h.TotalCount || i > 0 && (h.Rows[i-1].Index >= r.Index || h.Rows[i-1].OccurredAt.Before(r.OccurredAt)) {
			return ErrInvalid
		}
	}
	if checkBytes {
		b, e := json.Marshal(s)
		if e != nil || len(b) > MaxBytes {
			return ErrInvalid
		}
	}
	return nil
}
func Validate(s Snapshot) error { return validate(s, true) }
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
func FitBudget(s Snapshot, max int) (Snapshot, error) {
	if Validate(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	return fit(s, max)
}
func fit(s Snapshot, max int) (Snapshot, error) {
	if max <= 0 || validate(s, false) != nil {
		return Snapshot{}, ErrInvalid
	}
	if max > MaxBytes {
		max = MaxBytes
	}
	s.History.Rows = append([]Entry{}, s.History.Rows...)
	for {
		b, e := json.Marshal(s)
		if e != nil {
			return Snapshot{}, ErrInvalid
		}
		if len(b) <= max {
			return s, nil
		}
		if len(s.History.Rows) == 0 {
			return Snapshot{}, ErrBounds
		}
		s.History.Rows = s.History.Rows[:len(s.History.Rows)-1]
		s.History.Truncated = true
	}
}
func Empty(req Request, reason string) Snapshot {
	v := Value{Quality: "unavailable"}
	return Snapshot{SchemaVersion: SchemaVersion, Scope: Scope, GrantID: req.Consent.GrantID, GenerationID: req.GenerationID, CollectedAt: req.CollectedAt, OS: OS{v, v, v, v}, Reboot: Reboot{"unavailable", "unavailable", "unavailable"}, History: History{Quality: "unavailable", Reason: reason, Rows: []Entry{}}}
}
