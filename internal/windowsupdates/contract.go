// Package windowsupdates inspects bounded Windows Update Agent cache metadata.
// It has no runtime, manager, update-installation or network-scan integration.
package windowsupdates

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

const SchemaVersion = "tracebolt.windows-update-inspection.v1"
const ConsentVersion = "tracebolt.windows-update-inspection-consent.v1"
const Scope = "windows-cached-update-inspection-v1"
const SearchCriteria = "IsInstalled=0 and IsHidden=0 and Type='Software'"
const MaxBytes = 24 << 10
const MaxRows = 64
const MaxNativeRows = 128
const MaxTitleBytes = 256
const MaxNativeStringUnits = 2048
const MaxKBArticles = 8
const CollectionBudget = 15 * time.Second
const Privacy = "Read bounded Windows Update Agent cached, non-hidden, not-installed software update metadata: update identifiers and revisions, sanitized titles, KB article numbers, vendor severity and whether update content is already downloaded. Cache freshness is unknown; no current patch or CVE coverage is established. No online search, metadata refresh, download, installation, reboot, policy change, update-history content, URLs, descriptions, paths or AI/provider export. This separate local scope is not granted by Windows Setup or existing inventory approvals."
const HTTPPrivacy = "WARNING: HTTP-test would send update identifiers, titles, KB article numbers, severity and download state in plaintext. Network observers can read them. Production requires HTTPS."

var ErrInvalid = errors.New("windows_updates_invalid")
var ErrDisabled = errors.New("windows_updates_scope_disabled")
var ErrDenied = errors.New("windows_updates_access_denied")
var ErrUnavailable = errors.New("windows_updates_unavailable")
var ErrUnsupported = errors.New("windows_updates_unsupported_platform")
var ErrMetadata = errors.New("windows_updates_invalid_metadata")
var ErrBounds = errors.New("windows_updates_bounds")
var ErrOffline = errors.New("windows_updates_offline_not_verified")
var ErrPartial = errors.New("windows_updates_partial_result")
var ErrBudget = errors.New("windows_updates_budget_exhausted")

type Consent struct {
	SchemaVersion string `json:"schemaVersion"`
	Scope         string `json:"scope"`
	SenderBinding string `json:"senderBinding"`
	GrantID       string `json:"grantId"`
	Enabled       bool   `json:"enabled"`
}

type Update struct {
	UpdateID          string   `json:"updateId"`
	Revision          uint32   `json:"revision"`
	Title             string   `json:"title"`
	KBArticleIDs      []string `json:"kbArticleIds"`
	Severity          string   `json:"severity"`
	Downloaded        bool     `json:"downloaded"`
	MetadataTruncated bool     `json:"metadataTruncated"`
}

// CountExact describes the fixed search's cached result count, never online
// availability, whole-machine coverage or the number of retained rows.
// CollectedAt is inspection time, NOT cache time. CacheFreshness stays unknown.
type Snapshot struct {
	SchemaVersion  string    `json:"schemaVersion"`
	Scope          string    `json:"scope"`
	GrantID        string    `json:"grantId"`
	GenerationID   string    `json:"generationId"`
	CollectedAt    time.Time `json:"collectedAt"`
	Source         string    `json:"source"`
	CacheFreshness string    `json:"cacheFreshness"`
	Quality        string    `json:"quality"`
	Reason         string    `json:"reason"`
	CountExact     bool      `json:"countExact"`
	ObservedCount  uint32    `json:"observedCount"`
	Truncated      bool      `json:"truncated"`
	Rows           []Update  `json:"rows"`
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
func validGeneration(s string) bool {
	return strings.HasPrefix(s, "sample_") && hex(strings.TrimPrefix(s, "sample_"), 32)
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
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return s != "00000000-0000-0000-0000-000000000000"
}
func validKB(s string) bool {
	if len(s) < 3 || len(s) > 12 || !strings.HasPrefix(s, "KB") || s[2] == '0' {
		return false
	}
	for _, c := range s[2:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func validSeverity(s string) bool {
	switch s {
	case "unspecified", "critical", "important", "moderate", "low":
		return true
	}
	return false
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
func validUpdate(u Update) bool {
	if !validID(u.UpdateID) || u.Revision > 1<<31-1 || !validTitle(u.Title) || !validSeverity(u.Severity) || u.KBArticleIDs == nil || len(u.KBArticleIDs) > MaxKBArticles {
		return false
	}
	for i, kb := range u.KBArticleIDs {
		if !validKB(kb) || i > 0 && u.KBArticleIDs[i-1] >= kb {
			return false
		}
	}
	return true
}
func less(a, b Update) bool {
	if a.UpdateID != b.UpdateID {
		return a.UpdateID < b.UpdateID
	}
	return a.Revision < b.Revision
}
func validReason(s string) bool {
	switch s {
	case "", ErrDenied.Error(), ErrUnavailable.Error(), ErrUnsupported.Error(), ErrMetadata.Error(), ErrBounds.Error(), ErrOffline.Error(), ErrPartial.Error(), ErrBudget.Error():
		return true
	}
	return false
}
func validate(s Snapshot, checkBytes bool) error {
	if s.SchemaVersion != SchemaVersion || s.Scope != Scope || !hex(s.GrantID, 32) || !validGeneration(s.GenerationID) || !validTime(s.CollectedAt) || s.Source != "wua-cache" || s.CacheFreshness != "unknown" || s.Rows == nil || len(s.Rows) > MaxRows || s.ObservedCount > 1<<31-1 || s.ObservedCount < uint32(len(s.Rows)) || s.Truncated != (s.ObservedCount > uint32(len(s.Rows))) || !validReason(s.Reason) {
		return ErrInvalid
	}
	switch s.Quality {
	case "observed":
		if !s.CountExact || s.Reason != "" {
			return ErrInvalid
		}
	case "partial":
		if s.Reason == "" {
			return ErrInvalid
		}
	case "denied", "unavailable":
		if s.CountExact || s.ObservedCount != 0 || len(s.Rows) != 0 || s.Reason == "" || (s.Quality == "denied") != (s.Reason == ErrDenied.Error()) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	for i, u := range s.Rows {
		if !validUpdate(u) || i > 0 && !less(s.Rows[i-1], u) {
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

// FitBudget only drops complete highest-sorted rows. It preserves capture age,
// count semantics and generation/grant binding. It does not mutate its input.
func FitBudget(s Snapshot, maxBytes int) (Snapshot, error) {
	if Validate(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	return fit(s, maxBytes)
}
func fit(s Snapshot, maxBytes int) (Snapshot, error) {
	if maxBytes <= 0 || validate(s, false) != nil {
		return Snapshot{}, ErrInvalid
	}
	if maxBytes > MaxBytes {
		maxBytes = MaxBytes
	}
	s.Rows = append([]Update{}, s.Rows...)
	for i := range s.Rows {
		s.Rows[i].KBArticleIDs = append([]string{}, s.Rows[i].KBArticleIDs...)
	}
	for {
		b, e := json.Marshal(s)
		if e != nil {
			return Snapshot{}, ErrInvalid
		}
		if len(b) <= maxBytes {
			return s, nil
		}
		if len(s.Rows) == 0 {
			return Snapshot{}, ErrBounds
		}
		s.Rows = s.Rows[:len(s.Rows)-1]
		s.Truncated = true
	}
}

func Encode(s Snapshot) ([]byte, error) {
	if Validate(s) != nil {
		return nil, ErrInvalid
	}
	b, e := json.Marshal(s)
	if e != nil {
		return nil, ErrInvalid
	}
	return b, nil
}

// ValidateBinding ties inspection to the existing base sample without changing
// either capture age or grants. It does not itself authenticate a local receipt.
func ValidateBinding(s Snapshot, generation, grant string, capturedAt time.Time) error {
	if Validate(s) != nil || !validGeneration(generation) || !hex(grant, 32) || !validTime(capturedAt) || s.GenerationID != generation || s.GrantID != grant || !s.CollectedAt.Equal(capturedAt) {
		return ErrInvalid
	}
	return nil
}
