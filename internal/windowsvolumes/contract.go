// Package windowsvolumes is a default-off, separately consented local volume
// metadata extension. It never exposes labels, serials, files or mount paths.
package windowsvolumes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const SchemaVersion = "tracebolt.windows-volumes.v1"
const ConsentVersion = "tracebolt.windows-volumes-consent.v1"
const Scope = "windows-visible-volumes-v1"
const MaxBytes = 12 << 10
const MaxRows = 64
const MaxNativeRows = 128
const Privacy = "Read and send bounded caller-visible local volume GUID identifiers, drive types and capacity: quota-aware caller total and available bytes, and physical free bytes. Volume GUIDs identify volumes. No labels, serial numbers, file names, mount paths, network volume probing or elevated access. This is not whole-machine disk coverage. Private manager data is excluded from AI/provider export."
const HTTPPrivacy = "WARNING: HTTP-test also sends volume GUID identifiers, drive types and capacity in plaintext. Network observers can read them; signatures do not encrypt metadata or authenticate manager responses. Use only a disposable test network; production requires HTTPS."

var ErrInvalid = errors.New("windows_volumes_invalid")
var ErrDenied = errors.New("windows_volumes_access_denied")
var ErrUnavailable = errors.New("windows_volumes_source_unavailable")
var ErrUnsupported = errors.New("windows_volumes_unsupported_platform")
var ErrMetadata = errors.New("windows_volumes_invalid_metadata")
var ErrDriveType = errors.New("windows_volumes_unsupported_drive_type")

type Consent struct {
	SchemaVersion string `json:"schemaVersion"`
	Scope         string `json:"scope"`
	SenderBinding string `json:"senderBinding"`
	GrantID       string `json:"grantId"`
	Enabled       bool   `json:"enabled"`
}

// TotalBytes and AvailableBytes are caller/quota-aware; FreeBytes is physical
// volume free space and can exceed TotalBytes. Values are decimal uint64 strings.
type Capacity struct {
	TotalBytes     string `json:"totalBytes"`
	FreeBytes      string `json:"freeBytes"`
	AvailableBytes string `json:"availableBytes"`
}
type Volume struct {
	VolumeID  string    `json:"volumeId"`
	DriveType string    `json:"driveType"`
	Quality   string    `json:"quality"`
	Reason    string    `json:"reason"`
	Capacity  *Capacity `json:"capacity"`
}
type Snapshot struct {
	SchemaVersion string    `json:"schemaVersion"`
	Scope         string    `json:"scope"`
	GrantID       string    `json:"grantId"`
	GenerationID  string    `json:"generationId"`
	CollectedAt   time.Time `json:"collectedAt"`
	Quality       string    `json:"quality"`
	Reason        string    `json:"reason"`
	Complete      bool      `json:"complete"`
	Truncated     bool      `json:"truncated"`
	CountExact    bool      `json:"countExact"`
	ObservedCount uint32    `json:"observedCount"`
	Rows          []Volume  `json:"rows"`
}

func hex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
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
func validGeneration(g string) bool {
	return strings.HasPrefix(g, "sample_") && hex(strings.TrimPrefix(g, "sample_"), 32)
}
func validVolumeID(s string) bool {
	if len(s) != 49 || !strings.HasPrefix(s, `\\?\Volume{`) || !strings.HasSuffix(s, `}\`) {
		return false
	}
	g := s[11:47]
	if len(g) != 36 {
		return false
	}
	for i, c := range g {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func decimal(s string) (uint64, bool) {
	n, e := strconv.ParseUint(s, 10, 64)
	return n, e == nil && strconv.FormatUint(n, 10) == s
}
func validReason(s string) bool {
	switch s {
	case "", ErrDenied.Error(), ErrUnavailable.Error(), ErrUnsupported.Error(), ErrMetadata.Error(), ErrDriveType.Error(), "context canceled", "context deadline exceeded":
		return true
	}
	return false
}
func Validate(s Snapshot) error {
	if s.SchemaVersion != SchemaVersion || s.Scope != Scope || !hex(s.GrantID, 32) || !validGeneration(s.GenerationID) || s.CollectedAt.IsZero() || s.CollectedAt.Location() != time.UTC || s.CollectedAt.Year() < 1970 || s.CollectedAt.Year() > 9999 || s.Rows == nil || len(s.Rows) > MaxRows || s.ObservedCount > MaxNativeRows || int(s.ObservedCount) < len(s.Rows) || !validReason(s.Reason) {
		return ErrInvalid
	}
	if int(s.ObservedCount) > len(s.Rows) && !s.Truncated {
		return ErrInvalid
	}
	switch s.Quality {
	case "observed":
		if !s.Complete || s.Truncated || !s.CountExact || s.Reason != "" || int(s.ObservedCount) != len(s.Rows) {
			return ErrInvalid
		}
	case "bounded":
		if s.Complete || !s.Truncated || s.Reason != "" || !s.CountExact && s.ObservedCount != MaxNativeRows || s.CountExact && int(s.ObservedCount) <= len(s.Rows) {
			return ErrInvalid
		}
	case "partial":
		if s.Complete || s.CountExact || s.Reason == "" || s.ObservedCount == 0 {
			return ErrInvalid
		}
	case "denied", "unavailable":
		if s.Complete || s.Truncated || s.CountExact || s.Reason == "" || len(s.Rows) != 0 || s.ObservedCount != 0 || (s.Quality == "denied") != (s.Reason == ErrDenied.Error()) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, v := range s.Rows {
		if !validVolumeID(v.VolumeID) || seen[v.VolumeID] || !validReason(v.Reason) {
			return ErrInvalid
		}
		seen[v.VolumeID] = true
		switch v.DriveType {
		case "fixed", "removable", "cdrom", "ramdisk", "unknown":
		default:
			return ErrInvalid
		}
		// Unknown includes unsupported/remote types: the native boundary never
		// queries their capacity. Preserve that exclusion in incoming frames.
		if v.Reason == ErrDriveType.Error() && v.DriveType != "unknown" {
			return ErrInvalid
		}
		switch v.Quality {
		case "observed":
			if v.DriveType == "unknown" || v.Capacity == nil || v.Reason != "" {
				return ErrInvalid
			}
			t, a := decimal(v.Capacity.TotalBytes)
			f, b := decimal(v.Capacity.FreeBytes)
			av, c := decimal(v.Capacity.AvailableBytes)
			if !a || !b || !c || av > t || av > f {
				return ErrInvalid
			}
		case "denied", "unavailable":
			if v.Capacity != nil || v.Reason == "" || (v.Quality == "denied") != (v.Reason == ErrDenied.Error()) {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
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

// Collect checks explicit sender-bound consent before making any native call.
func Collect(ctx context.Context, generation string, c Consent, binding string) (Snapshot, error) {
	return collectUsing(ctx, generation, c, binding, openNative, time.Now)
}

// FitBudget deterministically omits whole rows without refreshing capture or
// altering native observed counts. It returns an independent rows slice.
func FitBudget(s Snapshot, maxBytes int) (Snapshot, error) {
	if Validate(s) != nil || maxBytes <= 0 {
		return Snapshot{}, ErrInvalid
	}
	if maxBytes > MaxBytes {
		maxBytes = MaxBytes
	}
	s.Rows = append([]Volume{}, s.Rows...)
	for {
		b, e := json.Marshal(s)
		if e != nil {
			return Snapshot{}, ErrInvalid
		}
		if len(b) <= maxBytes {
			if Validate(s) != nil {
				return Snapshot{}, ErrInvalid
			}
			return s, nil
		}
		if len(s.Rows) == 0 {
			return Snapshot{}, ErrInvalid
		}
		s.Rows = s.Rows[:len(s.Rows)-1]
		s.Complete = false
		s.Truncated = true
		if s.Reason == "" {
			s.Quality = "bounded"
		}
	}
}
