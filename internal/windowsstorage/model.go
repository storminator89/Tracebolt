// Package windowsstorage carries separately consented fixed local storage and power context.
package windowsstorage

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const SchemaVersion = "tracebolt.windows-storage-context.v1"
const ConsentVersion = "tracebolt.windows-storage-context-consent.v1"
const Scope = "windows-storage-context-v1"
const MaxBytes = 16 * 1024
const MaxDriveRows = 26
const MaxDiskRows = 32
const MaxNativeDiskRows = 64
const MaxOperationalStatuses = 16
const MaxStringUnits = 128
const CollectionBudget = 5 * time.Second
const ProviderBudget = time.Second
const Privacy = "Read and send caller-visible local drive letters and their exact volume GUID mapping, plus fixed local MSFT_PhysicalDisk provider device identifiers, friendly/model labels, media and bus types, size, and provider health/operational status. Provider device identifiers and user-editable friendly labels can identify storage devices. Separate default-off local scope; earlier grants/receipts do not authorize it. No physical-disk serial/unique IDs, paths/files, network shares, remote queries, SMART, raw sectors, recovery keys, credentials, arbitrary WMI, privilege or configuration changes. Provider-reported health is not SMART or proof of physical-device health; RAID/virtual/Storage Spaces visibility may hide underlying devices. No inferred volume-to-physical-disk joins. Operator-only; no AI/provider export."

// Wire carries a compact privacy label; the full local acknowledgement above is unchanged.
const TelemetryPrivacy = "Separately consented storage context: caller-visible local drive letters/volume GUID mappings and MSFT_PhysicalDisk identifiers/friendly labels, bus/media/size and provider health/status. Provider reports are not SMART, physical-health proof or volume-to-physical-disk mappings. RAID/virtual/Storage Spaces may hide backing devices. Private operator view only; no AI export."
const HTTPPrivacy = "WARNING: HTTP-test sends identifying drive letters, volume GUIDs and storage-provider device labels/status in plaintext. Network observers can read it; signatures do not encrypt metadata or authenticate manager responses. Production requires HTTPS."

var ErrInvalid = errors.New("windows_storage_context_invalid")
var ErrDisabled = errors.New("windows_storage_context_scope_disabled")
var ErrDenied = errors.New("windows_storage_context_access_denied")
var ErrUnavailable = errors.New("windows_storage_context_unavailable")
var ErrUnsupported = errors.New("windows_storage_context_unsupported_platform")
var ErrMetadata = errors.New("windows_storage_context_invalid_metadata")
var ErrBounds = errors.New("windows_storage_context_bounds")
var ErrPartial = errors.New("windows_storage_context_partial_result")
var ErrBudget = errors.New("windows_storage_context_budget_exhausted")

type Consent struct {
	SchemaVersion string `json:"schemaVersion"`
	Scope         string `json:"scope"`
	SenderBinding string `json:"senderBinding"`
	GrantID       string `json:"grantId"`
	Enabled       bool   `json:"enabled"`
}
type Field struct {
	Value   *string `json:"value"`
	Quality string  `json:"quality"`
}
type Drive struct {
	Letter     string  `json:"letter"`
	DriveType  string  `json:"driveType"`
	VolumeGUID *string `json:"volumeGuid"`
	Quality    string  `json:"quality"`
	Reason     string  `json:"reason"`
}
type Drives struct {
	Quality       string  `json:"quality"`
	Reason        string  `json:"reason"`
	Rows          []Drive `json:"rows"`
	ObservedCount int     `json:"observedCount"`
	CountExact    bool    `json:"countExact"`
	Complete      bool    `json:"complete"`
	Truncated     bool    `json:"truncated"`
}
type Disk struct {
	Index             int      `json:"index"`
	DeviceID          Field    `json:"deviceId"`
	FriendlyName      Field    `json:"friendlyName"`
	HealthStatus      *uint16  `json:"healthStatus"`
	OperationalStatus []uint16 `json:"operationalStatus"`
	BusType           *uint16  `json:"busType"`
	MediaType         *uint16  `json:"mediaType"`
	SizeBytes         *string  `json:"sizeBytes"`
}
type Disks struct {
	Quality       string `json:"quality"`
	Reason        string `json:"reason"`
	Rows          []Disk `json:"rows"`
	ObservedCount int    `json:"observedCount"`
	CountExact    bool   `json:"countExact"`
	Complete      bool   `json:"complete"`
	Truncated     bool   `json:"truncated"`
}
type Snapshot struct {
	SchemaVersion string    `json:"schemaVersion"`
	Scope         string    `json:"scope"`
	GrantID       string    `json:"grantId"`
	GenerationID  string    `json:"generationId"`
	CollectedAt   time.Time `json:"collectedAt"`
	Drives        Drives    `json:"drives"`
	Disks         Disks     `json:"disks"`
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

func validField(f Field, units int) bool {
	if f.Quality == "observed" {
		return f.Value != nil && validLabel(*f.Value, units)
	}
	return f.Value == nil && (f.Quality == "empty" || f.Quality == "denied" || f.Quality == "unavailable")
}

var volumeGUID = regexp.MustCompile(`^\\\\\?\\Volume\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}\\$`)

func ValidVolumeGUID(s string) bool { return volumeGUID.MatchString(s) }
func validCoverage(q, reason string, n, count, max int, exact, complete, truncated bool) bool {
	if !validReason(reason) || n > max || count < n || count > MaxNativeDiskRows || (truncated && complete) || (complete && (!exact || n != count)) {
		return false
	}
	switch q {
	case "observed":
		return reason == "" && complete && !truncated
	case "partial":
		return reason != "" && (!complete || n > 0) && complete == (exact && n == count) && truncated == (count > n || !exact)
	case "denied", "unavailable":
		return reason != "" && (q == "denied") == (reason == ErrDenied.Error()) && n == 0 && count == 0 && !exact && !complete && !truncated
	}
	return false
}
func validDrives(s Drives) bool {
	if s.Rows == nil || s.ObservedCount > MaxDriveRows || !validCoverage(s.Quality, s.Reason, len(s.Rows), s.ObservedCount, MaxDriveRows, s.CountExact, s.Complete, s.Truncated) {
		return false
	}
	last := ""
	for _, r := range s.Rows {
		if s.Quality == "observed" && r.Quality != "observed" {
			return false
		}
		if len(r.Letter) != 2 || r.Letter[0] < 'A' || r.Letter[0] > 'Z' || r.Letter[1] != ':' || r.Letter <= last || !validReason(r.Reason) {
			return false
		}
		last = r.Letter
		switch r.DriveType {
		case "fixed", "removable", "cdrom", "ramdisk", "unknown":
		default:
			return false
		}
		if r.Quality == "observed" {
			if r.VolumeGUID == nil || !ValidVolumeGUID(*r.VolumeGUID) || r.Reason != "" || r.DriveType == "unknown" {
				return false
			}
		} else if (r.Quality != "denied" && r.Quality != "unavailable") || r.VolumeGUID != nil || r.Reason == "" || (r.Quality == "denied") != (r.Reason == ErrDenied.Error()) {
			return false
		}
	}
	return true
}
func validDisks(s Disks) bool {
	if s.Rows == nil || !validCoverage(s.Quality, s.Reason, len(s.Rows), s.ObservedCount, MaxDiskRows, s.CountExact, s.Complete, s.Truncated) {
		return false
	}
	for i, r := range s.Rows {
		if s.Quality == "observed" && (r.DeviceID.Quality == "denied" || r.DeviceID.Quality == "unavailable" || r.FriendlyName.Quality == "denied" || r.FriendlyName.Quality == "unavailable" || r.HealthStatus == nil || r.BusType == nil || r.MediaType == nil || r.SizeBytes == nil) {
			return false
		}
		if r.Index != i || !validField(r.DeviceID, 64) || !validField(r.FriendlyName, 128) || r.OperationalStatus == nil || len(r.OperationalStatus) > MaxOperationalStatuses {
			return false
		}
		seen := map[uint16]bool{}
		for _, n := range r.OperationalStatus {
			if seen[n] {
				return false
			}
			seen[n] = true
		}
		if r.SizeBytes != nil {
			n, e := strconv.ParseUint(*r.SizeBytes, 10, 64)
			if e != nil || strconv.FormatUint(n, 10) != *r.SizeBytes {
				return false
			}
		}
	}
	return true
}
func validateStructure(s Snapshot) error {
	if s.SchemaVersion != SchemaVersion || s.Scope != Scope || !hex(s.GrantID, 32) || !strings.HasPrefix(s.GenerationID, "sample_") || !hex(strings.TrimPrefix(s.GenerationID, "sample_"), 32) || !validTime(s.CollectedAt) || !validDrives(s.Drives) || !validDisks(s.Disks) {
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
func emptyField(reason string) Field {
	q := "unavailable"
	if reason == ErrDenied.Error() {
		q = "denied"
	}
	return Field{Quality: q}
}
func EmptyDrives(reason string) Drives {
	return Drives{Quality: emptyField(reason).Quality, Reason: reason, Rows: []Drive{}}
}
func EmptyDisks(reason string) Disks {
	return Disks{Quality: emptyField(reason).Quality, Reason: reason, Rows: []Disk{}}
}
func Empty(r Request, reason string) Snapshot {
	return Snapshot{SchemaVersion, Scope, r.Consent.GrantID, r.GenerationID, r.CollectedAt, EmptyDrives(reason), EmptyDisks(reason)}
}
func FitBudget(s Snapshot, budget int) (Snapshot, error) {
	if budget > MaxBytes {
		budget = MaxBytes
	}
	if validateStructure(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	for {
		b, e := json.Marshal(s)
		if e != nil {
			return Snapshot{}, ErrInvalid
		}
		if len(b) <= budget {
			return s, nil
		}
		if len(s.Disks.Rows) > 0 {
			s.Disks.Rows = s.Disks.Rows[:len(s.Disks.Rows)-1]
			s.Disks.Quality = "partial"
			s.Disks.Reason = ErrBounds.Error()
			s.Disks.Complete = false
			s.Disks.Truncated = true
		} else if len(s.Drives.Rows) > 0 {
			s.Drives.Rows = s.Drives.Rows[:len(s.Drives.Rows)-1]
			s.Drives.Quality = "partial"
			s.Drives.Reason = ErrBounds.Error()
			s.Drives.Complete = false
			s.Drives.Truncated = true
		} else {
			return Snapshot{}, ErrBounds
		}
	}
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
