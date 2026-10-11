// Package windowshardware carries separately consented fixed local hardware and power context.
package windowshardware

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

const SchemaVersion = "tracebolt.windows-hardware-context.v1"
const ConsentVersion = "tracebolt.windows-hardware-context-consent.v1"
const Scope = "windows-hardware-context-v1"
const MaxBytes = 6 * 1024
const MaxStringUnits = 128
const CollectionBudget = 5 * time.Second
const ProviderBudget = time.Second
const Privacy = "Read and send fixed local computer manufacturer/model, Win32_BIOS vendor, SMBIOS BIOS version, release date and source-labeled BIOS serial number, physical chassis serial from Win32_SystemEnclosure, plus system power and battery presence, charging, percentage and estimated remaining time. Serial metadata can identify a device; Win32_BIOS serial is a software-element field, not a verified unique system serial. Separate default-off local scope; earlier scopes and receipts do not authorize it. No hardware UUID, raw SMBIOS, product/license/recovery keys, credentials, remote queries, arbitrary WMI, firmware changes, battery health/cycle history or privilege changes. Operator-only; no AI/provider export."
const HTTPPrivacy = "WARNING: HTTP-test sends identifying chassis/BIOS serial and hardware/power metadata in plaintext. Network observers can read it; signatures do not encrypt metadata or authenticate manager responses. Production requires HTTPS."

var ErrInvalid = errors.New("windows_hardware_context_invalid")
var ErrDisabled = errors.New("windows_hardware_context_scope_disabled")
var ErrDenied = errors.New("windows_hardware_context_access_denied")
var ErrUnavailable = errors.New("windows_hardware_context_unavailable")
var ErrUnsupported = errors.New("windows_hardware_context_unsupported_platform")
var ErrMetadata = errors.New("windows_hardware_context_invalid_metadata")
var ErrBounds = errors.New("windows_hardware_context_bounds")
var ErrPartial = errors.New("windows_hardware_context_partial_result")
var ErrBudget = errors.New("windows_hardware_context_budget_exhausted")

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
type System struct {
	Quality      string `json:"quality"`
	Reason       string `json:"reason"`
	Manufacturer Field  `json:"manufacturer"`
	Model        Field  `json:"model"`
}
type Firmware struct {
	Quality      string `json:"quality"`
	Reason       string `json:"reason"`
	Source       string `json:"source"`
	Vendor       Field  `json:"vendor"`
	Version      Field  `json:"version"`
	ReleaseDate  Field  `json:"releaseDate"`
	SerialNumber Field  `json:"serialNumber"`
}
type Chassis struct {
	Quality      string `json:"quality"`
	Reason       string `json:"reason"`
	Source       string `json:"source"`
	SerialNumber Field  `json:"serialNumber"`
}
type Power struct {
	Quality          string  `json:"quality"`
	Reason           string  `json:"reason"`
	Source           string  `json:"source"`
	ACLineStatus     string  `json:"acLineStatus"`
	BatteryPresence  string  `json:"batteryPresence"`
	Charging         string  `json:"charging"`
	BatteryPercent   *uint8  `json:"batteryPercent"`
	EstimatedSeconds *uint32 `json:"estimatedSeconds"`
}
type Snapshot struct {
	SchemaVersion string    `json:"schemaVersion"`
	Scope         string    `json:"scope"`
	GrantID       string    `json:"grantId"`
	GenerationID  string    `json:"generationId"`
	CollectedAt   time.Time `json:"collectedAt"`
	System        System    `json:"system"`
	Firmware      Firmware  `json:"firmware"`
	Power         Power     `json:"power"`
	Chassis       Chassis   `json:"chassis"`
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
func validGroup(q, reason string, fields ...Field) bool {
	if !validReason(reason) {
		return false
	}
	partial := false
	for _, f := range fields {
		if !validField(f, MaxStringUnits) {
			return false
		}
		partial = partial || f.Quality == "denied" || f.Quality == "unavailable"
	}
	switch q {
	case "observed":
		return !partial && reason == ""
	case "partial":
		return partial && reason != ""
	case "denied", "unavailable":
		if reason == "" || (q == "denied") != (reason == ErrDenied.Error()) {
			return false
		}
		for _, f := range fields {
			if f.Value != nil || f.Quality != q {
				return false
			}
		}
		return true
	}
	return false
}
func validSystem(s System) bool { return validGroup(s.Quality, s.Reason, s.Manufacturer, s.Model) }
func validFirmware(s Firmware) bool {
	return s.Source == "Win32_BIOS" && validGroup(s.Quality, s.Reason, s.Vendor, s.Version, s.ReleaseDate, s.SerialNumber) && validField(s.SerialNumber, 64) && (s.ReleaseDate.Value == nil || validDMTF(*s.ReleaseDate.Value))
}
func validChassis(s Chassis) bool {
	return s.Source == "Win32_SystemEnclosure" && validGroup(s.Quality, s.Reason, s.SerialNumber) && validField(s.SerialNumber, 64)
}
func validPower(p Power) bool {
	if p.Source != "GetSystemPowerStatus" || !validReason(p.Reason) || (p.ACLineStatus != "online" && p.ACLineStatus != "offline" && p.ACLineStatus != "unknown") || (p.BatteryPresence != "present" && p.BatteryPresence != "absent" && p.BatteryPresence != "unknown") || (p.Charging != "yes" && p.Charging != "no" && p.Charging != "unknown") || (p.BatteryPercent != nil && *p.BatteryPercent > 100) || (p.EstimatedSeconds != nil && *p.EstimatedSeconds == 0xffffffff) {
		return false
	}
	if p.BatteryPresence != "present" && (p.Charging != "unknown" || p.BatteryPercent != nil || p.EstimatedSeconds != nil) {
		return false
	}
	if p.EstimatedSeconds != nil && p.ACLineStatus != "offline" {
		return false
	}
	unknown := p.ACLineStatus == "unknown" || p.BatteryPresence == "unknown" || (p.BatteryPresence == "present" && (p.Charging == "unknown" || p.BatteryPercent == nil || (p.ACLineStatus == "offline" && p.EstimatedSeconds == nil)))
	switch p.Quality {
	case "observed":
		return !unknown && p.Reason == ""
	case "partial":
		return unknown && p.Reason != ""
	case "denied", "unavailable":
		return p.Reason != "" && (p.Quality == "denied") == (p.Reason == ErrDenied.Error()) && p.ACLineStatus == "unknown" && p.BatteryPresence == "unknown"
	}
	return false
}
func Validate(s Snapshot) error {
	if s.SchemaVersion != SchemaVersion || s.Scope != Scope || !hex(s.GrantID, 32) || !strings.HasPrefix(s.GenerationID, "sample_") || !hex(strings.TrimPrefix(s.GenerationID, "sample_"), 32) || !validTime(s.CollectedAt) || !validSystem(s.System) || !validFirmware(s.Firmware) || !validPower(s.Power) || !validChassis(s.Chassis) {
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
func emptyField(reason string) Field {
	q := "unavailable"
	if reason == ErrDenied.Error() {
		q = "denied"
	}
	return Field{Quality: q}
}
func EmptySystem(reason string) System {
	f := emptyField(reason)
	return System{f.Quality, reason, f, f}
}
func EmptyFirmware(reason string) Firmware {
	f := emptyField(reason)
	return Firmware{f.Quality, reason, "Win32_BIOS", f, f, f, f}
}
func EmptyChassis(reason string) Chassis {
	f := emptyField(reason)
	return Chassis{f.Quality, reason, "Win32_SystemEnclosure", f}
}
func EmptyPower(reason string) Power {
	f := emptyField(reason)
	return Power{Quality: f.Quality, Reason: reason, Source: "GetSystemPowerStatus", ACLineStatus: "unknown", BatteryPresence: "unknown", Charging: "unknown"}
}
func Empty(r Request, reason string) Snapshot {
	return Snapshot{SchemaVersion, Scope, r.Consent.GrantID, r.GenerationID, r.CollectedAt, EmptySystem(reason), EmptyFirmware(reason), EmptyPower(reason), EmptyChassis(reason)}
}
func FitBudget(s Snapshot, budget int) (Snapshot, error) {
	b, e := Encode(s)
	if e != nil {
		return Snapshot{}, e
	}
	if len(b) > budget {
		return Snapshot{}, ErrBounds
	}
	return s, nil
}
